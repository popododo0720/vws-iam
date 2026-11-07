package iam_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

func TestValidSAMLProviderName(t *testing.T) {
	for _, n := range []string{"a", "A_b.c-9", "corp.idp", strings.Repeat("p", 128)} {
		if !iam.ValidSAMLProviderName(n) {
			t.Errorf("%q refused", n)
		}
	}
	long := strings.Repeat("p", 129)
	for _, n := range []string{"", long, "a b", "a/b", "a+b", "a=b", "a,b", "a@b", "é", "a\nb", "a\x00"} {
		if iam.ValidSAMLProviderName(n) {
			t.Errorf("%q accepted", n)
		}
	}
	if got, want := iam.SAMLProviderNamePattern(), "[A-Za-z0-9_.-]{1,128}"; got != want {
		t.Errorf("pattern %q, want %q", got, want)
	}
}

// samlDoc returns valid metadata of exactly runes characters.
func samlDoc(t *testing.T, runes int) string {
	t.Helper()
	_, c := testCert(t, "doc")
	base := entity(`entityID="https://idp.example/saml"`, "<!---->"+idp("", keyDesc("signing", c)))
	pad := runes - len([]rune(base))
	if pad < 0 {
		t.Fatalf("metadata is %d characters already", len([]rune(base)))
	}
	// é is two bytes, so characters and bytes differ.
	comment := "<!--" + strings.Repeat("é", pad) + "-->"
	return entity(`entityID="https://idp.example/saml"`, comment+idp("", keyDesc("signing", c)))
}

func TestSAMLProviderValidate(t *testing.T) {
	doc := samlDoc(t, iam.MinSAMLMetadataLen)
	p := iam.SAMLProvider{Name: "corp", MetadataDocument: doc, Created: time.Now()}
	if err := p.Validate(); err != nil {
		t.Fatalf("a valid provider: %v", err)
	}
	if n := len([]rune(doc)); n != iam.MinSAMLMetadataLen {
		t.Fatalf("test document has %d characters", n)
	}
	if p.Kind() != iam.KindSAMLProvider || p.Key() != "corp" {
		t.Fatalf("kind %v key %q", p.Kind(), p.Key())
	}

	short := p
	short.MetadataDocument = samlDoc(t, iam.MinSAMLMetadataLen-1)
	huge := p
	huge.MetadataDocument = strings.Repeat("x", iam.MaxSAMLMetadataLen+1)
	manyTags := map[string]string{}
	for i := range iam.MaxSAMLProviderTags + 1 {
		manyTags[strings.Repeat("k", i+1)] = "v"
	}
	exactTags := map[string]string{}
	for k := range manyTags {
		if len(exactTags) < iam.MaxSAMLProviderTags {
			exactTags[k] = "v"
		}
	}
	if err := (iam.SAMLProvider{Name: "corp", MetadataDocument: doc, Tags: exactTags}).Validate(); err != nil {
		t.Fatalf("50 tags: %v", err)
	}
	bad := map[string]iam.SAMLProvider{
		"empty name":     {MetadataDocument: doc},
		"long name":      {Name: strings.Repeat("p", 129), MetadataDocument: doc},
		"bad name":       {Name: "a b", MetadataDocument: doc},
		"short document": short,
		"huge document":  huge,
		"51 tags":        {Name: "corp", MetadataDocument: doc, Tags: manyTags},
		"reserved tag":   {Name: "corp", MetadataDocument: doc, Tags: map[string]string{"aws:x": "v"}},
		"bad tag value":  {Name: "corp", MetadataDocument: doc, Tags: map[string]string{"k": "<v>"}},
	}
	for name, p := range bad {
		if err := p.Validate(); !errors.Is(err, iam.ErrInvalid) || errors.Is(err, iam.ErrSAMLProviderTooLarge) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}

	// Metadata that does not parse is ErrInvalid for the store and also
	// ErrSAMLMetadata for the edge, and the error does not carry it.
	junk := p
	junk.MetadataDocument = canary + strings.Repeat("é", iam.MinSAMLMetadataLen)
	err := junk.Validate()
	tooLarge := errors.Is(err, iam.ErrSAMLProviderTooLarge)
	if !errors.Is(err, iam.ErrInvalid) || !errors.Is(err, iam.ErrSAMLMetadata) || tooLarge {
		t.Fatalf("unparsable metadata: %v", err)
	}
	if strings.Contains(err.Error(), canary) || len(err.Error()) > 300 {
		t.Fatalf("error carries the document: %q", err)
	}
	// Nothing in an invalid provider's errors echoes its document.
	for name, p := range bad {
		if e := p.Validate(); e != nil && len(e.Error()) > 500 {
			t.Errorf("%s: error is %d bytes", name, len(e.Error()))
		}
	}
}

// TestSAMLProviderValidateEncodedSize: a provider whose JSON encoding is
// MaxSAMLProviderEncodedLen bytes is valid and one byte more is not,
// however few characters the document has; escaped characters count as
// they are stored.
func TestSAMLProviderValidateEncodedSize(t *testing.T) {
	_, c := testCert(t, "doc")
	at := func(comment string) iam.SAMLProvider {
		return iam.SAMLProvider{
			Name: "corp", Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Meta: iam.Meta{UID: "u", Generation: 1},
			MetadataDocument: entity(`entityID="e"`, "<!--"+comment+"-->"+idp("", keyDesc("signing", c))),
		}
	}
	size := func(comment string) int {
		b, err := json.Marshal(at(comment))
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	room := iam.MaxSAMLProviderEncodedLen - size("")
	// <, > and & are six bytes each once encoded.
	comment := strings.Repeat("<&>", room/18) + strings.Repeat("x", room%18)
	if got := size(comment); got != iam.MaxSAMLProviderEncodedLen {
		t.Fatalf("encodes to %d, want %d", got, iam.MaxSAMLProviderEncodedLen)
	}
	if n := len([]rune(at(comment).MetadataDocument)); n >= iam.MaxSAMLProviderEncodedLen/2 {
		t.Fatalf("the test document has %d characters; escaping should inflate it", n)
	}
	if err := at(comment).Validate(); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	// The pending marker of an uncommitted create is not counted.
	pending := at(comment)
	pending.Pending = true
	if err := pending.Validate(); err != nil {
		t.Fatalf("pending at the limit: %v", err)
	}
	err := at(comment + "x").Validate()
	if !errors.Is(err, iam.ErrSAMLProviderTooLarge) || !errors.Is(err, iam.ErrInvalid) {
		t.Fatalf("one byte over: %v", err)
	}
	pending = at(comment + "x")
	pending.Pending = true
	if err := pending.Validate(); !errors.Is(err, iam.ErrSAMLProviderTooLarge) {
		t.Fatalf("pending one byte over: %v", err)
	}
	// A document longer than the limit in plain bytes is refused without
	// being encoded.
	err = at(strings.Repeat("x", iam.MaxSAMLProviderEncodedLen)).Validate()
	if !errors.Is(err, iam.ErrSAMLProviderTooLarge) {
		t.Fatalf("a document over the limit: %v", err)
	}
	if len(err.Error()) > 200 {
		t.Fatalf("error carries the document: %d bytes", len(err.Error()))
	}
}
