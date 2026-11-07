package grpcapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/store/storetest"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

func storedSAML(t *testing.T, b store.Backend, name string) store.Versioned[iam.SAMLProvider] {
	t.Helper()
	v, err := store.Get[iam.SAMLProvider](t.Context(), store.Scoped(b, proj), name)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func samlCount(t *testing.T, b store.Backend) int {
	t.Helper()
	all, err := store.List[iam.SAMLProvider](t.Context(), store.Scoped(b, proj))
	if err != nil {
		t.Fatal(err)
	}
	return len(all)
}

func samlTag(k, v string) *iamv1.Tag { return &iamv1.Tag{Key: k, Value: v} }

// samlDocOfLen is valid metadata of exactly n characters.
func samlDocOfLen(t *testing.T, n int) string {
	t.Helper()
	pad := n - utf8.RuneCountInString(storetest.SAMLMetadata(""))
	if pad < 0 {
		t.Fatalf("metadata has more than %d characters", n)
	}
	// é is two bytes, so the byte length differs from the character count.
	doc := storetest.SAMLMetadata(strings.Repeat("é", pad))
	if got := utf8.RuneCountInString(doc); got != n {
		t.Fatalf("document has %d characters, want %d", got, n)
	}
	return doc
}

// TestCreateSAMLProvider: a new provider has the requested name, the
// request time and the metadata document verbatim, with the tags (the last
// value of a repeated key), a UID and generation 1; it is returned with
// its ARN, stored as returned and seen by every replica. A name taken in
// any case is EntityAlreadyExists and the stored provider stays. On both
// store backends.
func TestCreateSAMLProvider(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC)
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			doc := idp.Metadata(now.Add(24 * time.Hour))
			e := newEnvOn(t, b, &now)
			tags := []*iamv1.Tag{samlTag("team", "a"), samlTag("env", "prod"), samlTag("team", "b")}
			got, err := e.api.CreateSAMLProvider(t.Context(), proj, "Corp.IdP", doc, tags)
			if err != nil {
				t.Fatal(err)
			}
			p := got.Provider
			if p.Name != "Corp.IdP" || p.MetadataDocument != doc || !p.Created.Equal(now) || p.UID == "" || p.Generation != 1 ||
				len(p.Tags) != 2 || p.Tags["team"] != "b" || p.Tags["env"] != "prod" {
				t.Fatalf("CreateSAMLProvider = %+v, want Corp.IdP with the document and tags team=b env=prod", p)
			}
			if want := "arn:vws:iam::" + proj + ":saml-provider/Corp.IdP"; got.ARN != want {
				t.Fatalf("Arn = %q, want %q", got.ARN, want)
			}
			stored := storedSAML(t, b, "corp.idp")
			s := stored.Object
			if s.UID != p.UID || s.MetadataDocument != doc || !s.Created.Equal(now) || s.Name != "Corp.IdP" ||
				len(s.Tags) != 2 || s.Tags["team"] != "b" {
				t.Fatalf("stored %+v, want it as returned %+v", s.Name, p.Name)
			}
			replica := newEnvOn(t, b, &now)
			for _, name := range []string{"Corp.IdP", "CORP.IDP", "corp.idp"} {
				_, err := replica.api.CreateSAMLProvider(t.Context(), proj, name, doc, nil)
				wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			}
			if again := storedSAML(t, b, "Corp.IdP"); again.Version != stored.Version || again.Object.Tags["team"] != "b" {
				t.Fatalf("a refused create changed the provider: %+v", again.Object.Tags)
			}
			// Another project has its own namespace of providers.
			if _, err := e.api.CreateSAMLProvider(t.Context(), "other", "Corp.IdP", doc, nil); err != nil {
				t.Fatalf("same name in another project: %v", err)
			}
		})
	}
}

// TestCreateSAMLProviderNoTags: a provider made without tags stores none.
func TestCreateSAMLProviderNoTags(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	doc := storetest.SAMLMetadata(strings.Repeat(" ", 100))
	if _, err := e.api.CreateSAMLProvider(t.Context(), proj, "plain", doc, nil); err != nil {
		t.Fatal(err)
	}
	if tags := storedSAML(t, b, "plain").Object.Tags; len(tags) != 0 {
		t.Fatalf("tags %v, want none", tags)
	}
}

// TestCreateSAMLProviderServesAssumeRoleWithSAML: the document a provider
// was created with, read from the store by another replica and parsed with
// iam.ParseSAMLMetadata, is what sts.WithSAML needs: a SAML response
// signed by the IdP gets role credentials, and a response signed by an
// IdP the document does not name does not.
func TestCreateSAMLProviderServesAssumeRoleWithSAML(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			other, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			writer := newEnvOn(t, b, &now)
			created, err := writer.api.CreateSAMLProvider(t.Context(), proj, "corp", idp.Metadata(now.Add(time.Hour)), nil)
			if err != nil {
				t.Fatal(err)
			}
			if created.ARN != samlIdpARN {
				t.Fatalf("Arn = %q, want %q", created.ARN, samlIdpARN)
			}

			// A replica started later reads the provider from the store.
			md, err := iam.ParseSAMLMetadata(storedSAML(t, b, "corp").Object.MetadataDocument)
			if err != nil {
				t.Fatalf("the stored document does not parse: %v", err)
			}
			if md.EntityID != samlIssuer || len(md.Certificates) != 1 || !md.Certificates[0].Equal(idp.Cert) ||
				!md.ValidUntil.Equal(now.Add(time.Hour).Truncate(time.Second)) {
				t.Fatalf("parsed %+v, want the IdP %q with its certificate", md, samlIssuer)
			}
			providers := samltest.Providers{samlIdpARN: sts.SAMLProvider{
				ARN: created.ARN, EntityID: md.EntityID, Certificates: md.Certificates, ValidUntil: md.ValidUntil,
			}}
			sp := sts.SAMLServiceProvider{Audience: samlSPID, SignInURL: samlAud}
			e := newEnvOn(t, b, &now, grpcapi.WithSAML(providers, sp))
			trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"` + samlIdpARN + `"},
				"Action":"sts:AssumeRoleWithSAML","Condition":{"StringEquals":{"SAML:aud":"` + samlAud + `"}}}]}`
			if _, err := e.roles.CreateRole(t.Context(), &iamv1.CreateRoleRequest{
				Parent: parentName, RoleId: "saml-dev", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
			}); err != nil {
				t.Fatal(err)
			}
			good := samltest.Assertion{
				Issuer: samlIssuer, Audience: samlSPID, Recipient: samlAud, Destination: samlAud,
				NameID: "alice@corp.test", NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				Roles: []string{samlRoleARN + "," + samlIdpARN}, SessionName: "alice",
				NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
				ConfirmNotOnOrAfter: now.Add(5 * time.Minute),
			}
			signed := func(p *samltest.IdP) sts.SAMLRequest {
				r, err := p.Response(good, samltest.SignAssertion)
				if err != nil {
					t.Fatal(err)
				}
				return sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: r}
			}
			out, err := e.api.AssumeRoleWithSAML(t.Context(), signed(idp))
			if err != nil {
				t.Fatalf("AssumeRoleWithSAML with the stored provider: %v", err)
			}
			if out.Credentials.AssumedRoleARN != "arn:vws:sts::"+proj+":assumed-role/saml-dev/alice" {
				t.Fatalf("assumed %q", out.Credentials.AssumedRoleARN)
			}
			if _, err := e.api.AssumeRoleWithSAML(t.Context(), signed(other)); err == nil {
				t.Fatal("a response signed by another key was accepted")
			}
		})
	}
}

// TestCreateSAMLProviderConcurrent: of creates of one name in any case
// racing on two replicas exactly one succeeds and the rest are
// EntityAlreadyExists; the stored provider is the winner's, and a retry
// after success is EntityAlreadyExists. On both store backends.
func TestCreateSAMLProviderConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			names := []string{"corp", "CORP", "Corp"}
			docs := make([]string, 16)
			for i := range docs {
				docs[i] = storetest.SAMLMetadata("racer " + strconv.Itoa(i) + strings.Repeat(" ", 100))
			}
			errs := make([]error, len(docs))
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					_, errs[i] = replicas[i%2].api.CreateSAMLProvider(t.Context(), proj, names[i%len(names)], docs[i], nil)
				})
			}
			wg.Wait()
			won := -1
			for i, err := range errs {
				if err != nil {
					wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
					continue
				}
				if won >= 0 {
					t.Fatal("two creates succeeded")
				}
				won = i
			}
			if won < 0 {
				t.Fatal("no create succeeded")
			}
			got := storedSAML(t, b, "corp").Object
			if got.MetadataDocument != docs[won] || got.Name != names[won%len(names)] {
				t.Fatalf("stored %q with document %d, want the winner's (%d, %q)",
					got.Name, indexOf(docs, got.MetadataDocument), won, names[won%len(names)])
			}
			_, err := replicas[0].api.CreateSAMLProvider(t.Context(), proj, names[won%len(names)], docs[won], nil)
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			if n := samlCount(t, b); n != 1 {
				t.Fatalf("%d providers stored, want 1", n)
			}
		})
	}
}

func indexOf(docs []string, d string) int {
	for i := range docs {
		if docs[i] == d {
			return i
		}
	}
	return -1
}

// TestCreateSAMLProviderErrors: every bad argument gets its code and AWS
// error code and stores nothing; the AWS bounds are accepted; an error
// never carries the document; a store failure is InternalFailure.
func TestCreateSAMLProviderErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	doc := samlDocOfLen(t, 2000)
	const canary = "SECRETCANARY"
	create := func(pid, name, document string, tags ...*iamv1.Tag) error {
		_, err := e.api.CreateSAMLProvider(ctx, pid, name, document, tags)
		return err
	}
	tooMany := make([]*iamv1.Tag, iam.MaxSAMLProviderTags+1)
	for i := range tooMany {
		tooMany[i] = samlTag("k"+strconv.Itoa(i), "v")
	}
	hostile := map[string]string{
		"not XML": canary + strings.Repeat("x", 1000),
		"DTD":     `<!DOCTYPE ` + canary + ` [<!ENTITY a "` + strings.Repeat("a", 500) + `">]>` + doc,
		"EntitiesDescriptor": `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" data="` + canary +
			`">` + doc + strings.Repeat(" ", 1000) + `</md:EntitiesDescriptor>`,
		"no signing key":      strings.Replace(doc, `use="signing"`, `use="encryption"`, 1),
		"no certificate text": strings.Replace(doc, "MIIB", "!!"+canary, 1),
		"text after the root": doc + canary,
		"wrong namespace":     strings.Replace(doc, "urn:oasis:names:tc:SAML:2.0:metadata", "urn:"+canary, 1),
	}
	type row struct {
		name, aws string
		err       error
	}
	const (
		validation = "ValidationError"
		input      = "InvalidInput"
	)
	longName := strings.Repeat("p", iam.MaxSAMLProviderNameLen+1)
	short := samlDocOfLen(t, iam.MinSAMLMetadataLen-1)
	huge := strings.Repeat("x", iam.MaxSAMLMetadataLen+1)
	cases := []row{
		{"bad project", validation, create("Bad_Project", "corp", doc)},
		{"empty name", validation, create(proj, "", doc)},
		{"long name", validation, create(proj, longName, doc)},
		{"space in name", validation, create(proj, "a b", doc)},
		{"slash in name", validation, create(proj, "a/b", doc)},
		{"plus in name", validation, create(proj, "a+b", doc)},
		{"non-ASCII name", validation, create(proj, "é", doc)},
		{"empty document", validation, create(proj, "corp", "")},
		{"document of 999 characters", validation, create(proj, "corp", short)},
		{"document over 10,000,000 characters", validation, create(proj, "corp", huge)},
		{"51 tags", validation, create(proj, "corp", doc, tooMany...)},
		{"reserved tag key", input, create(proj, "corp", doc, samlTag("aws:team", "a"))},
		{"empty tag key", input, create(proj, "corp", doc, samlTag("", "a"))},
		{"tag value outside the alphabet", input, create(proj, "corp", doc, samlTag("k", "<script>"))},
		{"tag key of 129 characters", input, create(proj, "corp", doc, samlTag(strings.Repeat("k", 129), "v"))},
		{"a bad tag among good ones", input, create(proj, "corp", doc, samlTag("a", "1"), samlTag("b!", "2"))},
	}
	for name, d := range hostile {
		cases = append(cases, row{"metadata: " + name, input, create(proj, "corp", d)})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantAWS(t, c.err, codes.InvalidArgument, c.aws)
			if msg := status.Convert(c.err).Message(); strings.Contains(msg, canary) || len(msg) > 400 {
				t.Fatalf("message carries the document: %q", msg)
			}
		})
	}
	if n := samlCount(t, b); n != 0 {
		t.Fatalf("%d providers stored by refused requests", n)
	}

	fifty := make([]*iamv1.Tag, iam.MaxSAMLProviderTags)
	for i := range fifty {
		fifty[i] = samlTag("k"+strconv.Itoa(i), strings.Repeat("v", 256))
	}
	accepted := []struct {
		name, document string
		tags           []*iamv1.Tag
	}{
		{strings.Repeat("p", iam.MaxSAMLProviderNameLen), doc, nil},
		{"A_b.c-9", doc, nil},
		{"min", samlDocOfLen(t, iam.MinSAMLMetadataLen), nil},
		{"fifty", doc, fifty},
		{"repeat", doc, append(append([]*iamv1.Tag{}, fifty...), fifty[0])[:iam.MaxSAMLProviderTags]},
	}
	for _, a := range accepted {
		if _, err := e.api.CreateSAMLProvider(ctx, proj, a.name, a.document, a.tags); err != nil {
			t.Errorf("CreateSAMLProvider(%.20s) at the AWS bounds: %v", a.name, err)
		}
	}
	if n := samlCount(t, b); n != len(accepted) {
		t.Fatalf("%d providers stored, want %d", n, len(accepted))
	}

	fb := failingCreate{memstore.New(), iam.KindSAMLProvider, errors.New("backend down")}
	fe := newEnvOn(t, fb, &now)
	_, err := fe.api.CreateSAMLProvider(ctx, proj, "corp", doc, nil)
	wantAWS(t, err, codes.Internal, "InternalFailure")
	if msg := status.Convert(err).Message(); strings.Contains(msg, "backend down") {
		t.Fatalf("message carries backend detail: %q", msg)
	}
}

// TestCreateSAMLProviderCanceled: a request that was canceled before the
// write stores nothing, and the same request made afterwards succeeds.
func TestCreateSAMLProviderCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	doc := samlDocOfLen(t, 1500)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.api.CreateSAMLProvider(canceled, proj, "gone", doc, nil); err == nil {
		t.Fatal("a canceled create succeeded")
	}
	if n := samlCount(t, b); n != 0 {
		t.Fatalf("%d providers stored by a canceled request", n)
	}
	if _, err := e.api.CreateSAMLProvider(t.Context(), proj, "gone", doc, nil); err != nil {
		t.Fatalf("the same request afterwards: %v", err)
	}
}

// TestCreateSAMLProviderSizeLimit: a provider whose stored encoding is
// exactly iam.MaxSAMLProviderEncodedLen bytes is created, however few
// characters its document has once escaping is counted, and is read back
// intact; one byte more is InvalidInput and stores nothing. On both store
// backends.
func TestCreateSAMLProviderSizeLimit(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			// A time without a fraction and a UUID UID encode to the same
			// length whatever the server picks.
			now := time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC)
			e := newEnvOn(t, b, &now)
			sized := func(comment string) iam.SAMLProvider {
				return iam.SAMLProvider{
					Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: "big", Created: now,
					MetadataDocument: storetest.SAMLMetadata(comment),
				}
			}
			encoded := func(p iam.SAMLProvider) int {
				enc, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				return len(enc)
			}
			// <, > and & are six bytes each once encoded.
			room := iam.MaxSAMLProviderEncodedLen - encoded(sized(""))
			comment := strings.Repeat("<&>", room/18) + strings.Repeat("x", room%18)
			doc := sized(comment).MetadataDocument
			if got := encoded(sized(comment)); got != iam.MaxSAMLProviderEncodedLen {
				t.Fatalf("test provider encodes to %d, want %d", got, iam.MaxSAMLProviderEncodedLen)
			}
			if n := utf8.RuneCountInString(doc); n > iam.MaxSAMLProviderEncodedLen/4 {
				t.Fatalf("%d characters: escaping should make the encoding much larger", n)
			}
			create := func(name, document string) error {
				_, err := e.api.CreateSAMLProvider(t.Context(), proj, name, document, nil)
				return err
			}
			if err := create("big", doc); err != nil {
				t.Fatalf("a provider at the limit: %v", err)
			}
			got := storedSAML(t, b, "big")
			if got.Object.MetadataDocument != doc || encoded(got.Object) != iam.MaxSAMLProviderEncodedLen {
				t.Fatalf("stored document differs or is not at the limit: %d bytes", len(got.Object.MetadataDocument))
			}
			err := create("bigger", doc+" ")
			wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
			msg := status.Convert(err).Message()
			if !strings.Contains(msg, strconv.Itoa(iam.MaxSAMLProviderEncodedLen)) || len(msg) > 200 {
				t.Fatalf("message %q should name the limit and not the document", msg)
			}
			_, err = store.Get[iam.SAMLProvider](t.Context(), store.Scoped(b, proj), "bigger")
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("the refused provider was stored: %v", err)
			}
			huge := strings.Repeat("x", iam.MaxSAMLProviderEncodedLen+1)
			wantAWS(t, create("huge", huge), codes.InvalidArgument, "InvalidInput")
			if n := samlCount(t, b); n != 1 {
				t.Fatalf("%d providers stored, want 1", n)
			}
		})
	}
}
