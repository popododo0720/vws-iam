package iam_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

const goodThumbprint = "9e99a48a9960b14926bb7f3b02e22da2b0ab7280"

func TestCheckOIDCProviderURL(t *testing.T) {
	for _, u := range []string{
		"https://token.example.test",
		"https://Token.Example.TEST/team/a",
		"https://a",
		"https://10.0.0.1",
		"https://x-1.example/p%20q/~r%aF",
		"https://example.test/",
		"https://" + strings.Repeat("a", 63) + ".test",
	} {
		if err := iam.CheckOIDCProviderURL(u); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	for _, u := range []string{
		"", "token.example.test", "http://token.example.test", "HTTPS://token.example.test", "https://",
		"https:///path", "https://a.test:443", "https://user@a.test", "https://a.test?x=1", "https://a.test/p?x",
		"https://a.test#f", "https://a .test", "https://a.test/p q", "https://a.test/\x00", "https://é.test",
		"https://a.test/é", "https://-a.test", "https://a-.test", "https://a..test", "https://.a.test",
		"https://a.test.", "https://a_b.test", "https://[::1]", "https://" + strings.Repeat("a", 64) + ".test",
		"https://a.test/%zz", "https://a.test/%", "https://a.test/%2", "https://a.test/%%41", "https://a.test/%g0",
	} {
		err := iam.CheckOIDCProviderURL(u)
		if !errors.Is(err, iam.ErrOIDCProviderURL) {
			t.Errorf("%q: %v, want ErrOIDCProviderURL", u, err)
			continue
		}
		if u != "" && strings.Contains(err.Error(), u) {
			t.Errorf("%q: the error carries the URL: %v", u, err)
		}
	}
}

func TestValidOIDCClientIDAndThumbprint(t *testing.T) {
	for _, id := range []string{"a", "sts.amazonaws.com", "é", strings.Repeat("é", iam.MaxOIDCClientIDLen), "a b/c"} {
		if !iam.ValidOIDCClientID(id) {
			t.Errorf("client id %q refused", id)
		}
	}
	for _, id := range []string{"", strings.Repeat("a", iam.MaxOIDCClientIDLen+1), "\xff"} {
		if iam.ValidOIDCClientID(id) {
			t.Errorf("client id %q accepted", id)
		}
	}
	for _, tp := range []string{goodThumbprint, strings.ToUpper(goodThumbprint)} {
		if !iam.ValidOIDCThumbprint(tp) {
			t.Errorf("thumbprint %q refused", tp)
		}
	}
	for _, tp := range []string{
		"", goodThumbprint[:39], goodThumbprint + "0", "g" + goodThumbprint[1:], " " + goodThumbprint[1:],
	} {
		if iam.ValidOIDCThumbprint(tp) {
			t.Errorf("thumbprint %q accepted", tp)
		}
	}
}

func TestOIDCProviderValidate(t *testing.T) {
	p := iam.OIDCProvider{
		URL: "https://Token.Example.test/team", ClientIDs: []string{"sts.amazonaws.com", "app"},
		Thumbprints: []string{goodThumbprint}, Tags: map[string]string{"team": "a"}, Created: time.Now(),
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("a valid provider: %v", err)
	}
	if p.Kind() != iam.KindOIDCProvider || p.Key() != "!token.!example.test/team" {
		t.Fatalf("kind %v key %q", p.Kind(), p.Key())
	}
	if err := (iam.OIDCProvider{URL: "https://a.test"}).Validate(); err != nil {
		t.Fatalf("no client ids, thumbprints or tags: %v", err)
	}

	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "c" + strconv.Itoa(i)
		}
		return out
	}
	tps := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strconv.Itoa(i) + goodThumbprint[1:]
		}
		return out
	}
	tags := func(n int) map[string]string {
		out := map[string]string{}
		for i := range n {
			out["k"+strconv.Itoa(i)] = "v"
		}
		return out
	}
	full := iam.OIDCProvider{
		URL: "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." +
			strings.Repeat("d", iam.MaxOIDCProviderURLLen-8-3*64),
		ClientIDs: ids(iam.MaxOIDCClientIDs), Thumbprints: tps(iam.MaxOIDCThumbprints), Tags: tags(iam.MaxOIDCProviderTags),
	}
	if n := len(full.URL); n != iam.MaxOIDCProviderURLLen {
		t.Fatalf("test URL has %d characters", n)
	}
	if err := full.Validate(); err != nil {
		t.Fatalf("every limit reached: %v", err)
	}

	bad := map[string]iam.OIDCProvider{
		"empty URL":          {},
		"URL of 256":         {URL: full.URL + "/"},
		"http URL":           {URL: "http://a.test"},
		"URL with a port":    {URL: "https://a.test:8443"},
		"101 client ids":     {URL: "https://a.test", ClientIDs: ids(iam.MaxOIDCClientIDs + 1)},
		"empty client id":    {URL: "https://a.test", ClientIDs: []string{""}},
		"long client id":     {URL: "https://a.test", ClientIDs: []string{strings.Repeat("a", 256)}},
		"repeated client id": {URL: "https://a.test", ClientIDs: []string{"a", "a"}},
		"6 thumbprints":      {URL: "https://a.test", Thumbprints: tps(iam.MaxOIDCThumbprints + 1)},
		"short thumbprint":   {URL: "https://a.test", Thumbprints: []string{goodThumbprint[:39]}},
		"non-hex thumbprint": {URL: "https://a.test", Thumbprints: []string{"z" + goodThumbprint[1:]}},
		"repeated thumbprint": {
			URL: "https://a.test", Thumbprints: []string{goodThumbprint, strings.ToUpper(goodThumbprint)},
		},
		"51 tags":          {URL: "https://a.test", Tags: tags(iam.MaxOIDCProviderTags + 1)},
		"reserved tag key": {URL: "https://a.test", Tags: map[string]string{"aws:x": "v"}},
	}
	for name, p := range bad {
		if err := p.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// TestOIDCProviderKey: the key has no upper-case letter, so store case
// folding keeps it, and URLs that differ in any way, case or a literal !
// included, have different keys.
func TestOIDCProviderKey(t *testing.T) {
	urls := []string{
		"https://idp.test/team", "https://idp.test/Team", "https://IDP.test/team", "https://idp.test/!team",
		"https://idp.test/!!team", "https://idp.test/!Team", "https://idp.test/!t!eam", "https://idp.test/T!eam",
		"https://idp.test/team!", "https://idp.test/teaM",
	}
	seen := map[string]string{}
	for _, u := range urls {
		k := iam.OIDCProviderKey(u)
		if strings.ToLower(k) != k {
			t.Errorf("%q: key %q has an upper-case letter", u, k)
		}
		if other, dup := seen[k]; dup {
			t.Errorf("%q and %q share key %q", u, other, k)
		}
		seen[k] = u
	}
	if got := iam.OIDCProviderKey("https://Idp.test/A!b"); got != "!idp.test/!a!!b" {
		t.Errorf("key %q", got)
	}
	if got := iam.OIDCProviderResource("https://Idp.test/A!b"); got != "Idp.test/A!b" {
		t.Errorf("resource %q", got)
	}
}
