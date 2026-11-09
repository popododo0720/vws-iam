package policy_test

import (
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/policy"
)

// TestFoldKeyMatchesEqualFold: two keys have the same FoldKey exactly
// when strings.EqualFold holds, so a filter built on it drops every
// spelling a Request lookup would find, U+017F and U+212A included.
func TestFoldKeyMatchesEqualFold(t *testing.T) {
	keys := []string{
		"aws:EpochTime", "AWS:EPOCHTIME", "awſ:EpochTime", "aws:Epochтime", "saml:sub", "ſaml:sub",
		"K", "k", "K", "µ", "μ", "Μ", "\xff", "�", "", "aws:currenttime", "aws:CurrentTim",
	}
	for _, a := range keys {
		for _, b := range keys {
			if got, want := policy.FoldKey(a) == policy.FoldKey(b), strings.EqualFold(a, b); got != want {
				t.Errorf("FoldKey(%q) == FoldKey(%q) is %v, EqualFold %v", a, b, got, want)
			}
		}
	}
}

func FuzzFoldKeyMatchesEqualFold(f *testing.F) {
	f.Add("aws:EpochTime", "awſ:epochtime")
	f.Add("K", "k")
	f.Fuzz(func(t *testing.T, a, b string) {
		if got, want := policy.FoldKey(a) == policy.FoldKey(b), strings.EqualFold(a, b); got != want {
			t.Fatalf("FoldKey(%q) == FoldKey(%q) is %v, EqualFold %v", a, b, got, want)
		}
	})
}

func TestKeySet(t *testing.T) {
	s := policy.NewKeySet("aws:EpochTime", "saml:*")
	for k, want := range map[string]bool{
		"aws:epochtime": true, "AWS:EPOCHTIME": true, "awſ:EpochTime": true,
		"saml:sub": true, "SAML:aud": true, "ſaml:sub": true, "saml:": true,
		"aws:EpochTimes": false, "aws:CurrentTime": false, "sam:sub": false, "": false,
	} {
		if s.Has(k) != want {
			t.Errorf("Has(%q) = %v, want %v", k, !want, want)
		}
	}
}
