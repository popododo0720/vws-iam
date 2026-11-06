package iam_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestRequestTokensValidation: Validate keeps at most MaxRequests request
// tokens of 1 to 128 characters of [A-Za-z0-9._-] on every kind that
// records them, and a policy version token follows the same rule.
func TestRequestTokensValidation(t *testing.T) {
	tok := "rq-0123456789abcdef0123456789abcdef." + strings.Repeat("f", 64)
	many := make([]string, iam.MaxRequests+1)
	for i := range many {
		many[i] = tok
	}
	seal := iam.Sealed{KeyID: "k", Ciphertext: []byte{1}}
	doc := `{"Version":"2012-10-17","Statement":[]}`
	objects := func(reqs []string, versionToken string) []iam.Object {
		m := iam.Meta{Requests: reqs}
		return []iam.Object{
			iam.User{Meta: m, Name: "u"},
			iam.Group{Meta: m, Name: "g"},
			iam.Role{Meta: m, Name: "r", AssumeRolePolicy: doc},
			iam.Policy{
				Meta:           m,
				Name:           "p",
				DefaultVersion: "v1",
				Versions:       []iam.PolicyVersion{{ID: "v1", Document: doc, Request: versionToken}},
			},
			iam.AccessKey{Meta: m, ID: "AKIAABCDEFGHIJKLMNOP", UserName: "u", Status: iam.KeyActive, Secret: seal},
			iam.MfaDevice{Meta: m, Name: "d", Seed: seal},
		}
	}
	for _, o := range objects(many[:iam.MaxRequests], tok) {
		if err := o.Validate(); err != nil {
			t.Errorf("%T with %d tokens: %v", o, iam.MaxRequests, err)
		}
	}
	for _, reqs := range [][]string{many, {""}, {"a b"}, {strings.Repeat("a", 129)}, {"rq-\x00"}} {
		for _, o := range objects(reqs, "") {
			if err := o.Validate(); !errors.Is(err, iam.ErrInvalid) {
				t.Errorf("%T with %d tokens %.20q: %v, want ErrInvalid", o, len(reqs), reqs[0], err)
			}
		}
	}
	p := objects(nil, "a b")[3]
	if err := p.Validate(); !errors.Is(err, iam.ErrInvalid) {
		t.Errorf("policy version token %q: %v, want ErrInvalid", "a b", err)
	}
}
