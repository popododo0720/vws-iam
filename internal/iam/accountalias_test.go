package iam_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestValidAccountAlias: 3 to 63 of [a-z0-9-], no hyphen first, last or
// twice in a row, the AWS AccountAlias pattern.
func TestValidAccountAlias(t *testing.T) {
	for _, s := range []string{
		"abc", "a-b", "example-corporation", "123", "a1-b2-c3",
		strings.Repeat("a", iam.MaxAccountAliasLen),
	} {
		if !iam.ValidAccountAlias(s) {
			t.Errorf("ValidAccountAlias(%q) = false, want true", s)
		}
	}
	for _, s := range []string{
		"", "a", "ab", strings.Repeat("a", iam.MaxAccountAliasLen+1),
		"-ab", "ab-", "a--b", "Abc", "a_b", "a.b", "a b", "ab\u00e9", "a/b",
	} {
		if iam.ValidAccountAlias(s) {
			t.Errorf("ValidAccountAlias(%q) = true, want false", s)
		}
	}
}

func TestAccountAliasValidate(t *testing.T) {
	if err := (iam.AccountAlias{Name: "example-corp"}).Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	for _, n := range []string{"", "EXAMPLE", "a--b"} {
		if err := (iam.AccountAlias{Name: n}).Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("Validate(%q) = %v, want ErrInvalid", n, err)
		}
	}
}

func TestAccountAliasClaimValidate(t *testing.T) {
	if err := (iam.AccountAliasClaim{Name: "example-corp", Project: "proj-a", UID: "a-1"}).Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	for _, c := range []iam.AccountAliasClaim{
		{Name: "a--b", Project: "proj-a", UID: "a-1"},
		{Name: "example-corp", Project: "Bad_Project", UID: "a-1"},
		{Name: "example-corp", Project: "", UID: "a-1"},
		{Name: "example-corp", Project: "proj-a"},
	} {
		if err := c.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("Validate(%+v) = %v, want ErrInvalid", c, err)
		}
	}
}
