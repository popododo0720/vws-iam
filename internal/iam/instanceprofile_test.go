package iam_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestInstanceProfileValidate: a name of 1 to 128 characters of the IAM
// name alphabet, an IAM path, and at most one role with a valid role name.
func TestInstanceProfileValidate(t *testing.T) {
	ok := []iam.InstanceProfile{
		{Name: "web", ID: "AIPA1"},
		{Name: strings.Repeat("p", 128), Path: "/app/", Roles: []string{strings.Repeat("r", 64)}},
		{Name: "a+=,.@_-Z9", Path: "/", Roles: []string{"S3Access"}},
	}
	for _, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("Validate(%q): %v", p.Name, err)
		}
	}
	bad := []iam.InstanceProfile{
		{Name: ""},
		{Name: strings.Repeat("p", 129)},
		{Name: "a/b"},
		{Name: "a b"},
		{Name: "prôfile"},
		{Name: "web", Path: "app"},
		{Name: "web", Roles: []string{"a", "b"}},
		{Name: "web", Roles: []string{""}},
		{Name: "web", Roles: []string{strings.Repeat("r", 65)}},
		{Name: "web", Roles: []string{"a/b"}},
	}
	for _, p := range bad {
		if err := p.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("Validate(%+v) = %v, want ErrInvalid", p, err)
		}
	}
}

func TestValidInstanceProfileName(t *testing.T) {
	if !iam.ValidInstanceProfileName(strings.Repeat("n", iam.MaxInstanceProfileNameLen)) {
		t.Error("128-character name rejected")
	}
	if iam.ValidInstanceProfileName(strings.Repeat("n", iam.MaxInstanceProfileNameLen+1)) {
		t.Error("129-character name accepted")
	}
}
