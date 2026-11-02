package iam_test

import (
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestValidPolicyARN pins what a stored permissions boundary may be.
func TestValidPolicyARN(t *testing.T) {
	for _, a := range []string{
		"arn:vws:iam::123456789012:policy/Boundary",
		"arn:vws:iam::vws:policy/a",
		"arn:vws:iam::p:policy/path/to/Boundary",
		"arn:vws:iam::123456789012:policy/" + strings.Repeat("p", 2048-len("arn:vws:iam::123456789012:policy/")),
	} {
		if !iam.ValidPolicyARN(a) {
			t.Errorf("ValidPolicyARN(%q) = false, want true", a)
		}
	}
	for _, a := range []string{
		"",
		"arn:vws:iam::p:policy",
		"arn:vws:iam::p:policy/",
		"arn:vws:iam:::policy/Boundary",
		"arn:aws:iam::123456789012:policy/Boundary",
		"arn:vws:iam::123456789012:role/Boundary",
		"arn:vws:s3::123456789012:policy/Boundary",
		"arn:vws:iam::123456789012:policy/" + strings.Repeat("p", 2049-len("arn:vws:iam::123456789012:policy/")),
	} {
		if iam.ValidPolicyARN(a) {
			t.Errorf("ValidPolicyARN(%q) = true, want false", a)
		}
	}
}

// TestRoleValidateBoundary: a role with no boundary or a policy ARN
// boundary is valid; any other boundary is refused before it is stored.
func TestRoleValidateBoundary(t *testing.T) {
	r := iam.Role{Name: "r", AssumeRolePolicy: `{"Version":"2012-10-17","Statement":[]}`}
	if err := r.Validate(); err != nil {
		t.Fatalf("no boundary: %v", err)
	}
	r.PermissionsBoundary = "arn:vws:iam::123456789012:policy/Boundary"
	if err := r.Validate(); err != nil {
		t.Fatalf("policy boundary: %v", err)
	}
	r.PermissionsBoundary = "arn:vws:iam::123456789012:role/r"
	if err := r.Validate(); err == nil {
		t.Fatal("role ARN boundary accepted")
	}
}
