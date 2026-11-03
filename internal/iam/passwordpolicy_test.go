package iam_test

import (
	"errors"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestPasswordPolicyValidate: the AWS bounds are accepted at both ends
// and refused one past them.
func TestPasswordPolicyValidate(t *testing.T) {
	for _, p := range []iam.PasswordPolicy{
		{MinimumPasswordLength: 6},
		{MinimumPasswordLength: 128, MaxPasswordAge: 1095, PasswordReusePrevention: 24, HardExpiry: true},
		{MinimumPasswordLength: 14, MaxPasswordAge: 1, PasswordReusePrevention: 1, RequireSymbols: true},
	} {
		if err := p.Validate(); err != nil {
			t.Errorf("Validate(%+v): %v", p, err)
		}
	}
	for _, p := range []iam.PasswordPolicy{
		{},
		{MinimumPasswordLength: 5},
		{MinimumPasswordLength: 129},
		{MinimumPasswordLength: 8, MaxPasswordAge: -1},
		{MinimumPasswordLength: 8, MaxPasswordAge: 1096},
		{MinimumPasswordLength: 8, PasswordReusePrevention: -1},
		{MinimumPasswordLength: 8, PasswordReusePrevention: 25},
	} {
		if err := p.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("Validate(%+v) = %v, want ErrInvalid", p, err)
		}
	}
	if k := (iam.PasswordPolicy{}).Key(); k != iam.PasswordPolicyKey {
		t.Errorf("Key() = %q, want %q", k, iam.PasswordPolicyKey)
	}
}
