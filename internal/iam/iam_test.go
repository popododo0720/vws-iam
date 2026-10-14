package iam_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

func TestValidateRejectsHostileInput(t *testing.T) {
	seal := iam.Sealed{KeyID: "k", Ciphertext: []byte{1}}
	bad := []iam.Object{
		iam.User{Name: ""},
		iam.User{Name: strings.Repeat("a", 65)},
		iam.User{Name: "a/b"},
		iam.User{Name: "a", Path: "no-slash"},
		iam.User{Name: "a", PasswordHash: "plaintext"},
		iam.User{Name: "a", AttachedPolicies: []string{"arn:aws:iam::1:policy/x"}},
		iam.Group{Name: "g", AttachedPolicies: []string{"arn:vws:iam::1:policy/x", "arn:vws:iam::1:policy/x"}},
		iam.Role{Name: "r"},
		iam.Role{Name: "r", AssumeRolePolicy: "{}", MaxSessionDuration: 13 * time.Hour},
		iam.Policy{Name: "p"},
		iam.Policy{Name: "p", DefaultVersion: "v2", Versions: []iam.PolicyVersion{{ID: "v1"}}},
		iam.AccessKey{ID: "short", UserName: "a", Status: iam.KeyActive, Secret: seal},
		iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "a", Status: "On", Secret: seal},
		iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "a", Status: iam.KeyActive},
		iam.MfaDevice{Name: "d", Enabled: true, Seed: seal},
		iam.MfaDevice{Name: "d"},
	}
	for i, o := range bad {
		if err := o.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%d %T: %v, want ErrInvalid", i, o, err)
		}
	}
}

func TestARNs(t *testing.T) {
	if got := iam.UserARN("000000000000", iam.User{Name: "a", Path: "/dev/"}); got != "arn:vws:iam::000000000000:user/dev/a" {
		t.Fatal(got)
	}
	if got := iam.RoleARN("000000000000", iam.Role{Name: "r"}); got != "arn:vws:iam::000000000000:role/r" {
		t.Fatal(got)
	}
}
