package password_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/password"
)

func TestHashVerify(t *testing.T) {
	h, err := password.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") || strings.Contains(h, "correct horse") {
		t.Fatalf("hash %q", h)
	}
	if err := password.Verify("correct horse", h); err != nil {
		t.Fatal(err)
	}
	if err := password.Verify("wrong", h); !errors.Is(err, password.ErrMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
	h2, err := password.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if h2 == h {
		t.Fatal("salt is not random")
	}
}

func TestVerifyRejectsHostileHashes(t *testing.T) {
	for _, h := range []string{"", "plain", "$argon2i$v=19$m=1,t=1,p=1$AA$AA", "$argon2id$v=19$m=4294967295,t=1,p=1$AA$AA", "$argon2id$v=19$m=8,t=99,p=1$AA$AA", "$argon2id$v=16$m=8,t=1,p=1$AA$AA"} {
		if err := password.Verify("x", h); err == nil || errors.Is(err, password.ErrMismatch) {
			t.Errorf("%q: %v", h, err)
		}
	}
}
