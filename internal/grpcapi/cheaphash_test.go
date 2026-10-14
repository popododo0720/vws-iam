package grpcapi_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// cheapPasswords replaces the stored goodPW hash of users with an argon2id
// hash at the smallest parameters (8 KiB, t=1, p=1). password.Verify takes
// the cost from the stored PHC string, so every later Login of these users
// costs microseconds instead of a 64 MiB, t=3 derivation.
//
// Why (#43): the attempt-limit suites run dozens of Logins, each under a
// wall-clock RPC deadline. Production-cost argon2id is ~0.3 s of CPU per
// call under -race when idle, and on a shared box at load 60-240 (8 CPUs)
// one call alone could exceed the 30 s deadline; ConcurrentGuesses also ran
// 30 such derivations at once (about 2 GiB). The limit logic under test
// does not depend on the hash cost, and the window logic already runs on
// the injected clock, so the suite no longer depends on CPU budget.
func cheapPasswords(t *testing.T, b store.Backend, users ...string) {
	t.Helper()
	pb := store.Scoped(b, proj)
	for _, n := range users {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			t.Fatal(err)
		}
		const m, it, p = 8, 1, 1
		h := argon2.IDKey([]byte(goodPW), salt, it, m, p, 32)
		phc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, m, it, p,
			base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h))
		if _, err := store.Mutate(t.Context(), pb, n, func(u *iam.User) error {
			u.PasswordHash = phc
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
