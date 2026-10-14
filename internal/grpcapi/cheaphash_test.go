package grpcapi_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// cheapPHC is an argon2id PHC string of pw at the smallest parameters
// (8 KiB, t=1, p=1). password.Verify takes the cost from the stored PHC
// string, so verifying against it costs microseconds instead of a 64 MiB,
// t=3, p=4 derivation.
func cheapPHC(t *testing.T, pw string) string {
	t.Helper()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	const m, it, p = 8, 1, 1
	h := argon2.IDKey([]byte(pw), salt, it, m, p, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, m, it, p,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h))
}

// withCheapPassword creates users through the API and stores a cheapPHC of
// goodPW as their login profile directly in b. No production-cost hash is
// computed: SetLoginProfile would derive one (64 MiB, t=3, p=4) inside a
// call whose deadline is ClientServiceConfig's 5s.
//
// Why (#43): the attempt-limit suites run dozens of Logins, each under
// that 5s per-call budget (the 30s context of login() does not lift it:
// gRPC takes the shorter of the two). Production-cost argon2id is ~0.3 s
// of CPU per call under -race when idle, and on a shared box at load 20-240
// (8 CPUs) one derivation, or the CPU it takes from concurrent calls, could
// exceed the budget. The limit logic under test does not depend on the
// hash cost, and the window logic already runs on the injected clock.
func withCheapPassword(t *testing.T, e *env, b store.Backend, users ...string) {
	t.Helper()
	pb := store.Scoped(b, proj)
	for _, n := range users {
		e.createUser(t, t.Context(), n)
		phc := cheapPHC(t, goodPW)
		if _, err := store.Mutate(t.Context(), pb, n, func(u *iam.User) error {
			u.PasswordHash = phc
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// cheapDummyHash makes a Login that names an unknown user verify against a
// cheapPHC instead of the server's production-cost dummy hash, whose first
// use derives one (sync.OnceValue) and every use verifies at 64 MiB, t=3.
// PerSourceIP sends IPAttemptLimit such Logins.
func cheapDummyHash(t *testing.T) {
	t.Helper()
	grpcapi.SetDummyHash(t, cheapPHC(t, "vws-iam-unknown-user-placeholder"))
}
