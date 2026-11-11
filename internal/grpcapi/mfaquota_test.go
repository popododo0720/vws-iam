package grpcapi_test

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/store/memstore"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/totp"
)

func TestMFAQuotaEtcd(t *testing.T) { testMFAQuotaOn(t, etcdBackend) }
func TestMFAQuotaMemstore(t *testing.T) {
	testMFAQuotaOn(t, func(*testing.T) store.Backend { return memstore.New() })
}

func testMFAQuotaOn(t *testing.T, backend func(*testing.T) store.Backend) {
	for _, kind := range []string{"virtual", "fido", "mixed"} {
		t.Run(kind, func(t *testing.T) {
			b := store.Scoped(backend(t), proj)
			now := time.Unix(1_800_000_000, 0)
			keys, err := secret.NewKeyring("k1", map[string][]byte{"k1": make([]byte, 32)})
			if err != nil {
				t.Fatal(err)
			}
			svc := mfa.New(b, keys, proj, func() time.Time { return now })
			user := iam.User{Meta: iam.Meta{UID: "alice-uid"}, Name: "alice", ID: "alice"}
			if _, err := store.Create(t.Context(), b, user); err != nil {
				t.Fatal(err)
			}
			enrollDevice := func(name string) []byte {
				e, err := svc.CreateVirtual(t.Context(), name, "")
				if err != nil {
					t.Fatal(err)
				}
				seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(e.Base32Seed)
				if err != nil {
					t.Fatal(err)
				}
				return seed
			}
			code := func(seed []byte, off int64) string { return totp.Code(seed, totp.Step(now)+off, totp.Digits) }
			credential := func(id string) mfa.FidoCredential {
				return mfa.FidoCredential{ID: []byte(id), PublicKey: []byte{0xa5}}
			}
			ctx := t.Context()
			for i := range 7 {
				name := fmt.Sprintf("phone-%d", i)
				seed := enrollDevice(name)
				if err := svc.Enable(t.Context(), "alice", name, code(seed, -1), code(seed, 0)); err != nil {
					t.Fatal(err)
				}
			}
			calls := make([]func() error, 2)
			for i := range calls {
				name := fmt.Sprintf("racing-%d", i)
				if kind == "fido" || (kind == "mixed" && i == 1) {
					calls[i] = func() error {
						_, err := svc.RegisterFido(ctx, "alice", name, credential(name+"-credential"))
						return err
					}
				} else {
					e, err := svc.CreateVirtual(ctx, name, "")
					if err != nil {
						t.Fatal(err)
					}
					seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(e.Base32Seed)
					if err != nil {
						t.Fatal(err)
					}
					calls[i] = func() error { return svc.Enable(ctx, "alice", name, code(seed, -1), code(seed, 0)) }
				}
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			var wg sync.WaitGroup
			for _, call := range calls {
				wg.Go(func() { <-start; results <- call() })
			}
			close(start)
			wg.Wait()
			close(results)
			successes := 0
			for err := range results {
				if err == nil {
					successes++
				} else if !errors.Is(err, mfa.ErrLimitExceeded) {
					t.Fatalf("racing enable: %v", err)
				}
			}
			if successes != 1 {
				t.Fatalf("successes = %d, want 1", successes)
			}
			virtual, err := svc.List(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}
			fido, err := svc.ListFido(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if got := len(virtual) + len(fido); got != 8 {
				t.Fatalf("devices = %d, want 8", got)
			}
			if len(fido) > 0 {
				if err := svc.DeactivateFido(ctx, "alice", svc.FidoSerial(fido[0])); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := svc.Deactivate(ctx, "alice", virtual[0].Name); err != nil {
					t.Fatal(err)
				}
			}
			_, err = svc.RegisterFido(context.Background(), "alice", "replacement", credential("replacement-credential"))
			if err != nil {
				t.Fatalf("freed slot: %v", err)
			}
		})
	}
}
