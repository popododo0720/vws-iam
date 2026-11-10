package mfa_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"

	"github.com/popododo0720/vws-iam/internal/mfa"
)

func TestMFADevicesPerUser(t *testing.T) {
	for _, kind := range []string{"virtual", "fido", "mixed"} {
		t.Run(kind, func(t *testing.T) {
			svc, _, clk := setup(t)
			ctx := t.Context()
			for i := range 7 {
				enroll(t, svc, clk, "alice", fmt.Sprintf("phone-%d", i))
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
					seed := seedOf(t, e)
					calls[i] = func() error { return svc.Enable(ctx, "alice", name, code(seed, clk.t, -1), code(seed, clk.t, 0)) }
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

type beforeQuotaCommit struct {
	store.Backend
	hook func()
}

func (b *beforeQuotaCommit) UpdateIf(
	ctx context.Context, kind iam.Kind, key string, spec []byte, version string, pre store.Pre,
) (string, error) {
	if kind == iam.KindMfaDevice && b.hook != nil {
		hook := b.hook
		b.hook = nil
		hook()
	}
	return b.Backend.UpdateIf(ctx, kind, key, spec, version, pre)
}

func TestMFAExpiredHoldFencesOldWriter(t *testing.T) {
	var wrapped *beforeQuotaCommit
	svc, _, clk := setupOn(t, func(b store.Backend) store.Backend {
		wrapped = &beforeQuotaCommit{Backend: b}
		return wrapped
	})
	for i := range 7 {
		enroll(t, svc, clk, "alice", fmt.Sprintf("existing-%d", i))
	}
	e, err := svc.CreateVirtual(t.Context(), "stale", "")
	if err != nil {
		t.Fatal(err)
	}
	seed := seedOf(t, e)
	first, second := code(seed, clk.t, -1), code(seed, clk.t, 0)
	wrapped.hook = func() {
		clk.t = clk.t.Add(11 * time.Second)
		if _, err := svc.RegisterFido(t.Context(), "alice", "winner", credential("winning-credential")); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.Enable(t.Context(), "alice", "stale", first, second); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale writer: %v", err)
	}
	virtual, err := svc.List(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	fido, err := svc.ListFido(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(virtual)+len(fido) != 8 {
		t.Fatalf("devices = %d", len(virtual)+len(fido))
	}
}

func TestPendingFidoRetryAfterRestart(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := t.Context()
	cred := credential("pending-credential")
	d, err := svc.RegisterFido(ctx, "alice", "key", cred)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Mutate(ctx, b, d.ID, func(d *iam.FidoDevice) error { d.Pending = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Mutate(ctx, b, "alice", func(u *iam.User) error {
		u.MFARegistrationLease = iam.MFARegistrationLease{Holder: "crashed", Expires: clk.t.Add(-time.Second)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	restarted := mfa.New(b, nil, acct, clk.now)
	if keys, err := restarted.ListFido(ctx, "alice"); err != nil || len(keys) != 0 {
		t.Fatalf("pending device visible: %v, %v", keys, err)
	}
	if _, err := restarted.GetFido(ctx, restarted.FidoSerial(d), "alice"); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("pending get: %v", err)
	}
	if _, err := restarted.RegisterFido(ctx, "alice", "key", cred); err != nil {
		t.Fatalf("retry pending registration: %v", err)
	}
	if keys, err := restarted.ListFido(ctx, "alice"); err != nil || len(keys) != 1 {
		t.Fatalf("retry list: %v, %v", keys, err)
	}
}
