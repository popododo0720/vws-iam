package grpcapi_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// seedPasswordPolicy stores a custom password policy in project pid.
func seedPasswordPolicy(t *testing.T, b store.Backend, pid string) {
	t.Helper()
	p := iam.PasswordPolicy{
		Meta:                  iam.Meta{UID: iam.NewUID(), Generation: 1},
		MinimumPasswordLength: 12, RequireSymbols: true, MaxPasswordAge: 90,
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, pid), p); err != nil {
		t.Fatal(err)
	}
}

// storedPasswordPolicy returns the password policy of project pid,
// failing unless it is stored.
func storedPasswordPolicy(t *testing.T, b store.Backend, pid string) store.Versioned[iam.PasswordPolicy] {
	t.Helper()
	v, err := store.Get[iam.PasswordPolicy](t.Context(), store.Scoped(b, pid), iam.PasswordPolicyKey)
	if err != nil {
		t.Fatalf("password policy of %s: %v, want stored", pid, err)
	}
	return v
}

// passwordPolicyGone fails unless project pid stores no password policy.
func passwordPolicyGone(t *testing.T, b store.Backend, pid string) {
	t.Helper()
	_, err := store.Get[iam.PasswordPolicy](t.Context(), store.Scoped(b, pid), iam.PasswordPolicyKey)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("password policy of %s after delete: %v, want not found", pid, err)
	}
}

// TestDeleteAccountPasswordPolicy: the project's policy is deleted, a
// repeat from another replica is NoSuchEntity naming the account, and
// another project's policy stays unwritten. On both store backends.
func TestDeleteAccountPasswordPolicy(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			seedPasswordPolicy(t, b, proj)
			seedPasswordPolicy(t, b, "other")
			before := storedPasswordPolicy(t, b, "other")
			if err := e.api.DeleteAccountPasswordPolicy(ctx, proj); err != nil {
				t.Fatal(err)
			}
			passwordPolicyGone(t, b, proj)
			err := other.api.DeleteAccountPasswordPolicy(ctx, proj)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			want := "The Password Policy with domain name " + proj + " cannot be found."
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("NoSuchEntity message %q, want %q", err, want)
			}
			if got := storedPasswordPolicy(t, b, "other"); got.Version != before.Version {
				t.Fatalf("another project's policy was written: version %q, want %q", got.Version, before.Version)
			}
		})
	}
}

// TestDeleteAccountPasswordPolicyNone: a project that never had a custom
// policy is NoSuchEntity, every time, and nothing is stored.
func TestDeleteAccountPasswordPolicyNone(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	for range 2 {
		wantAWS(t, e.api.DeleteAccountPasswordPolicy(t.Context(), proj), codes.NotFound, "NoSuchEntity")
	}
	passwordPolicyGone(t, b, proj)
}

// TestDeleteAccountPasswordPolicyErrors: a bad project is ValidationError
// before any store access, and a store failure on the read or the delete
// is InternalFailure, without backend detail, and keeps the policy.
func TestDeleteAccountPasswordPolicyErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedPasswordPolicy(t, b, proj)
	for _, pid := range []string{"", "Bad_Project", "a/b", "proj\x00"} {
		wantAWS(t, e.api.DeleteAccountPasswordPolicy(t.Context(), pid), codes.InvalidArgument, "ValidationError")
	}
	storedPasswordPolicy(t, b, proj)

	boom := errors.New("backend down")
	for _, fail := range []func(store.Backend) store.Backend{
		func(m store.Backend) store.Backend { return failingGet{m, iam.KindPasswordPolicy, boom} },
		func(m store.Backend) store.Backend { return failingDelete{m, iam.KindPasswordPolicy, boom} },
	} {
		m := memstore.New()
		fe := newEnvOn(t, fail(m), &now)
		seedPasswordPolicy(t, m, proj)
		err := fe.api.DeleteAccountPasswordPolicy(t.Context(), proj)
		wantAWS(t, err, codes.Internal, "InternalFailure")
		if strings.Contains(err.Error(), "backend down") {
			t.Fatalf("error %v leaks backend detail", err)
		}
		storedPasswordPolicy(t, m, proj)
	}
}

// TestDeleteAccountPasswordPolicyCanceled: a request whose context is
// canceled deletes nothing.
func TestDeleteAccountPasswordPolicyCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedPasswordPolicy(t, b, proj)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := e.api.DeleteAccountPasswordPolicy(ctx, proj)
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
	storedPasswordPolicy(t, b, proj)
}

// TestDeleteAccountPasswordPolicyConcurrent: of deletes racing on two
// replicas exactly one succeeds and the rest are NoSuchEntity, so a
// retried request is never a second delete. On both store backends.
func TestDeleteAccountPasswordPolicyConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			seedPasswordPolicy(t, b, proj)
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.DeleteAccountPasswordPolicy(t.Context(), proj)
				})
			}
			wg.Wait()
			deleted := 0
			for _, err := range errs {
				if err == nil {
					deleted++
					continue
				}
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
			if deleted != 1 {
				t.Fatalf("%d deletes succeeded, want exactly one", deleted)
			}
			passwordPolicyGone(t, b, proj)
		})
	}
}

// changingPolicyBeforeDelete rewrites the password policy before the
// first n deletes of it, as a concurrent update between the read and the
// delete would.
type changingPolicyBeforeDelete struct {
	store.Backend
	mu sync.Mutex
	n  int
	t  *testing.T
}

func (c *changingPolicyBeforeDelete) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if k == iam.KindPasswordPolicy {
		c.mu.Lock()
		change := c.n > 0
		c.n--
		c.mu.Unlock()
		if change {
			b := store.Scoped(c.Backend, proj)
			if _, err := store.Mutate(ctx, b, iam.PasswordPolicyKey, func(p *iam.PasswordPolicy) error {
				p.MinimumPasswordLength++
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		}
	}
	return c.Backend.Delete(ctx, k, key, version)
}

// TestDeleteAccountPasswordPolicyStaleRead: a policy written after it
// was read is read again and then deleted, never deleted blind at a
// stale version; one that keeps changing is ConcurrentModification and
// stays. On both store backends.
func TestDeleteAccountPasswordPolicyStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedPasswordPolicy(t, inner, proj)
			b := &changingPolicyBeforeDelete{Backend: inner, n: 1, t: t}
			if err := newEnvOn(t, b, &now).api.DeleteAccountPasswordPolicy(t.Context(), proj); err != nil {
				t.Fatalf("delete after one concurrent write: %v, want deleted", err)
			}
			passwordPolicyGone(t, inner, proj)

			seedPasswordPolicy(t, inner, proj)
			b = &changingPolicyBeforeDelete{Backend: inner, n: 1 << 30, t: t}
			err := newEnvOn(t, b, &now).api.DeleteAccountPasswordPolicy(t.Context(), proj)
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			storedPasswordPolicy(t, inner, proj)
		})
	}
}
