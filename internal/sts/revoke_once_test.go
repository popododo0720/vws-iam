package sts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// contended loses every user write to another writer. The fifth read
// ends the context mid-call, as a deadline that lands during a store
// round trip does.
type contended struct {
	store.Backend
	cancel context.CancelFunc
	reads  int
}

func (c *contended) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	if k == iam.KindUser {
		if c.reads++; c.reads > 4 {
			c.cancel()
			return store.Entry{}, ctx.Err()
		}
	}
	return c.Backend.Get(ctx, k, key)
}

func (c *contended) Update(ctx context.Context, k iam.Kind, key string, spec []byte, version string) (string, error) {
	if k == iam.KindUser {
		return "", store.ErrConflict
	}
	return c.Backend.Update(ctx, k, key, spec, version)
}

// TestRevokeSessionsOnceRunsOutOfTimeUnderContention: a revocation that
// loses every race until its context ends during a retry's read fails
// with ErrConflict, so the RPC answers ConcurrentModification and not a
// bare timeout (#51). Nothing is bumped.
func TestRevokeSessionsOnceRunsOutOfTimeUnderContention(t *testing.T) {
	e := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &contended{Backend: e.b, cancel: cancel}
	svc := sts.New(b, e.keys, e.az, acct, e.clk.now)
	err := svc.RevokeSessionsOnce(ctx, authz.User, "alice", "req-1")
	if !errors.Is(err, store.ErrConflict) || !errors.Is(err, context.Canceled) || b.reads != 5 {
		t.Fatalf("err = %v after %d reads, want the conflict and context.Canceled after 5", err, b.reads)
	}
	u, err := store.Get[iam.User](context.Background(), e.b, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.Object.SessionsRevokeGeneration != 0 {
		t.Fatalf("generation %d, want 0", u.Object.SessionsRevokeGeneration)
	}
}
