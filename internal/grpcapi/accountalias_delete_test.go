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

// storedAlias returns account alias name of project pid, failing unless
// it is stored.
func storedAlias(t *testing.T, b store.Backend, pid, name string) store.Versioned[iam.AccountAlias] {
	t.Helper()
	v, err := store.Get[iam.AccountAlias](t.Context(), store.Scoped(b, pid), name)
	if err != nil {
		t.Fatalf("alias %s of %s: %v, want stored", name, pid, err)
	}
	return v
}

// aliasGone fails unless account alias name is absent from project pid.
func aliasGone(t *testing.T, b store.Backend, pid, name string) {
	t.Helper()
	_, err := store.Get[iam.AccountAlias](t.Context(), store.Scoped(b, pid), name)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("alias %s of %s after delete: %v, want not found", name, pid, err)
	}
}

// TestDeleteAccountAlias: the project's alias is deleted, a repeat from
// another replica is NoSuchEntity, another project's alias is
// NoSuchEntity and stays, and the listing is then empty. On both store
// backends.
func TestDeleteAccountAlias(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			seedAlias(t, b, proj, "example-corporation")
			seedAlias(t, b, "other", "other-corp")
			if err := e.api.DeleteAccountAlias(ctx, proj, "example-corporation"); err != nil {
				t.Fatal(err)
			}
			aliasGone(t, b, proj, "example-corporation")
			err := other.api.DeleteAccountAlias(ctx, proj, "example-corporation")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if !strings.Contains(err.Error(), "The account alias example-corporation cannot be found.") {
				t.Fatalf("NoSuchEntity message %q, want it to name the alias", err)
			}
			before := storedAlias(t, b, "other", "other-corp")
			wantAWS(t, e.api.DeleteAccountAlias(ctx, proj, "other-corp"), codes.NotFound, "NoSuchEntity")
			if got := storedAlias(t, b, "other", "other-corp"); got.Version != before.Version {
				t.Fatalf("another project's alias was written: version %q, want %q", got.Version, before.Version)
			}
			pg, err := other.api.ListAccountAliases(ctx, proj, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(pg.Aliases) != 0 || pg.IsTruncated {
				t.Fatalf("listing after delete = %+v, want empty and complete", pg)
			}
		})
	}
}

// TestDeleteAccountAliasErrors: a bad project or AccountAlias is
// ValidationError before any store access, the AWS length and pattern
// bounds are accepted, an unknown alias is NoSuchEntity, and a store
// failure on the read or the delete is InternalFailure, without backend
// detail, and keeps the alias.
func TestDeleteAccountAliasErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedAlias(t, b, proj, "example-corp")
	bad := []string{
		"", "ab", strings.Repeat("a", iam.MaxAccountAliasLen+1),
		"ExampleCorp", "-abc", "abc-", "a--b", "a_b", "a.b", "a b", "ab\x00", "é12",
	}
	for _, n := range bad {
		wantAWS(t, e.api.DeleteAccountAlias(ctx, proj, n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.DeleteAccountAlias(ctx, "Bad_Project", "example-corp"), codes.InvalidArgument, "ValidationError")
	storedAlias(t, b, proj, "example-corp")
	wantAWS(t, e.api.DeleteAccountAlias(ctx, proj, "missing"), codes.NotFound, "NoSuchEntity")
	for _, n := range []string{"abc", "a-b", "0-9", "a-b-c-1", strings.Repeat("z", iam.MaxAccountAliasLen)} {
		seedAlias(t, b, proj, n)
		if err := e.api.DeleteAccountAlias(ctx, proj, n); err != nil {
			t.Fatalf("DeleteAccountAlias(%q): %v, want deleted", n, err)
		}
		aliasGone(t, b, proj, n)
	}

	boom := errors.New("backend down")
	for _, fail := range []func(store.Backend) store.Backend{
		func(m store.Backend) store.Backend { return failingGet{m, iam.KindAccountAlias, boom} },
		func(m store.Backend) store.Backend { return failingDelete{m, iam.KindAccountAlias, boom} },
	} {
		m := memstore.New()
		fe := newEnvOn(t, fail(m), &now)
		seedAlias(t, m, proj, "example-corp")
		err := fe.api.DeleteAccountAlias(ctx, proj, "example-corp")
		wantAWS(t, err, codes.Internal, "InternalFailure")
		if strings.Contains(err.Error(), "backend down") {
			t.Fatalf("error %v leaks backend detail", err)
		}
		storedAlias(t, m, proj, "example-corp")
	}
}

// TestDeleteAccountAliasCanceled: a request whose context is canceled
// deletes nothing.
func TestDeleteAccountAliasCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedAlias(t, b, proj, "example-corp")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := e.api.DeleteAccountAlias(ctx, proj, "example-corp")
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
	storedAlias(t, b, proj, "example-corp")
}

// TestDeleteAccountAliasConcurrent: of deletes of one alias racing on two
// replicas exactly one succeeds and the rest are NoSuchEntity, so a lost
// response retried is never a second delete. On both store backends.
func TestDeleteAccountAliasConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			seedAlias(t, b, proj, "example-corp")
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.DeleteAccountAlias(t.Context(), proj, "example-corp")
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
			aliasGone(t, b, proj, "example-corp")
		})
	}
}

// changingAliasBeforeDelete rewrites the alias before the first n deletes
// of an account alias, as a concurrent write between the read and the
// delete would.
type changingAliasBeforeDelete struct {
	store.Backend
	mu sync.Mutex
	n  int
	t  *testing.T
}

func (c *changingAliasBeforeDelete) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if k == iam.KindAccountAlias {
		c.mu.Lock()
		change := c.n > 0
		c.n--
		c.mu.Unlock()
		if change {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(a *iam.AccountAlias) error {
				a.Created = a.Created.Add(time.Second)
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		}
	}
	return c.Backend.Delete(ctx, k, key, version)
}

// TestDeleteAccountAliasStaleRead: an alias written after it was read is
// read again and then deleted, never deleted blind at a stale version;
// one that keeps changing is ConcurrentModification and stays. On both
// store backends.
func TestDeleteAccountAliasStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedAlias(t, inner, proj, "example-corp")
			b := &changingAliasBeforeDelete{Backend: inner, n: 1, t: t}
			if err := newEnvOn(t, b, &now).api.DeleteAccountAlias(t.Context(), proj, "example-corp"); err != nil {
				t.Fatalf("delete after one concurrent write: %v, want deleted", err)
			}
			aliasGone(t, inner, proj, "example-corp")

			seedAlias(t, inner, proj, "busy-corp")
			b = &changingAliasBeforeDelete{Backend: inner, n: 1 << 30, t: t}
			err := newEnvOn(t, b, &now).api.DeleteAccountAlias(t.Context(), proj, "busy-corp")
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			storedAlias(t, inner, proj, "busy-corp")
		})
	}
}
