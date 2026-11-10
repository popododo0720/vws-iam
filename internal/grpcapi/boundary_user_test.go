package grpcapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// seedBoundedUser creates user name through the UserService and sets its
// permissions boundary and an inline policy in the store, as
// PutUserPermissionsBoundary (#98) and PutUserPolicy will.
func seedBoundedUser(t *testing.T, e *env, b store.Backend, name string) iam.User {
	t.Helper()
	e.createUser(t, t.Context(), name)
	u, err := store.Mutate(t.Context(), store.Scoped(b, proj), name, func(u *iam.User) error {
		u.PermissionsBoundary = boundaryARN
		u.InlinePolicies = map[string]string{"keep": slrInline}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func storedUser(t *testing.T, b store.Backend, name string) store.Versioned[iam.User] {
	t.Helper()
	v, err := store.Get[iam.User](t.Context(), store.Scoped(b, proj), name)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestDeleteUserPermissionsBoundary: the boundary is removed and the user
// keeps its id and inline policies; every replica sees it; a repeat
// succeeds without a write. On both store backends.
func TestDeleteUserPermissionsBoundary(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			before := seedBoundedUser(t, e, b, "Bounded")

			if err := e.api.DeleteUserBoundary(t.Context(), proj, "bounded"); err != nil {
				t.Fatal(err)
			}
			got := storedUser(t, b, "Bounded")
			if got.Object.PermissionsBoundary != "" {
				t.Fatalf("PermissionsBoundary = %q after delete, want empty", got.Object.PermissionsBoundary)
			}
			if got.Object.ID != before.ID || got.Object.InlinePolicies["keep"] != slrInline {
				t.Fatalf("user changed beyond its boundary: %+v", got.Object)
			}
			if got.Object.Generation != before.Generation+1 {
				t.Fatalf("Generation = %d, want %d", got.Object.Generation, before.Generation+1)
			}
			if err := newEnvOn(t, b, &now).api.DeleteUserBoundary(t.Context(), proj, "Bounded"); err != nil {
				t.Fatalf("repeat on another replica: %v", err)
			}
			if again := storedUser(t, b, "Bounded"); again.Version != got.Version {
				t.Fatalf("repeat wrote the user: version %q, want %q", again.Version, got.Version)
			}
		})
	}
}

// TestDeleteUserPermissionsBoundaryNoBoundary: a user that never had a
// boundary succeeds and is not written.
func TestDeleteUserPermissionsBoundaryNoBoundary(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	e.createUser(t, t.Context(), "plain")
	before := storedUser(t, b, "plain")
	if err := e.api.DeleteUserBoundary(t.Context(), proj, "plain"); err != nil {
		t.Fatal(err)
	}
	if got := storedUser(t, b, "plain"); got.Version != before.Version {
		t.Fatalf("no-boundary delete wrote the user: version %q, want %q", got.Version, before.Version)
	}
}

// TestDeleteUserPermissionsBoundaryErrors: an unknown user is
// NoSuchEntity, a user being renamed is ConcurrentModification and keeps
// its boundary, and a UserName outside the AWS pattern or a bad project
// is ValidationError before any store access.
func TestDeleteUserPermissionsBoundaryErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()

	wantAWS(t, e.api.DeleteUserBoundary(ctx, proj, "missing"), codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.DeleteUserBoundary(ctx, proj, strings.Repeat("u", 64)), codes.NotFound, "NoSuchEntity")

	renaming := iam.User{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: "moving", ID: iam.NewUniqueID("AIDA"),
		Created: now, PermissionsBoundary: boundaryARN,
		RenameState: iam.RenameState{RenameTo: "moved", RenameStarted: now},
	}
	if _, err := store.CreateMarked(ctx, store.Scoped(b, proj), renaming); err != nil {
		t.Fatal(err)
	}
	wantAWS(t, e.api.DeleteUserBoundary(ctx, proj, "moving"), codes.Aborted, "ConcurrentModification")
	if got := storedUser(t, b, "moving"); got.Object.PermissionsBoundary != boundaryARN {
		t.Fatalf("renaming user boundary = %q, want %q kept", got.Object.PermissionsBoundary, boundaryARN)
	}

	for _, n := range []string{"", strings.Repeat("u", 65), "a/b", "a b", "üser"} {
		wantAWS(t, e.api.DeleteUserBoundary(ctx, proj, n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.DeleteUserBoundary(ctx, "Bad_Project", "u"), codes.InvalidArgument, "ValidationError")
}

// TestDeleteUserPermissionsBoundaryConcurrent: requests racing on two
// replicas all succeed and leave the user without a boundary, its
// generation bumped once. On both store backends.
func TestDeleteUserPermissionsBoundaryConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			before := seedBoundedUser(t, replicas[0], b, "racer")
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.DeleteUserBoundary(t.Context(), proj, "racer")
				})
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			got := storedUser(t, b, "racer").Object
			if got.PermissionsBoundary != "" || got.Generation != before.Generation+1 {
				t.Fatalf("after race: boundary %q generation %d; want empty, %d",
					got.PermissionsBoundary, got.Generation, before.Generation+1)
			}
		})
	}
}

// changingUser adds an inline policy to the user between the read and
// the write of the first DeleteUserPermissionsBoundary.
type changingUser struct {
	store.Backend
	once sync.Once
	t    *testing.T
}

func (c *changingUser) Update(ctx context.Context, k iam.Kind, key string, v []byte, version string) (string, error) {
	if k == iam.KindUser {
		c.once.Do(func() {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(u *iam.User) error {
				u.InlinePolicies["added"] = slrInline
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		})
	}
	return c.Backend.Update(ctx, k, key, v, version)
}

// TestDeleteUserPermissionsBoundaryStaleRead: a user changed after it was
// read is read again, so the concurrent change is kept and the boundary
// is still removed.
func TestDeleteUserPermissionsBoundaryStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedBoundedUser(t, newEnvOn(t, inner, &now), inner, "stale")
			b := &changingUser{Backend: inner, t: t}
			if err := newEnvOn(t, b, &now).api.DeleteUserBoundary(t.Context(), proj, "stale"); err != nil {
				t.Fatal(err)
			}
			got := storedUser(t, inner, "stale").Object
			if got.PermissionsBoundary != "" || got.InlinePolicies["added"] != slrInline {
				t.Fatalf("after stale read: boundary %q inline %v; want empty, added kept",
					got.PermissionsBoundary, got.InlinePolicies)
			}
		})
	}
}
