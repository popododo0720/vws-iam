package grpcapi_test

import (
	"context"
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

// seedPlainUser creates user name, with no boundary and one inline
// policy, through the UserService and the store.
func seedPlainUser(t *testing.T, e *env, b store.Backend, name string) iam.User {
	t.Helper()
	e.createUser(t, t.Context(), name)
	u, err := store.Mutate(t.Context(), store.Scoped(b, proj), name, func(u *iam.User) error {
		u.InlinePolicies = map[string]string{"keep": slrInline}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestPutUserPermissionsBoundary: the boundary is set and the user keeps
// its id and inline policies; a second policy replaces it; a repeat on
// another replica succeeds without a write; DeleteUserPermissionsBoundary
// then clears it. On both store backends.
func TestPutUserPermissionsBoundary(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			first := seedBoundaryPolicy(t, e, "First", "")
			second := seedBoundaryPolicy(t, e, "Second", "/team/")
			before := seedPlainUser(t, e, b, "Bounded")

			if err := e.api.PutUserPermissionsBoundary(t.Context(), proj, "bounded", first); err != nil {
				t.Fatal(err)
			}
			got := storedUser(t, b, "Bounded")
			if got.Object.PermissionsBoundary != first {
				t.Fatalf("PermissionsBoundary = %q, want %q", got.Object.PermissionsBoundary, first)
			}
			if got.Object.ID != before.ID || got.Object.InlinePolicies["keep"] != slrInline {
				t.Fatalf("user changed beyond its boundary: %+v", got.Object)
			}
			if got.Object.Generation != before.Generation+1 {
				t.Fatalf("Generation = %d, want %d", got.Object.Generation, before.Generation+1)
			}

			if err := e.api.PutUserPermissionsBoundary(t.Context(), proj, "Bounded", second); err != nil {
				t.Fatal(err)
			}
			replaced := storedUser(t, b, "Bounded")
			if replaced.Object.PermissionsBoundary != second || replaced.Object.Generation != before.Generation+2 {
				t.Fatalf("after replace: boundary %q generation %d; want %q, %d",
					replaced.Object.PermissionsBoundary, replaced.Object.Generation, second, before.Generation+2)
			}

			if err := newEnvOn(t, b, &now).api.PutUserPermissionsBoundary(t.Context(), proj, "Bounded", second); err != nil {
				t.Fatalf("repeat on another replica: %v", err)
			}
			if again := storedUser(t, b, "Bounded"); again.Version != replaced.Version {
				t.Fatalf("repeat wrote the user: version %q, want %q", again.Version, replaced.Version)
			}

			if err := e.api.DeleteUserPermissionsBoundary(t.Context(), proj, "Bounded"); err != nil {
				t.Fatal(err)
			}
			if got := storedUser(t, b, "Bounded"); got.Object.PermissionsBoundary != "" {
				t.Fatalf("after delete: boundary %q, want empty", got.Object.PermissionsBoundary)
			}
		})
	}
}

// TestPutUserPermissionsBoundaryErrors: an unknown user or policy is
// NoSuchEntity, a user being renamed is ConcurrentModification and keeps
// its boundary, a UserName outside the AWS pattern, an ARN outside 20 to
// 2048 characters or a bad project is ValidationError and an ARN that is
// not a policy ARN is InvalidInput. No refused call writes the user.
func TestPutUserPermissionsBoundaryErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	pol := seedBoundaryPolicy(t, e, "Boundary", "/team/")
	seedPlainUser(t, e, b, "plain")
	before := storedUser(t, b, "plain")

	wantAWS(t, e.api.PutUserPermissionsBoundary(ctx, proj, "missing", pol), codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.PutUserPermissionsBoundary(ctx, proj, strings.Repeat("u", 64), pol), codes.NotFound, "NoSuchEntity")
	for _, a := range []string{
		"arn:vws:iam::" + proj + ":policy/team/Nope",                   // no such policy
		"arn:vws:iam::" + proj + ":policy/Boundary",                    // wrong path
		"arn:vws:iam::" + proj + ":policy/other/Boundary",              // wrong path
		"arn:vws:iam::vws:policy/team/Boundary",                        // another account
		"arn:vws:iam::aws:policy/AdministratorAccess",                  // no AWS managed policies
		"arn:vws:iam::" + proj + ":policy/" + strings.Repeat("p", 129), // not a policy name
	} {
		wantAWS(t, e.api.PutUserPermissionsBoundary(ctx, proj, "plain", a), codes.NotFound, "NoSuchEntity")
	}

	renaming := iam.User{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: "moving", ID: iam.NewUniqueID("AIDA"),
		Created: now, RenameState: iam.RenameState{RenameTo: "moved", RenameStarted: now},
	}
	if _, err := store.CreateMarked(ctx, store.Scoped(b, proj), renaming); err != nil {
		t.Fatal(err)
	}
	wantAWS(t, e.api.PutUserPermissionsBoundary(ctx, proj, "moving", pol), codes.Aborted, "ConcurrentModification")
	if got := storedUser(t, b, "moving"); got.Object.PermissionsBoundary != "" {
		t.Fatalf("renaming user boundary = %q, want none", got.Object.PermissionsBoundary)
	}

	for _, n := range []string{"", strings.Repeat("u", 65), "a/b", "a b", "üser"} {
		wantAWS(t, e.api.PutUserPermissionsBoundary(ctx, proj, n, pol), codes.InvalidArgument, "ValidationError")
	}
	for _, a := range []string{"", "arn:vws:iam::p:pol", "arn:vws:iam::" + proj + ":policy/" + strings.Repeat("p", 2049)} {
		wantAWS(t, e.api.PutUserPermissionsBoundary(ctx, proj, "plain", a), codes.InvalidArgument, "ValidationError")
	}
	for _, a := range []string{
		"arn:aws:iam::" + proj + ":policy/team/Boundary",
		"arn:vws:iam::" + proj + ":user/team/Boundary",
		"arn:vws:s3::" + proj + ":policy/team/Boundary",
		"arn:vws:iam:::policy/team/Boundary",
		"not-an-arn-at-all-but-long",
	} {
		wantAWS(t, e.api.PutUserPermissionsBoundary(ctx, proj, "plain", a), codes.InvalidArgument, "InvalidInput")
	}
	err := e.api.PutUserPermissionsBoundary(ctx, "Bad_Project", "plain", pol)
	wantAWS(t, err, codes.InvalidArgument, "ValidationError")

	if got := storedUser(t, b, "plain"); got.Version != before.Version || got.Object.PermissionsBoundary != "" {
		t.Fatalf("a refused call wrote the user: version %q boundary %q", got.Version, got.Object.PermissionsBoundary)
	}
}

// TestPutUserPermissionsBoundaryCanceled: a request whose context is
// already done is Canceled and does not write the user.
func TestPutUserPermissionsBoundaryCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	pol := seedBoundaryPolicy(t, e, "Boundary", "")
	seedPlainUser(t, e, b, "plain")
	before := storedUser(t, b, "plain")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := e.api.PutUserPermissionsBoundary(ctx, proj, "plain", pol)
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
	if got := storedUser(t, b, "plain"); got.Version != before.Version {
		t.Fatalf("canceled request wrote the user: version %q, want %q", got.Version, before.Version)
	}
}

// TestPutUserPermissionsBoundaryConcurrent: requests racing on two
// replicas all succeed and leave the boundary set, the user generation
// bumped once. On both store backends.
func TestPutUserPermissionsBoundaryConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			pol := seedBoundaryPolicy(t, replicas[0], "Boundary", "")
			before := seedPlainUser(t, replicas[0], b, "racer")
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.PutUserPermissionsBoundary(t.Context(), proj, "racer", pol)
				})
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			got := storedUser(t, b, "racer").Object
			if got.PermissionsBoundary != pol || got.Generation != before.Generation+1 {
				t.Fatalf("after race: boundary %q generation %d; want %q, %d",
					got.PermissionsBoundary, got.Generation, pol, before.Generation+1)
			}
		})
	}
}

// TestPutUserPermissionsBoundaryStaleRead: a user changed after it was
// read is read again, so the concurrent change is kept and the boundary
// is still set.
func TestPutUserPermissionsBoundaryStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seed := newEnvOn(t, inner, &now)
			pol := seedBoundaryPolicy(t, seed, "Boundary", "")
			seedPlainUser(t, seed, inner, "stale")
			b := &changingUser{Backend: inner, t: t}
			if err := newEnvOn(t, b, &now).api.PutUserPermissionsBoundary(t.Context(), proj, "stale", pol); err != nil {
				t.Fatal(err)
			}
			got := storedUser(t, inner, "stale").Object
			if got.PermissionsBoundary != pol || got.InlinePolicies["added"] != slrInline {
				t.Fatalf("after stale read: boundary %q inline %v; want %q, added kept",
					got.PermissionsBoundary, got.InlinePolicies, pol)
			}
		})
	}
}
