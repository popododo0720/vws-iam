package grpcapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const boundaryARN = "arn:vws:iam::" + proj + ":policy/Boundary"

// seedBoundedRole creates role name through the RoleService and sets its
// permissions boundary in the store, as PutRolePermissionsBoundary (#100)
// will.
func seedBoundedRole(t *testing.T, e *env, b store.Backend, name string) iam.Role {
	t.Helper()
	spec := &iamv1.RoleSpec{AssumeRolePolicy: slrTrust, InlinePolicies: map[string]string{"keep": slrInline}}
	req := &iamv1.CreateRoleRequest{Parent: parentName, RoleId: name, Role: &iamv1.Role{Spec: spec}}
	if _, err := e.roles.CreateRole(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	r, err := store.Mutate(t.Context(), store.Scoped(b, proj), name, func(r *iam.Role) error {
		r.PermissionsBoundary = boundaryARN
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func storedRole(t *testing.T, b store.Backend, name string) store.Versioned[iam.Role] {
	t.Helper()
	v, err := store.Get[iam.Role](t.Context(), store.Scoped(b, proj), name)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestDeleteRolePermissionsBoundary: the boundary is removed and the role
// keeps its trust and inline policies; every replica sees it; a repeat
// succeeds without a write. On both store backends.
func TestDeleteRolePermissionsBoundary(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			before := seedBoundedRole(t, e, b, "Bounded")

			if err := e.api.DeleteRolePermissionsBoundary(t.Context(), proj, "bounded"); err != nil {
				t.Fatal(err)
			}
			got := storedRole(t, b, "Bounded")
			if got.Object.PermissionsBoundary != "" {
				t.Fatalf("PermissionsBoundary = %q after delete, want empty", got.Object.PermissionsBoundary)
			}
			if got.Object.AssumeRolePolicy != before.AssumeRolePolicy || got.Object.InlinePolicies["keep"] != slrInline {
				t.Fatalf("role changed beyond its boundary: %+v", got.Object)
			}
			if got.Object.Generation != before.Generation+1 {
				t.Fatalf("Generation = %d, want %d", got.Object.Generation, before.Generation+1)
			}
			if err := newEnvOn(t, b, &now).api.DeleteRolePermissionsBoundary(t.Context(), proj, "Bounded"); err != nil {
				t.Fatalf("repeat on another replica: %v", err)
			}
			if again := storedRole(t, b, "Bounded"); again.Version != got.Version {
				t.Fatalf("repeat wrote the role: version %q, want %q", again.Version, got.Version)
			}
		})
	}
}

// TestDeleteRolePermissionsBoundaryErrors: an unknown role is
// NoSuchEntity, a service-linked role is UnmodifiableEntity and keeps its
// boundary, and a RoleName outside the AWS pattern or a bad project is
// ValidationError before any store access.
func TestDeleteRolePermissionsBoundaryErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()

	wantAWS(t, e.api.DeleteRolePermissionsBoundary(ctx, proj, "missing"), codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.DeleteRolePermissionsBoundary(ctx, proj, strings.Repeat("r", 64)), codes.NotFound, "NoSuchEntity")

	slr := seedLinkedRole(t, b, "linked")
	if _, err := store.Mutate(ctx, store.Scoped(b, proj), slr.Name, func(r *iam.Role) error {
		r.PermissionsBoundary = boundaryARN
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wantAWS(t, e.api.DeleteRolePermissionsBoundary(ctx, proj, slr.Name), codes.FailedPrecondition, "UnmodifiableEntity")
	if got := storedRole(t, b, slr.Name); got.Object.PermissionsBoundary != boundaryARN {
		t.Fatalf("service-linked boundary = %q, want %q kept", got.Object.PermissionsBoundary, boundaryARN)
	}

	for _, n := range []string{"", strings.Repeat("r", 65), "a/b", "a b", "rôle"} {
		wantAWS(t, e.api.DeleteRolePermissionsBoundary(ctx, proj, n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.DeleteRolePermissionsBoundary(ctx, "Bad_Project", "r"), codes.InvalidArgument, "ValidationError")
}

// TestDeleteRolePermissionsBoundaryConcurrent: requests racing on two
// replicas all succeed and leave the role without a boundary, its
// generation bumped once. On both store backends.
func TestDeleteRolePermissionsBoundaryConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			before := seedBoundedRole(t, replicas[0], b, "racer")
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.DeleteRolePermissionsBoundary(t.Context(), proj, "racer")
				})
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			got := storedRole(t, b, "racer").Object
			if got.PermissionsBoundary != "" || got.Generation != before.Generation+1 {
				t.Fatalf("after race: boundary %q generation %d; want empty, %d",
					got.PermissionsBoundary, got.Generation, before.Generation+1)
			}
		})
	}
}

// changing sets a new boundary on the role between the read and the
// write of the first DeleteRolePermissionsBoundary.
type changing struct {
	store.Backend
	once sync.Once
	t    *testing.T
}

func (c *changing) Update(ctx context.Context, k iam.Kind, key string, v []byte, version string) (string, error) {
	if k == iam.KindRole {
		c.once.Do(func() {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(r *iam.Role) error {
				r.Description = "changed"
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		})
	}
	return c.Backend.Update(ctx, k, key, v, version)
}

// TestDeleteRolePermissionsBoundaryStaleRead: a role changed after it was
// read is read again, so the concurrent change is kept and the boundary
// is still removed.
func TestDeleteRolePermissionsBoundaryStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedBoundedRole(t, newEnvOn(t, inner, &now), inner, "stale")
			b := &changing{Backend: inner, t: t}
			if err := newEnvOn(t, b, &now).api.DeleteRolePermissionsBoundary(t.Context(), proj, "stale"); err != nil {
				t.Fatal(err)
			}
			got := storedRole(t, inner, "stale").Object
			if got.PermissionsBoundary != "" || got.Description != "changed" {
				t.Fatalf("after stale read: boundary %q description %q; want empty, changed",
					got.PermissionsBoundary, got.Description)
			}
		})
	}
}
