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

const boundaryDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

// seedBoundaryPolicy creates managed policy n at path through the
// PolicyService and returns its ARN.
func seedBoundaryPolicy(t *testing.T, e *env, n, path string) string {
	t.Helper()
	pol := &iamv1.Policy{Spec: &iamv1.PolicySpec{Path: path, Document: boundaryDoc}}
	req := &iamv1.CreatePolicyRequest{Parent: parentName, PolicyId: n, Policy: pol}
	op, err := e.policies.CreatePolicy(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	return unpack(t, op, &iamv1.Policy{}).GetStatus().GetArn()
}

// seedPlainRole creates role name, with no boundary, through the
// RoleService.
func seedPlainRole(t *testing.T, e *env, name string) {
	t.Helper()
	spec := &iamv1.RoleSpec{AssumeRolePolicy: slrTrust, InlinePolicies: map[string]string{"keep": slrInline}}
	req := &iamv1.CreateRoleRequest{Parent: parentName, RoleId: name, Role: &iamv1.Role{Spec: spec}}
	if _, err := e.roles.CreateRole(t.Context(), req); err != nil {
		t.Fatal(err)
	}
}

// TestPutRolePermissionsBoundary: the boundary is set and the role keeps
// its trust and inline policies; a second policy replaces it; a repeat
// on another replica succeeds without a write. On both store backends.
func TestPutRolePermissionsBoundary(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			first := seedBoundaryPolicy(t, e, "First", "")
			second := seedBoundaryPolicy(t, e, "Second", "/team/")
			seedPlainRole(t, e, "Bounded")
			before := storedRole(t, b, "Bounded").Object

			if err := e.api.PutRolePermissionsBoundary(t.Context(), proj, "bounded", first); err != nil {
				t.Fatal(err)
			}
			got := storedRole(t, b, "Bounded")
			if got.Object.PermissionsBoundary != first {
				t.Fatalf("PermissionsBoundary = %q, want %q", got.Object.PermissionsBoundary, first)
			}
			if got.Object.AssumeRolePolicy != before.AssumeRolePolicy || got.Object.InlinePolicies["keep"] != slrInline {
				t.Fatalf("role changed beyond its boundary: %+v", got.Object)
			}
			if got.Object.Generation != before.Generation+1 {
				t.Fatalf("Generation = %d, want %d", got.Object.Generation, before.Generation+1)
			}

			if err := e.api.PutRolePermissionsBoundary(t.Context(), proj, "Bounded", second); err != nil {
				t.Fatal(err)
			}
			replaced := storedRole(t, b, "Bounded")
			if replaced.Object.PermissionsBoundary != second || replaced.Object.Generation != before.Generation+2 {
				t.Fatalf("after replace: boundary %q generation %d; want %q, %d",
					replaced.Object.PermissionsBoundary, replaced.Object.Generation, second, before.Generation+2)
			}

			if err := newEnvOn(t, b, &now).api.PutRolePermissionsBoundary(t.Context(), proj, "Bounded", second); err != nil {
				t.Fatalf("repeat on another replica: %v", err)
			}
			if again := storedRole(t, b, "Bounded"); again.Version != replaced.Version {
				t.Fatalf("repeat wrote the role: version %q, want %q", again.Version, replaced.Version)
			}
		})
	}
}

// TestPutRolePermissionsBoundaryErrors: an unknown role or policy is
// NoSuchEntity, a service-linked role is UnmodifiableEntity, a RoleName
// outside the AWS pattern, an ARN outside 20 to 2048 characters or a bad
// project is ValidationError and an ARN that is not a policy ARN is
// InvalidInput. No refused call writes the role.
func TestPutRolePermissionsBoundaryErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	pol := seedBoundaryPolicy(t, e, "Boundary", "/team/")
	seedPlainRole(t, e, "plain")
	before := storedRole(t, b, "plain")

	wantAWS(t, e.api.PutRolePermissionsBoundary(ctx, proj, "missing", pol), codes.NotFound, "NoSuchEntity")
	for _, a := range []string{
		"arn:vws:iam::" + proj + ":policy/team/Nope",                   // no such policy
		"arn:vws:iam::" + proj + ":policy/Boundary",                    // wrong path
		"arn:vws:iam::" + proj + ":policy/other/Boundary",              // wrong path
		"arn:vws:iam::vws:policy/team/Boundary",                        // another account
		"arn:vws:iam::aws:policy/AdministratorAccess",                  // no AWS managed policies
		"arn:vws:iam::" + proj + ":policy/" + strings.Repeat("p", 129), // not a policy name
	} {
		wantAWS(t, e.api.PutRolePermissionsBoundary(ctx, proj, "plain", a), codes.NotFound, "NoSuchEntity")
	}

	slr := seedLinkedRole(t, b, "linked")
	wantAWS(t, e.api.PutRolePermissionsBoundary(ctx, proj, slr.Name, pol), codes.FailedPrecondition, "UnmodifiableEntity")
	if got := storedRole(t, b, slr.Name); got.Object.PermissionsBoundary != "" {
		t.Fatalf("service-linked boundary = %q, want none", got.Object.PermissionsBoundary)
	}

	for _, n := range []string{"", strings.Repeat("r", 65), "a/b", "a b", "rôle"} {
		wantAWS(t, e.api.PutRolePermissionsBoundary(ctx, proj, n, pol), codes.InvalidArgument, "ValidationError")
	}
	for _, a := range []string{"", "arn:vws:iam::p:pol", "arn:vws:iam::" + proj + ":policy/" + strings.Repeat("p", 2049)} {
		wantAWS(t, e.api.PutRolePermissionsBoundary(ctx, proj, "plain", a), codes.InvalidArgument, "ValidationError")
	}
	for _, a := range []string{
		"arn:aws:iam::" + proj + ":policy/team/Boundary",
		"arn:vws:iam::" + proj + ":role/team/Boundary",
		"arn:vws:s3::" + proj + ":policy/team/Boundary",
		"arn:vws:iam:::policy/team/Boundary",
		"not-an-arn-at-all-but-long",
	} {
		wantAWS(t, e.api.PutRolePermissionsBoundary(ctx, proj, "plain", a), codes.InvalidArgument, "InvalidInput")
	}
	err := e.api.PutRolePermissionsBoundary(ctx, "Bad_Project", "plain", pol)
	wantAWS(t, err, codes.InvalidArgument, "ValidationError")

	if got := storedRole(t, b, "plain"); got.Version != before.Version || got.Object.PermissionsBoundary != "" {
		t.Fatalf("a refused call wrote the role: version %q boundary %q", got.Version, got.Object.PermissionsBoundary)
	}
}

// TestPutRolePermissionsBoundaryConcurrent: requests racing on two
// replicas all succeed and leave the boundary set, the role generation
// bumped once. On both store backends.
func TestPutRolePermissionsBoundaryConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			pol := seedBoundaryPolicy(t, replicas[0], "Boundary", "")
			seedPlainRole(t, replicas[0], "racer")
			before := storedRole(t, b, "racer").Object
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.PutRolePermissionsBoundary(t.Context(), proj, "racer", pol)
				})
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			got := storedRole(t, b, "racer").Object
			if got.PermissionsBoundary != pol || got.Generation != before.Generation+1 {
				t.Fatalf("after race: boundary %q generation %d; want %q, %d",
					got.PermissionsBoundary, got.Generation, pol, before.Generation+1)
			}
		})
	}
}

// describing changes the role description between the read and the
// write of the first PutRolePermissionsBoundary.
type describing struct {
	store.Backend
	once sync.Once
	t    *testing.T
}

func (c *describing) Update(ctx context.Context, k iam.Kind, key string, v []byte, version string) (string, error) {
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

// TestPutRolePermissionsBoundaryStaleRead: a role changed after it was
// read is read again, so the concurrent change is kept and the boundary
// is still set.
func TestPutRolePermissionsBoundaryStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seed := newEnvOn(t, inner, &now)
			pol := seedBoundaryPolicy(t, seed, "Boundary", "")
			seedPlainRole(t, seed, "stale")
			b := &describing{Backend: inner, t: t}
			if err := newEnvOn(t, b, &now).api.PutRolePermissionsBoundary(t.Context(), proj, "stale", pol); err != nil {
				t.Fatal(err)
			}
			got := storedRole(t, inner, "stale").Object
			if got.PermissionsBoundary != pol || got.Description != "changed" {
				t.Fatalf("after stale read: boundary %q description %q; want %q, changed",
					got.PermissionsBoundary, got.Description, pol)
			}
		})
	}
}
