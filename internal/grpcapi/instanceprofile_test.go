package grpcapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// seedRole creates role name through the RoleService.
func seedRole(t *testing.T, e *env, name string) {
	t.Helper()
	spec := &iamv1.RoleSpec{AssumeRolePolicy: slrTrust}
	req := &iamv1.CreateRoleRequest{Parent: parentName, RoleId: name, Role: &iamv1.Role{Spec: spec}}
	if _, err := e.roles.CreateRole(t.Context(), req); err != nil {
		t.Fatal(err)
	}
}

// seedInstanceProfile stores instance profile name with roles in proj, as
// CreateInstanceProfile (#91) will.
func seedInstanceProfile(t *testing.T, b store.Backend, name string, roles ...string) iam.InstanceProfile {
	t.Helper()
	p := iam.InstanceProfile{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: name, Path: "/app/",
		ID: iam.NewUniqueID("AIPA"), Created: time.Now().UTC(), Roles: roles,
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, proj), p); err != nil {
		t.Fatal(err)
	}
	return p
}

func storedProfile(t *testing.T, b store.Backend, name string) store.Versioned[iam.InstanceProfile] {
	t.Helper()
	v, err := store.Get[iam.InstanceProfile](t.Context(), store.Scoped(b, proj), name)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestRemoveRoleFromInstanceProfile: the role leaves the profile, names
// compare case-insensitively, the profile and role stay, and every
// replica sees it; a repeat is NoSuchEntity without a write, as in AWS.
// On both store backends.
func TestRemoveRoleFromInstanceProfile(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			before := seedInstanceProfile(t, b, "Webserver", "S3Access")

			if err := e.api.RemoveRoleFromInstanceProfile(t.Context(), proj, "webserver", "s3access"); err != nil {
				t.Fatal(err)
			}
			got := storedProfile(t, b, "Webserver")
			if len(got.Object.Roles) != 0 {
				t.Fatalf("Roles = %q after remove, want none", got.Object.Roles)
			}
			if got.Object.Generation != before.Generation+1 || got.Object.ID != before.ID || got.Object.Path != before.Path {
				t.Fatalf("profile changed beyond its roles: %+v, was %+v", got.Object, before)
			}
			if !got.Object.Updated.Equal(now) {
				t.Fatalf("Updated = %v, want %v", got.Object.Updated, now)
			}
			if _, err := store.Get[iam.Role](t.Context(), store.Scoped(b, proj), "S3Access"); err != nil {
				t.Fatalf("role after remove: %v", err)
			}
			err := newEnvOn(t, b, &now).api.RemoveRoleFromInstanceProfile(t.Context(), proj, "Webserver", "S3Access")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if again := storedProfile(t, b, "Webserver"); again.Version != got.Version {
				t.Fatalf("repeat wrote the profile: version %q, want %q", again.Version, got.Version)
			}
		})
	}
}

// TestRemoveRoleFromInstanceProfileErrors: an unknown profile, an unknown
// role, and a role not in the profile are NoSuchEntity; a service-linked
// role is UnmodifiableEntity and stays; a bad name or project is
// ValidationError before any store access. None writes the profile.
func TestRemoveRoleFromInstanceProfileErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedRole(t, e, "inside")
	seedRole(t, e, "outside")
	seedInstanceProfile(t, b, "web", "inside")
	before := storedProfile(t, b, "web")

	wantAWS(t, e.api.RemoveRoleFromInstanceProfile(ctx, proj, "missing", "inside"), codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.RemoveRoleFromInstanceProfile(ctx, proj, strings.Repeat("p", 128), "inside"),
		codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.RemoveRoleFromInstanceProfile(ctx, proj, "web", "missing"), codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.RemoveRoleFromInstanceProfile(ctx, proj, "web", "outside"), codes.NotFound, "NoSuchEntity")

	slr := seedLinkedRole(t, b, "linked")
	seedInstanceProfile(t, b, "svc", slr.Name)
	wantAWS(t, e.api.RemoveRoleFromInstanceProfile(ctx, proj, "svc", slr.Name),
		codes.FailedPrecondition, "UnmodifiableEntity")
	if got := storedProfile(t, b, "svc").Object.Roles; len(got) != 1 || got[0] != slr.Name {
		t.Fatalf("service-linked profile roles = %q, want [%q] kept", got, slr.Name)
	}

	for _, n := range []string{"", strings.Repeat("p", 129), "a/b", "a b", "prôfile"} {
		wantAWS(t, e.api.RemoveRoleFromInstanceProfile(ctx, proj, n, "inside"), codes.InvalidArgument, "ValidationError")
	}
	for _, n := range []string{"", strings.Repeat("r", 65), "a/b", "a b", "rôle"} {
		wantAWS(t, e.api.RemoveRoleFromInstanceProfile(ctx, proj, "web", n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.RemoveRoleFromInstanceProfile(ctx, "Bad_Project", "web", "inside"),
		codes.InvalidArgument, "ValidationError")
	if got := storedProfile(t, b, "web"); got.Version != before.Version {
		t.Fatalf("a refused request wrote the profile: version %q, want %q", got.Version, before.Version)
	}
}

// TestRemoveRoleFromInstanceProfileDeletedRole: a profile that still
// names a deleted role can be emptied.
func TestRemoveRoleFromInstanceProfileDeletedRole(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedInstanceProfile(t, b, "web", "Gone")
	if err := e.api.RemoveRoleFromInstanceProfile(t.Context(), proj, "web", "gone"); err != nil {
		t.Fatal(err)
	}
	if got := storedProfile(t, b, "web").Object.Roles; len(got) != 0 {
		t.Fatalf("Roles = %q, want none", got)
	}
}

// TestRemoveRoleFromInstanceProfileCanceled: a request whose context is
// already done is Canceled and does not write the profile.
func TestRemoveRoleFromInstanceProfileCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "r")
	seedInstanceProfile(t, b, "web", "r")
	before := storedProfile(t, b, "web")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := e.api.RemoveRoleFromInstanceProfile(ctx, proj, "web", "r")
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
	if got := storedProfile(t, b, "web"); got.Version != before.Version {
		t.Fatalf("canceled request wrote the profile: version %q, want %q", got.Version, before.Version)
	}
}

// TestRemoveRoleFromInstanceProfileConcurrent: of requests racing on two
// replicas exactly one succeeds and the rest are NoSuchEntity; the
// profile ends without the role, its generation bumped once. On both
// store backends.
func TestRemoveRoleFromInstanceProfileConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			seedRole(t, replicas[0], "racer")
			before := seedInstanceProfile(t, b, "web", "racer")
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.RemoveRoleFromInstanceProfile(t.Context(), proj, "web", "racer")
				})
			}
			wg.Wait()
			ok := 0
			for _, err := range errs {
				if err == nil {
					ok++
					continue
				}
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
			if ok != 1 {
				t.Fatalf("%d requests succeeded, want 1", ok)
			}
			got := storedProfile(t, b, "web").Object
			if len(got.Roles) != 0 || got.Generation != before.Generation+1 {
				t.Fatalf("after race: roles %q generation %d; want none, %d", got.Roles, got.Generation, before.Generation+1)
			}
		})
	}
}

// changingProfile changes the profile's path between the read and the
// write of the first RemoveRoleFromInstanceProfile.
type changingProfile struct {
	store.Backend
	once sync.Once
	t    *testing.T
}

func (c *changingProfile) Update(
	ctx context.Context, k iam.Kind, key string, v []byte, version string,
) (string, error) {
	if k == iam.KindInstanceProfile {
		c.once.Do(func() {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(p *iam.InstanceProfile) error {
				p.Path = "/changed/"
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		})
	}
	return c.Backend.Update(ctx, k, key, v, version)
}

// TestRemoveRoleFromInstanceProfileStaleRead: a profile changed after it
// was read is read again, so the concurrent change is kept and the role
// is still removed. On both store backends.
func TestRemoveRoleFromInstanceProfileStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedRole(t, newEnvOn(t, inner, &now), "stale")
			seedInstanceProfile(t, inner, "web", "stale")
			b := &changingProfile{Backend: inner, t: t}
			if err := newEnvOn(t, b, &now).api.RemoveRoleFromInstanceProfile(t.Context(), proj, "web", "stale"); err != nil {
				t.Fatal(err)
			}
			got := storedProfile(t, inner, "web").Object
			if len(got.Roles) != 0 || got.Path != "/changed/" {
				t.Fatalf("after stale read: roles %q path %q; want none, /changed/", got.Roles, got.Path)
			}
		})
	}
}
