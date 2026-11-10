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

// TestAddRoleToInstanceProfile: the role joins the profile under its
// stored name, names compare case-insensitively, and every replica sees
// it; a repeat is LimitExceeded without a write, as in AWS. On both store
// backends.
func TestAddRoleToInstanceProfile(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			before := seedInstanceProfile(t, b, "Webserver")

			if err := e.api.AddProfileRole(t.Context(), proj, "webserver", "s3access"); err != nil {
				t.Fatal(err)
			}
			got := storedProfile(t, b, "Webserver")
			if len(got.Object.Roles) != 1 || got.Object.Roles[0] != "S3Access" {
				t.Fatalf("Roles = %q after add, want [S3Access]", got.Object.Roles)
			}
			if got.Object.Generation != before.Generation+1 || got.Object.ID != before.ID || got.Object.Path != before.Path {
				t.Fatalf("profile changed beyond its roles: %+v, was %+v", got.Object, before)
			}
			if !got.Object.Updated.Equal(now) {
				t.Fatalf("Updated = %v, want %v", got.Object.Updated, now)
			}
			err := newEnvOn(t, b, &now).api.AddProfileRole(t.Context(), proj, "Webserver", "S3Access")
			wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
			if again := storedProfile(t, b, "Webserver"); again.Version != got.Version {
				t.Fatalf("repeat wrote the profile: version %q, want %q", again.Version, got.Version)
			}
		})
	}
}

// TestAddRoleToInstanceProfileErrors: an unknown profile or role is
// NoSuchEntity; a profile holding another role is LimitExceeded; a
// service-linked role is UnmodifiableEntity; a bad name or project is
// ValidationError before any store access. None writes a profile.
func TestAddRoleToInstanceProfileErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedRole(t, e, "inside")
	seedRole(t, e, "outside")
	seedInstanceProfile(t, b, "full", "inside")
	seedInstanceProfile(t, b, "empty")
	full, empty := storedProfile(t, b, "full"), storedProfile(t, b, "empty")

	wantAWS(t, e.api.AddProfileRole(ctx, proj, "missing", "outside"), codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.AddProfileRole(ctx, proj, strings.Repeat("p", 128), "outside"),
		codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.AddProfileRole(ctx, proj, "empty", "missing"), codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.AddProfileRole(ctx, proj, "full", "outside"), codes.ResourceExhausted, "LimitExceeded")
	wantAWS(t, e.api.AddProfileRole(ctx, proj, "full", "INSIDE"), codes.ResourceExhausted, "LimitExceeded")

	slr := seedLinkedRole(t, b, "linked")
	wantAWS(t, e.api.AddProfileRole(ctx, proj, "empty", slr.Name),
		codes.FailedPrecondition, "UnmodifiableEntity")

	for _, n := range []string{"", strings.Repeat("p", 129), "a/b", "a b", "prôfile"} {
		wantAWS(t, e.api.AddProfileRole(ctx, proj, n, "outside"), codes.InvalidArgument, "ValidationError")
	}
	for _, n := range []string{"", strings.Repeat("r", 65), "a/b", "a b", "rôle"} {
		wantAWS(t, e.api.AddProfileRole(ctx, proj, "empty", n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.AddProfileRole(ctx, "Bad_Project", "empty", "outside"),
		codes.InvalidArgument, "ValidationError")
	if got := storedProfile(t, b, "full"); got.Version != full.Version {
		t.Fatalf("a refused request wrote profile full: version %q, want %q", got.Version, full.Version)
	}
	if got := storedProfile(t, b, "empty"); got.Version != empty.Version {
		t.Fatalf("a refused request wrote profile empty: version %q, want %q", got.Version, empty.Version)
	}
}

// TestAddRoleToInstanceProfileCanceled: a request whose context is
// already done is Canceled and does not write the profile.
func TestAddRoleToInstanceProfileCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "r")
	seedInstanceProfile(t, b, "web")
	before := storedProfile(t, b, "web")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := e.api.AddProfileRole(ctx, proj, "web", "r")
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
	if got := storedProfile(t, b, "web"); got.Version != before.Version {
		t.Fatalf("canceled request wrote the profile: version %q, want %q", got.Version, before.Version)
	}
}

// TestAddRoleToInstanceProfileConcurrent: of requests racing on two
// replicas to add one of two roles exactly one succeeds and the rest are
// LimitExceeded; the profile ends with one role, its generation bumped
// once. On both store backends.
func TestAddRoleToInstanceProfileConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			roles := []string{"first", "second"}
			for _, r := range roles {
				seedRole(t, replicas[0], r)
			}
			before := seedInstanceProfile(t, b, "web")
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.AddProfileRole(t.Context(), proj, "web", roles[i/2%2])
				})
			}
			wg.Wait()
			ok := 0
			for _, err := range errs {
				if err == nil {
					ok++
					continue
				}
				wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
			}
			if ok != 1 {
				t.Fatalf("%d requests succeeded, want 1", ok)
			}
			got := storedProfile(t, b, "web").Object
			if len(got.Roles) != 1 || got.Generation != before.Generation+1 {
				t.Fatalf("after race: roles %q generation %d; want one, %d", got.Roles, got.Generation, before.Generation+1)
			}
		})
	}
}

// changingBeforeAdd runs change once, before the first conditional write
// of an instance profile, as a concurrent request between the read and
// the write of AddRoleToInstanceProfile would.
type changingBeforeAdd struct {
	store.Backend
	once   sync.Once
	change func(ctx context.Context, b store.Backend) error
	t      *testing.T
}

func (c *changingBeforeAdd) UpdateIf(
	ctx context.Context, k iam.Kind, key string, v []byte, version string, pre store.Pre,
) (string, error) {
	if k == iam.KindInstanceProfile {
		c.once.Do(func() {
			if err := c.change(ctx, store.Scoped(c.Backend, proj)); err != nil {
				c.t.Error(err)
			}
		})
	}
	return c.Backend.UpdateIf(ctx, k, key, v, version, pre)
}

// TestAddRoleToInstanceProfileStaleRead: a profile changed after it was
// read is read again, so the concurrent change is kept and the role is
// still added. On both store backends.
func TestAddRoleToInstanceProfileStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedRole(t, newEnvOn(t, inner, &now), "stale")
			seedInstanceProfile(t, inner, "web")
			b := &changingBeforeAdd{Backend: inner, t: t, change: func(ctx context.Context, b store.Backend) error {
				_, err := store.Mutate(ctx, b, "web", func(p *iam.InstanceProfile) error {
					p.Path = "/changed/"
					return nil
				})
				return err
			}}
			if err := newEnvOn(t, b, &now).api.AddProfileRole(t.Context(), proj, "web", "stale"); err != nil {
				t.Fatal(err)
			}
			got := storedProfile(t, inner, "web").Object
			if len(got.Roles) != 1 || got.Roles[0] != "stale" || got.Path != "/changed/" {
				t.Fatalf("after stale read: roles %q path %q; want [stale], /changed/", got.Roles, got.Path)
			}
		})
	}
}

// TestAddRoleToInstanceProfileRoleDeleted: a role deleted between the
// read and the write is never added: the request is NoSuchEntity and the
// profile stays empty. On both store backends.
func TestAddRoleToInstanceProfileRoleDeleted(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedRole(t, newEnvOn(t, inner, &now), "doomed")
			seedInstanceProfile(t, inner, "web")
			b := &changingBeforeAdd{Backend: inner, t: t, change: func(ctx context.Context, b store.Backend) error {
				return b.Delete(ctx, iam.KindRole, "doomed", "")
			}}
			err := newEnvOn(t, b, &now).api.AddProfileRole(t.Context(), proj, "web", "doomed")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if got := storedProfile(t, inner, "web").Object; len(got.Roles) != 0 {
				t.Fatalf("Roles = %q after the role was deleted, want none", got.Roles)
			}
		})
	}
}
