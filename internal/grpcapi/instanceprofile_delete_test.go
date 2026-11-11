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

// profileGone fails unless instance profile name is absent from proj.
func profileGone(t *testing.T, b store.Backend, name string) {
	t.Helper()
	_, err := store.Get[iam.InstanceProfile](t.Context(), store.Scoped(b, proj), name)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("profile %s after delete: %v, want not found", name, err)
	}
}

// TestDeleteInstanceProfile: a profile without a role is deleted for any
// case of its name and a repeat from another replica is NoSuchEntity; a
// profile that holds a role is DeleteConflict and stays until the role is
// removed. On both store backends.
func TestDeleteInstanceProfile(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			seedInstanceProfile(t, b, "Webserver")
			if err := e.api.DeleteProfile(ctx, proj, "WEBSERVER"); err != nil {
				t.Fatal(err)
			}
			profileGone(t, b, "Webserver")
			wantAWS(t, other.api.DeleteProfile(ctx, proj, "Webserver"), codes.NotFound, "NoSuchEntity")

			seedRole(t, e, "S3Access")
			seedInstanceProfile(t, b, "app", "S3Access")
			before := storedProfile(t, b, "app")
			err := other.api.DeleteProfile(ctx, proj, "app")
			wantAWS(t, err, codes.FailedPrecondition, "DeleteConflict")
			if !strings.Contains(err.Error(), "must remove roles from instance profile first") {
				t.Fatalf("DeleteConflict message %q, want the AWS wording", err)
			}
			if got := storedProfile(t, b, "app"); got.Version != before.Version {
				t.Fatalf("a refused delete wrote the profile: version %q, want %q", got.Version, before.Version)
			}
			if err := e.api.RemoveProfileRole(ctx, proj, "app", "s3access"); err != nil {
				t.Fatal(err)
			}
			if err := other.api.DeleteProfile(ctx, proj, "app"); err != nil {
				t.Fatal(err)
			}
			profileGone(t, b, "app")
		})
	}
}

// TestDeleteInstanceProfileDeletedRole: the stale name of a role deleted
// while in the profile (#234) holds no role, so the profile is deleted.
func TestDeleteInstanceProfileDeletedRole(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedInstanceProfile(t, b, "web", "Gone")
	if err := e.api.DeleteProfile(t.Context(), proj, "web"); err != nil {
		t.Fatal(err)
	}
	profileGone(t, b, "web")
}

// failingDelete fails every Delete of kind k with err.
type failingDelete struct {
	store.Backend
	k   iam.Kind
	err error
}

func (f failingDelete) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if k == f.k {
		return f.err
	}
	return f.Backend.Delete(ctx, k, key, version)
}

// TestDeleteInstanceProfileErrors: a bad project or InstanceProfileName
// is ValidationError before any store access, the AWS name bounds are
// accepted, an unknown profile is NoSuchEntity, and a store failure on
// the profile, a role or the delete is InternalFailure and keeps the
// profile.
func TestDeleteInstanceProfileErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedInstanceProfile(t, b, "web")
	for _, n := range []string{"", "a b", "a/b", "é", strings.Repeat("p", iam.MaxInstanceProfileNameLen+1)} {
		wantAWS(t, e.api.DeleteProfile(ctx, proj, n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.DeleteProfile(ctx, "Bad_Project", "web"), codes.InvalidArgument, "ValidationError")
	storedProfile(t, b, "web")
	wantAWS(t, e.api.DeleteProfile(ctx, proj, "missing"), codes.NotFound, "NoSuchEntity")
	for _, n := range []string{strings.Repeat("p", iam.MaxInstanceProfileNameLen), "A+=,.@_-z9"} {
		seedInstanceProfile(t, b, n)
		if err := e.api.DeleteProfile(ctx, proj, n); err != nil {
			t.Fatalf("DeleteInstanceProfile(%q): %v, want deleted", n, err)
		}
	}

	boom := errors.New("backend down")
	for _, fail := range []func(store.Backend) store.Backend{
		func(m store.Backend) store.Backend { return failingGet{m, iam.KindInstanceProfile, boom} },
		func(m store.Backend) store.Backend { return failingGet{m, iam.KindRole, boom} },
		func(m store.Backend) store.Backend { return failingDelete{m, iam.KindInstanceProfile, boom} },
	} {
		m := memstore.New()
		fe := newEnvOn(t, fail(m), &now)
		seedInstanceProfile(t, m, "web", "r")
		wantAWS(t, fe.api.DeleteProfile(ctx, proj, "web"), codes.Internal, "InternalFailure")
		storedProfile(t, m, "web")
	}
}

// TestDeleteInstanceProfileCanceled: a request whose context is canceled
// deletes nothing.
func TestDeleteInstanceProfileCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedInstanceProfile(t, b, "web")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := e.api.DeleteProfile(ctx, proj, "web")
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
	storedProfile(t, b, "web")
}

// TestDeleteInstanceProfileConcurrent: of DeleteInstanceProfile and
// AddRoleToInstanceProfile requests racing on two replicas, exactly one
// succeeds: a delete after the add is DeleteConflict and an add after the
// delete is NoSuchEntity, so a profile is never deleted while it holds a
// role. On both store backends.
func TestDeleteInstanceProfileConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			seedRole(t, replicas[0], "r")
			seedInstanceProfile(t, b, "web")
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					api := replicas[i%2].api
					if i/2%2 == 0 {
						errs[i] = api.DeleteProfile(t.Context(), proj, "web")
					} else {
						errs[i] = api.AddProfileRole(t.Context(), proj, "web", "r")
					}
				})
			}
			wg.Wait()
			deleted, added := 0, 0
			for i, err := range errs {
				isDelete := i/2%2 == 0
				switch {
				case err == nil && isDelete:
					deleted++
				case err == nil:
					added++
				case status.Code(err) == codes.NotFound:
					wantAWS(t, err, codes.NotFound, "NoSuchEntity")
				case isDelete:
					wantAWS(t, err, codes.FailedPrecondition, "DeleteConflict")
				default:
					wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
				}
			}
			if deleted+added != 1 {
				t.Fatalf("%d deletes and %d adds succeeded, want exactly one request", deleted, added)
			}
			v, err := store.Get[iam.InstanceProfile](t.Context(), store.Scoped(b, proj), "web")
			switch {
			case deleted == 1 && !errors.Is(err, store.ErrNotFound):
				t.Fatalf("delete won but the profile is %+v (%v)", v.Object, err)
			case added == 1 && (err != nil || len(v.Object.Roles) != 1):
				t.Fatalf("add won but the profile is %+v (%v), want it with the role", v.Object, err)
			}
		})
	}
}

// changingBeforeDelete adds role to the instance profile once, before the
// first delete of an instance profile, as a concurrent
// AddRoleToInstanceProfile between the read and the delete would.
type changingBeforeDelete struct {
	store.Backend
	once sync.Once
	role string
	t    *testing.T
}

func (c *changingBeforeDelete) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if k == iam.KindInstanceProfile {
		c.once.Do(func() {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(p *iam.InstanceProfile) error {
				p.Roles = []string{c.role}
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		})
	}
	return c.Backend.Delete(ctx, k, key, version)
}

// TestDeleteInstanceProfileStaleRead: a role added after the profile was
// read is seen by the delete, which is refused, never done blind. On both
// store backends.
func TestDeleteInstanceProfileStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedRole(t, newEnvOn(t, inner, &now), "late")
			seedInstanceProfile(t, inner, "web")
			b := &changingBeforeDelete{Backend: inner, role: "late", t: t}
			err := newEnvOn(t, b, &now).api.DeleteProfile(t.Context(), proj, "web")
			wantAWS(t, err, codes.FailedPrecondition, "DeleteConflict")
			if got := storedProfile(t, inner, "web").Object.Roles; len(got) != 1 || got[0] != "late" {
				t.Fatalf("after stale read: roles %q, want [late] kept", got)
			}
		})
	}
}
