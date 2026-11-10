package grpcapi_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// roleDeleteLease outlasts grpcapi.roleDeleteLease (10s), the lease of a
// DeleteRole mark whose writer died.
const roleDeleteLease = 11 * time.Second

func deleteRoleRPC(t *testing.T, e *env, role string) error {
	t.Helper()
	_, err := e.roles.DeleteRole(t.Context(), &iamv1.DeleteRoleRequest{Name: parentName + "/roles/" + role})
	return err
}

func lookupRole(t *testing.T, b store.Backend, name string) (store.Versioned[iam.Role], bool) {
	t.Helper()
	v, err := store.Get[iam.Role](t.Context(), store.Scoped(b, proj), name)
	if errors.Is(err, store.ErrNotFound) {
		return v, false
	}
	if err != nil {
		t.Fatal(err)
	}
	return v, true
}

// TestDeleteRoleHeldByInstanceProfile: a role an instance profile of its
// project names, in any case, is DeleteConflict on every replica and
// stays unmarked; a profile of another project does not hold it, and
// once the role is removed from the profile it is deleted. On every
// backend in renameBackends.
func TestDeleteRoleHeldByInstanceProfile(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			seedInstanceProfile(t, b, "web", "s3access")
			other := iam.InstanceProfile{
				Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: "web", ID: iam.NewUniqueID("AIPA"),
				Created: now, Roles: []string{"S3Access"},
			}
			if _, err := store.Create(t.Context(), store.Scoped(b, "other"), other); err != nil {
				t.Fatal(err)
			}

			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				wantAWS(t, deleteRoleRPC(t, replica, "S3ACCESS"), codes.FailedPrecondition, "DeleteConflict")
				r, ok := lookupRole(t, b, "S3Access")
				if !ok || !r.Object.DeleteStarted.IsZero() {
					t.Fatalf("refused delete: role kept %v, DeleteStarted %v; want kept, unmarked", ok, r.Object.DeleteStarted)
				}
			}
			if _, err := e.profiles.RemoveRoleFromInstanceProfile(t.Context(), &iamv1.RemoveRoleFromInstanceProfileRequest{
				Name: parentName + "/instanceProfiles/web", RoleName: "S3Access",
			}); err != nil {
				t.Fatal(err)
			}
			if err := deleteRoleRPC(t, e, "S3Access"); err != nil {
				t.Fatal(err)
			}
			if _, ok := lookupRole(t, b, "S3Access"); ok {
				t.Fatal("role is still stored after DeleteRole")
			}
		})
	}
}

// addingBeforeRoleDelete runs add once, just before the store delete of
// a role, as an AddRoleToInstanceProfile racing DeleteRole between its
// in-use check and its delete would.
type addingBeforeRoleDelete struct {
	store.Backend
	once sync.Once
	add  func()
}

func (a *addingBeforeRoleDelete) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if k == iam.KindRole {
		a.once.Do(a.add)
	}
	return a.Backend.Delete(ctx, k, key, version)
}

// TestDeleteRoleRacesAddRoleToInstanceProfile: an add that lands between
// DeleteRole's in-use check and its delete never leaves a deleted role in
// a profile. While the delete's mark is recent the add waits and adds
// nothing, and the role is deleted; an add on a replica that sees the
// mark as stale clears it and adds the role, and the delete is then
// ConcurrentModification and deletes nothing. On every backend in
// renameBackends.
func TestDeleteRoleRacesAddRoleToInstanceProfile(t *testing.T) {
	for _, bk := range renameBackends {
		for _, stale := range []bool{false, true} {
			t.Run(bk.name+map[bool]string{false: "/recent", true: "/stale"}[stale], func(t *testing.T) {
				inner := bk.open()
				now := time.Now().UTC()
				later := now
				if stale {
					later = now.Add(roleDeleteLease)
				}
				adder := newEnvOn(t, inner, &later)
				seedRole(t, adder, "r")
				seedInstanceProfile(t, inner, "web")
				var addErr error
				b := &addingBeforeRoleDelete{Backend: inner, add: func() {
					ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
					defer cancel()
					addErr = adder.api.AddProfileRole(ctx, proj, "web", "r")
				}}
				delErr := deleteRoleRPC(t, newEnvOn(t, b, &now), "r")

				r, kept := lookupRole(t, inner, "r")
				roles := storedProfile(t, inner, "web").Object.Roles
				if !kept && len(roles) > 0 {
					t.Fatalf("role deleted while profile names it: %q", roles)
				}
				if !stale {
					if status.Code(addErr) != codes.DeadlineExceeded || delErr != nil || kept {
						t.Fatalf("recent mark: add %v, delete %v, role kept %v; want DeadlineExceeded, ok, deleted",
							addErr, delErr, kept)
					}
					return
				}
				if addErr != nil || len(roles) != 1 || !r.Object.DeleteStarted.IsZero() {
					t.Fatalf("stale mark: add %v, roles %q, mark %v; want added, unmarked", addErr, roles, r.Object.DeleteStarted)
				}
				wantAWS(t, delErr, codes.Aborted, "ConcurrentModification")
			})
		}
	}
}

// TestDeleteRoleConcurrentAdd: DeleteRole and AddRoleToInstanceProfile
// racing on two replicas never leave a profile naming a deleted role, and
// each answers success or one of its documented refusals. On every
// backend in renameBackends.
func TestDeleteRoleConcurrentAdd(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			for range 8 {
				seedRole(t, replicas[0], "r")
				seedInstanceProfile(t, b, "web")
				var wg sync.WaitGroup
				var delErr, addErr error
				wg.Go(func() { delErr = deleteRoleRPC(t, replicas[0], "r") })
				wg.Go(func() { addErr = replicas[1].api.AddProfileRole(t.Context(), proj, "web", "r") })
				wg.Wait()
				_, kept := lookupRole(t, b, "r")
				roles := storedProfile(t, b, "web").Object.Roles
				if !kept && len(roles) > 0 {
					t.Fatalf("role deleted while profile names it: %q (delete %v, add %v)", roles, delErr, addErr)
				}
				if c := status.Code(delErr); delErr != nil && c != codes.FailedPrecondition && c != codes.Aborted {
					t.Fatalf("delete: %v", delErr)
				}
				if c := status.Code(addErr); addErr != nil && c != codes.NotFound && c != codes.Aborted {
					t.Fatalf("add: %v", addErr)
				}
				if kept {
					if _, err := replicas[0].profiles.RemoveRoleFromInstanceProfile(t.Context(),
						&iamv1.RemoveRoleFromInstanceProfileRequest{Name: parentName + "/instanceProfiles/web", RoleName: "r"},
					); err != nil && status.Code(err) != codes.NotFound {
						t.Fatal(err)
					}
					if err := deleteRoleRPC(t, replicas[0], "r"); err != nil {
						t.Fatal(err)
					}
				}
				if err := store.Delete[iam.InstanceProfile](t.Context(), store.Scoped(b, proj), "web", ""); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// TestAddRoleAfterCrashedRoleDelete: a delete mark left by a DeleteRole
// that stopped after marking (a crash) makes AddRoleToInstanceProfile
// wait and add nothing while it is recent; on a restarted server once it
// is stale, the add clears it and adds the role, and DeleteRole is then
// DeleteConflict. On every backend in renameBackends.
func TestAddRoleAfterCrashedRoleDelete(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "r")
			seedInstanceProfile(t, b, "web")
			if _, err := store.Mutate(t.Context(), store.Scoped(b, proj), "r", func(r *iam.Role) error {
				r.DeleteStarted = now
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer cancel()
			if err := e.api.AddProfileRole(ctx, proj, "web", "r"); status.Code(err) != codes.DeadlineExceeded {
				t.Fatalf("add on a recent mark: %v, want DeadlineExceeded", err)
			}
			if roles := storedProfile(t, b, "web").Object.Roles; len(roles) != 0 {
				t.Fatalf("add on a recent mark wrote roles %q", roles)
			}

			later := now.Add(roleDeleteLease)
			restarted := newEnvOn(t, b, &later)
			if err := restarted.api.AddProfileRole(t.Context(), proj, "web", "r"); err != nil {
				t.Fatal(err)
			}
			if r, _ := lookupRole(t, b, "r"); !r.Object.DeleteStarted.IsZero() {
				t.Fatalf("stale mark kept after add: %v", r.Object.DeleteStarted)
			}
			wantAWS(t, deleteRoleRPC(t, restarted, "r"), codes.FailedPrecondition, "DeleteConflict")
		})
	}
}
