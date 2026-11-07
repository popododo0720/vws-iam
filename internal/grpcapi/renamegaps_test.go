package grpcapi_test

import (
	"maps"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// storeVersions is the version of every stored object, keyed by kind and
// key.
func storeVersions(t *testing.T, b store.Backend) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, k := range iam.Kinds {
		es, err := b.List(t.Context(), k)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			out[string(k)+"/"+e.Key] = e.Version
		}
	}
	return out
}

// crashAfterCopy renames alice to bob and kills the process at the first
// write that leaves bob stored with RenamedFrom, so bob is the new side of
// an unfinished rename.
func crashAfterCopy(t *testing.T, open func() store.Backend) (*env, *crashing, renameFixture) {
	t.Helper()
	for n := 1; n < 32; n++ {
		c := &crashing{Backend: open()}
		now := time.Now().UTC()
		e := newEnvOn(t, c, &now)
		f := seedRename(t, e, c)
		c.arm(n, true)
		_, err := e.api.UpdateUserRename(t.Context(), renameUserReq("alice", f.etag, "r1"), "bob")
		if !c.revive() {
			t.Fatalf("rename finished (%v) before bob was left half renamed", err)
		}
		bob, err := store.Get[iam.User](t.Context(), store.Scoped(c, proj), "bob")
		if err == nil && bob.Object.RenamedFrom != "" {
			*e.now = e.now.Add(membershipLease)
			return e, c, f
		}
	}
	t.Fatal("no crash point leaves bob half renamed")
	return nil, nil, renameFixture{}
}

// TestRenameValidateOnlyWritesNothing: a validate_only rename of the new
// side of an unfinished rename answers ConcurrentModification and writes
// nothing; it does not finish the earlier rename (#180).
func TestRenameValidateOnlyWritesNothing(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			e, c, f := crashAfterCopy(t, bc.open)
			before := storeVersions(t, c)
			req := renameUserReq("bob", "", "dry-1")
			req.ValidateOnly = true
			_, err := e.api.UpdateUserRename(t.Context(), req, "carol")
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			if after := storeVersions(t, c); !maps.Equal(before, after) {
				t.Errorf("validate_only wrote:\nbefore %v\nafter  %v", before, after)
			}
			if _, err := e.api.UpdateUserRename(t.Context(), renameUserReq("alice", f.etag, "r1"), "bob"); err != nil {
				t.Fatalf("retry of the real rename: %v", err)
			}
			wantRenamed(t, e, c, f)
		})
	}
}

// TestRenameUndoRestoresPathAndLabels: a rename with a new path and labels
// whose new name is taken after the mark backs out with
// EntityAlreadyExists and leaves the old path and labels, whether the
// retry of the request or the sweep undoes it (#180).
func TestRenameUndoRestoresPathAndLabels(t *testing.T) {
	for _, bc := range renameBackends {
		for _, by := range []string{"retry", "sweep"} {
			t.Run(bc.name+"/"+by, func(t *testing.T) {
				c := &crashing{Backend: bc.open()}
				now := time.Now().UTC()
				e := newEnvOn(t, c, &now)
				ctx := t.Context()
				e.createUser(t, ctx, "alice")
				if _, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
					User: &iamv1.User{
						Name: userName("alice"), Labels: map[string]string{"team": "old"},
						Spec: &iamv1.UserSpec{Path: "/old/"},
					},
					UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels", "spec.path"}},
				}); err != nil {
					t.Fatal(err)
				}
				req := &iamv1.UpdateUserRequest{
					User: &iamv1.User{
						Name: userName("alice"), Labels: map[string]string{"team": "new"},
						Spec: &iamv1.UserSpec{Path: "/new/"},
					},
					UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels", "spec.path"}},
					RequestId:  "r1",
				}
				c.arm(2, true) // the mark commits, then the process dies
				if _, err := e.api.UpdateUserRename(ctx, req, "bob"); err == nil {
					t.Fatal("rename survived the crash")
				}
				c.revive()
				u, err := store.Get[iam.User](ctx, store.Scoped(c, proj), "alice")
				if err != nil || u.Object.RenameTo != "bob" || u.Object.Path != "/new/" {
					t.Fatalf("alice not marked with the request's path: %+v %v", u.Object, err)
				}
				*e.now = e.now.Add(2 * time.Minute)
				e.createUser(t, ctx, "BOB")
				if by == "retry" {
					_, err = e.api.UpdateUserRename(ctx, req, "bob")
					wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
				} else if _, err := e.api.ResumeRenames(ctx); err != nil {
					t.Logf("sweep reports the taken name: %v", err)
				}
				noMarks(t, c)
				got := e.getUser(t, "alice")
				if got.GetSpec().GetPath() != "/old/" ||
					!maps.Equal(got.GetLabels(), map[string]string{"team": "old"}) {
					t.Errorf(
						"alice path %q labels %v, want /old/ and team=old",
						got.GetSpec().GetPath(),
						got.GetLabels(),
					)
				}
				u, err = store.Get[iam.User](ctx, store.Scoped(c, proj), "alice")
				if err != nil || u.Object.RenameUndo != nil {
					t.Errorf("alice keeps the undo record: %+v %v", u.Object.RenameState, err)
				}
			})
		}
	}
}

// TestUserStatusIgnoresRecreatedPartner: while alice's rename to bob is
// stuck after the mark, another user created as BOB is not alice's rename
// partner, so GetUser and ListUsers show none of BOB's groups on alice
// (#180).
func TestUserStatusIgnoresRecreatedPartner(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			c := &crashing{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, c, &now)
			ctx := t.Context()
			f := seedRename(t, e, c)
			c.arm(2, true) // the mark commits, then the process dies
			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", f.etag, ""), "bob"); err == nil {
				t.Fatal("rename survived the crash")
			}
			c.revive()
			*e.now = e.now.Add(membershipLease)
			e.createUser(t, ctx, "BOB")
			e.createGroupWith(t, "ops", userName("BOB"))

			want := []string{groupName("devs")}
			if got := e.getUser(t, "alice").GetStatus().GetGroups(); !slices.Equal(got, want) {
				t.Errorf("GetUser alice groups %v, want %v", got, want)
			}
			l, err := e.users.ListUsers(ctx, &iamv1.ListUsersRequest{Parent: parentName})
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(l.GetUsers(), func(u *iamv1.User) bool { return u.GetName() == userName("alice") })
			if i < 0 {
				t.Fatalf("ListUsers has no alice: %v", l.GetUsers())
			}
			if got := l.GetUsers()[i].GetStatus().GetGroups(); !slices.Equal(got, want) {
				t.Errorf("ListUsers alice groups %v, want %v", got, want)
			}
		})
	}
}

// TestUserStatusMergesRealPartner: both sides of an unfinished rename show
// the groups that still name either side.
func TestUserStatusMergesRealPartner(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			e, _, _ := crashAfterCopy(t, bc.open)
			want := []string{groupName("devs")}
			for _, n := range []string{"alice", "bob"} {
				if got := e.getUser(t, n).GetStatus().GetGroups(); !slices.Equal(got, want) {
					t.Errorf("GetUser %s groups %v, want %v", n, got, want)
				}
			}
		})
	}
}
