package grpcapi_test

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// wantGroupMoved checks that group from is gone and group to exists.
func wantGroupMoved(t *testing.T, e *env, from, to string) {
	t.Helper()
	ctx := t.Context()
	if _, err := e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName(to)}); err != nil {
		t.Fatalf("group %s after the rename: %v", to, err)
	}
	_, err := e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName(from)})
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
}

// TestRenameCopyKeepsConfirmation: coordinator A confirms the copy
// builders of devs. Before A deletes devs, coordinator B copies devs
// again and dies right after. B must not take the confirmation back, or
// A, having deleted devs, drops builders as a stale copy and the group is
// lost.
func TestRenameCopyKeepsConfirmation(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			c := &crashing{Backend: bc.open()}
			h := &hooked{Backend: c}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createGroupWith(t, "devs")
			ran := false
			h.at("delete", iam.KindGroup, "devs", func() error {
				ran = true
				// B: its create of builders fails (exists), its rewrite
				// commits, then it dies.
				c.arm(2, true)
				_, _ = e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders") //nolint:errcheck // B dies
				if !c.revive() {
					t.Error("coordinator B did not crash")
				}
				dst, err := store.Get[iam.Group](ctx, store.Scoped(c.Backend, proj), "builders")
				if err != nil {
					t.Fatal(err)
				}
				if !dst.Object.RenameConfirmed {
					t.Error("coordinator B took the confirmation of builders back")
				}
				return nil
			})
			if _, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders"); err != nil {
				t.Errorf("coordinator A: %v", err)
			}
			if !ran {
				t.Fatal("the hook did not run")
			}
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.ResumeRenames(ctx); err != nil {
				t.Fatal(err)
			}
			wantGroupMoved(t, e, "devs", "builders")
		})
	}
}

// TestRenameDeleteFencedOnConfirmedCopy: coordinator A confirms the copy
// builders of devs. Before A deletes devs, a writer that does not keep
// the confirmation (a release before it did) rewrites builders under
// devs' mark. A must not delete devs while builders is no longer the copy
// it confirmed: finish would drop the unconfirmed builders, and both
// groups would be gone.
func TestRenameDeleteFencedOnConfirmedCopy(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			b := bc.open()
			h := &hooked{Backend: b}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createGroupWith(t, "devs")
			ran := false
			h.at("delete", iam.KindGroup, "devs", func() error {
				ran = true
				pb := store.Scoped(b, proj)
				src, err := store.Get[iam.Group](ctx, pb, "devs")
				if err != nil {
					t.Fatal(err)
				}
				dst, err := store.Get[iam.Group](ctx, pb, "builders")
				if err != nil {
					t.Fatal(err)
				}
				if !dst.Object.RenameConfirmed {
					t.Fatal("builders is not confirmed before the delete")
				}
				dst.Object.RenameConfirmed = false
				if _, err := store.UpdateMarkedIf(ctx, pb, dst.Object, dst.Version, store.PreOf(src)); err != nil {
					t.Fatal(err)
				}
				return nil
			})
			if _, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders"); err != nil {
				t.Errorf("rename: %v", err)
			}
			if !ran {
				t.Fatal("the hook did not run")
			}
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.ResumeRenames(ctx); err != nil {
				t.Fatal(err)
			}
			wantGroupMoved(t, e, "devs", "builders")
		})
	}
}
