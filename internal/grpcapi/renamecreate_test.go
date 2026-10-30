package grpcapi_test

import (
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestCreateGroupRetryKeepsRenamingGroup: a CreateGroup with members dies
// after it stores the empty group, a rename marks that group and copies it
// without confirming, and the client retries the create with the same
// request id. The retry adopts the marked group; its cleanup must not
// delete it, or the rename drops its unconfirmed copy and the group is
// lost.
func TestCreateGroupRetryKeepsRenamingGroup(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			c := &crashing{Backend: bc.open()}
			h := &hooked{Backend: c}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			req := &iamv1.CreateGroupRequest{
				Parent: parentName, GroupId: "devs", RequestId: "create-devs",
				Group: &iamv1.Group{Spec: &iamv1.GroupSpec{Members: []string{userName("alice")}}},
			}

			// The empty group is stored; the process dies at the next write.
			h.at("create", iam.KindGroup, "devs", func() error { c.arm(2, false); return nil })
			if _, err := e.groups.CreateGroup(ctx, req); err == nil {
				t.Fatal("first CreateGroup survived its crash")
			}
			if !c.revive() {
				t.Fatal("no crash injected")
			}
			if m := e.getGroup(t, "devs").GetSpec().GetMembers(); len(m) != 0 {
				t.Fatalf("devs members %v after the crash, want none", m)
			}

			// The rename marks devs and stores an unconfirmed copy, then dies.
			h.at("create", iam.KindGroup, "builders", func() error { c.arm(1, true); return nil })
			if _, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders"); err == nil {
				t.Fatal("rename survived its crash")
			}
			if !c.revive() {
				t.Fatal("no crash injected in the rename")
			}

			_, _ = e.groups.CreateGroup(ctx, req) //nolint:errcheck // refused while devs is renaming
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.ResumeRenames(ctx); err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, n := range []string{"devs", "builders"} {
				if _, err := e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName(n)}); err == nil {
					found++
				}
			}
			if found != 1 {
				t.Errorf("%d of devs and builders exist after the retry and the sweep, want 1", found)
			}
			noMarks(t, h)
		})
	}
}
