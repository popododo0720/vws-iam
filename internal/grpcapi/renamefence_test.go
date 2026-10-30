package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// TestLoginMFARacingRenameMark: Login reads alice before a rename marks
// her, then the rename moves her MFA device to bob before Login lists
// devices. Login must not issue a password-only session that the rename
// later hands to bob.
func TestLoginMFARacingRenameMark(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			h := &hooked{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			e.setPassword(t, ctx, "alice", testPassword)
			enableMFA(t, e, ctx, "alice")
			ran := false
			h.at("list", iam.KindMfaDevice, "", func() error {
				ran = true
				markRename(t, h, "alice", "bob", now)
				pb := store.Scoped(h, proj)
				d, err := store.Get[iam.MfaDevice](ctx, pb, "alice-phone")
				if err != nil {
					t.Fatal(err)
				}
				d.Object.UserName = "bob"
				if _, err := store.Update(ctx, pb, d.Object, d.Version); err != nil {
					t.Fatal(err)
				}
				return nil
			})
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: testPassword})
			if !ran {
				t.Fatal("the hook did not run")
			}
			if err == nil {
				// Finish the rename: it moves the session to bob.
				*e.now = e.now.Add(2 * time.Minute)
				if _, rerr := e.api.ResumeRenames(ctx); rerr != nil {
					t.Fatal(rerr)
				}
				v, verr := e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()})
				t.Fatalf("Login issued a session without MFA (mfa=%v); after the rename it validates as %v (%v)",
					l.GetPrincipal().GetMfaAuthenticated(), v.GetPrincipal().GetResource(), verr)
			}
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
		})
	}
}

// TestRenamePartnerMustMatch: a user rename of alice to bob deleted alice
// and crashed before it cleared bob's RenamedFrom. A new alice joins a
// privileged group; bob must not inherit its policies.
func TestRenamePartnerMustMatch(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			b := bc.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), "bob"); err != nil {
				t.Fatal(err)
			}
			pb := store.Scoped(b, proj)
			bob, err := store.Get[iam.User](ctx, pb, "bob")
			if err != nil {
				t.Fatal(err)
			}
			bob.Object.RenamedFrom, bob.Object.RenameStarted, bob.Object.RenameConfirmed = "alice", now, true
			if _, err := store.UpdateMarked(ctx, pb, bob.Object, bob.Version); err != nil {
				t.Fatal(err)
			}
			alice := e.createUser(t, ctx, "alice")
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
			if _, err := e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{
				Parent: parentName, GroupId: "admins",
				Group: &iamv1.Group{Spec: &iamv1.GroupSpec{
					Members: []string{alice.GetName()}, InlinePolicies: map[string]string{"all": doc},
				}},
			}); err != nil {
				t.Fatal(err)
			}
			allowed := func(u *iamv1.User) bool {
				t.Helper()
				r, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: &iamv1.Principal{
					Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: u.GetStatus().GetArn(), Project: proj,
					UniqueId: u.GetStatus().GetUniqueId(), Resource: u.GetName(),
				}, Action: "s3:GetObject"})
				if err != nil {
					t.Fatal(err)
				}
				return r.GetDecision() == iamv1.Decision_DECISION_ALLOW
			}
			if !allowed(alice) {
				t.Error("the new alice is not allowed by her group")
			}
			if allowed(e.getUser(t, "bob")) {
				t.Error("bob inherits the groups of the new alice")
			}
		})
	}
}

// TestStaleCopyAfterDeleteIsNotPromoted: coordinator A marks devs, then
// coordinator B finishes the rename and builders is deleted before A
// copies; A creates its stale copy and dies right after. The sweep must
// drop the copy, not bring builders back.
func TestStaleCopyAfterDeleteIsNotPromoted(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			c := &crashing{Backend: bc.open()}
			h := &hooked{Backend: c}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createGroupWith(t, "devs")
			ran := false
			h.at("create", iam.KindGroup, "builders", func() error {
				ran = true
				if _, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders"); err != nil {
					t.Errorf("coordinator B: %v", err)
				}
				if _, err := e.groups.DeleteGroup(ctx, &iamv1.DeleteGroupRequest{Name: groupName("builders")}); err != nil {
					t.Errorf("delete builders: %v", err)
				}
				// A dies at the write after its create.
				c.arm(2, false)
				return nil
			})
			_, _ = e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders") //nolint:errcheck // A dies
			if !ran {
				t.Fatal("the hook did not run")
			}
			if !c.revive() {
				t.Fatal("coordinator A did not crash")
			}
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.ResumeRenames(ctx); err != nil {
				t.Fatal(err)
			}
			for _, n := range []string{"devs", "builders"} {
				g, err := e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName(n)})
				if err == nil {
					t.Errorf("group %s came back: %v", n, strings.TrimSpace(g.String()))
					continue
				}
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
		})
	}
}
