package grpcapi_test

import (
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// TestRenamePartnerRecreatedDuringGroupRead: bob is the new copy of a
// rename of alice. Authorize checks that alice is still bob's partner;
// then, before it reads the groups, the rename commits, a new alice is
// created and joins a privileged group. bob must not inherit it.
func TestRenamePartnerRecreatedDuringGroupRead(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			b := bc.open()
			h := &hooked{Backend: b}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			markRename(t, b, "alice", "bob", now)
			bob := e.getUser(t, "bob")
			doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
			ran := false
			h.at("list", iam.KindGroup, "", func() error {
				ran = true
				pb := store.Scoped(b, proj)
				old, err := store.Get[iam.User](ctx, pb, "alice")
				if err != nil {
					t.Fatal(err)
				}
				// The rename commits: alice is deleted.
				if err := store.Delete[iam.User](ctx, pb, "alice", old.Version); err != nil {
					t.Fatal(err)
				}
				alice := e.createUser(t, ctx, "alice")
				if _, err := e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{
					Parent: parentName, GroupId: "admins",
					Group: &iamv1.Group{Spec: &iamv1.GroupSpec{
						Members: []string{alice.GetName()}, InlinePolicies: map[string]string{"all": doc},
					}},
				}); err != nil {
					t.Fatal(err)
				}
				return nil
			})
			r, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: &iamv1.Principal{
				Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: bob.GetStatus().GetArn(), Project: proj,
				UniqueId: bob.GetStatus().GetUniqueId(), Resource: bob.GetName(),
			}, Action: "s3:GetObject"})
			if !ran {
				t.Fatal("the hook did not run")
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.GetDecision() == iamv1.Decision_DECISION_ALLOW {
				t.Error("bob inherits the groups of the new alice")
			}
		})
	}
}
