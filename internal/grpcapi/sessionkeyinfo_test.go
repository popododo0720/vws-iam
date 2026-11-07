package grpcapi_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// TestGetAccessKeyInfoSessionKeys: the ASIA key id of an AssumeRole or
// GetSessionToken session answers its project on the issuing replica, on
// another replica and after a restart over the same store, on both store
// backends, until the session expires; GCSessionKeys then removes only
// the expired session's entry (#188).
func TestGetAccessKeyInfoSessionKeys(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			auditor := e.keyedUser(t, "auditor", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["sts:AssumeRole","sts:GetAccessKeyInfo"],"Resource":"*"}]}`)
			trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` +
				auditor.user.GetStatus().GetArn() + `"},"Action":"sts:AssumeRole"}]}`
			if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{Parent: parentName, RoleId: "ops", Role: &iamv1.Role{
				Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust},
			}}); err != nil {
				t.Fatal(err)
			}
			ar, err := e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
				Authentication: arSig(e.stsSign(auditor.id, auditor.secretKey, "", "AssumeRole")),
				Role:           parentName + "/roles/ops", RoleSessionName: "keyinfo",
			})
			if err != nil {
				t.Fatal(err)
			}
			st, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
				Authentication: gstSig(e.stsSign(auditor.id, auditor.secretKey, "", "GetSessionToken")),
			})
			if err != nil {
				t.Fatal(err)
			}
			role, gst := ar.GetCredentials().GetAccessKeyId(), st.GetCredentials().GetAccessKeyId()

			replica := newEnvOn(t, b, &now)
			replica.nonce = 1000
			info := func(on *env, id string) (string, error) {
				return on.api.AccessKeyInfo(ctx, on.stsSign(auditor.id, auditor.secretKey, "", keyInfoAction), "", "", id)
			}
			for _, id := range []string{role, gst} {
				for name, on := range map[string]*env{"issuer": e, "replica": replica} {
					if got, err := info(on, id); err != nil || got != proj {
						t.Fatalf("%s: GetAccessKeyInfo(%s) = %q, %v; want %q", name, id, got, err, proj)
					}
				}
			}

			// The role session lasts the default hour, the GetSessionToken
			// session 12 hours.
			now = now.Add(time.Hour + time.Second)
			_, err = info(replica, role)
			wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "InvalidClientTokenId")
			if got, err := info(replica, gst); err != nil || got != proj {
				t.Fatalf("live session: %q, %v", got, err)
			}
			for _, want := range []int{1, 0} {
				if n, err := replica.api.GCSessionKeys(ctx); err != nil || n != want {
					t.Fatalf("GCSessionKeys = %d, %v; want %d", n, err, want)
				}
			}
			if _, err := store.Get[iam.KeyIndex](ctx, b, role); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("expired entry after GC: %v", err)
			}
			for _, id := range []string{gst, auditor.id} {
				if got, err := info(e, id); err != nil || got != proj {
					t.Fatalf("after GC, %s: %q, %v", id, got, err)
				}
			}
		})
	}
}
