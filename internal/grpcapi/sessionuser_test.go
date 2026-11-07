package grpcapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

const allowAll = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// recreating is a backend that, at the nth read of a user, first gives
// that user the unique id and UID of another user, as if it was deleted
// and created again under the same name between two reads.
type recreating struct {
	store.Backend
	mu      sync.Mutex
	user    string
	left    int
	id, uid string
}

func (r *recreating) at(user string, nth int, id, uid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.user, r.left, r.id, r.uid = user, nth, id, uid
}

func (r *recreating) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	r.mu.Lock()
	fire := false
	if k == iam.KindUser && r.left > 0 && store.Fold(key) == store.Fold(proj+"/"+r.user) {
		r.left--
		fire = r.left == 0
	}
	r.mu.Unlock()
	if fire {
		b := store.Scoped(r.Backend, proj)
		u, err := store.Get[iam.User](ctx, b, r.user)
		if err != nil {
			return store.Entry{}, err
		}
		u.Object.ID, u.Object.UID = r.id, r.uid
		if _, err := store.Update(ctx, b, u.Object, u.Version); err != nil {
			return store.Entry{}, err
		}
	}
	return r.Backend.Get(ctx, k, key)
}

func (e *env) attach(t *testing.T, ctx context.Context, user string, policies ...string) {
	t.Helper()
	if _, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: userName(user), Spec: &iamv1.UserSpec{AttachedPolicies: policies}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *env) trustingRole(t *testing.T, ctx context.Context, name string, u *iamv1.User) *iamv1.Role {
	t.Helper()
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` +
		u.GetStatus().GetArn() + `"},"Action":"sts:AssumeRole"}]}`
	op, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
		Parent: parentName, RoleId: name, Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return unpack(t, op, &iamv1.Role{})
}

func (e *env) sessionToken(t *testing.T, ctx context.Context, k keyed) *iamv1.Credentials {
	t.Helper()
	resp, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
		Authentication: gstSig(e.stsSign(k.id, k.secretKey, "", "GetSessionToken")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp.GetCredentials()
}

func (e *env) signedWith(c *iamv1.Credentials) *iamv1.AuthenticateRequest {
	return e.signFor("s3", c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken())
}

func (e *env) assumeWith(
	ctx context.Context, c *iamv1.Credentials, role *iamv1.Role,
) (*iamv1.AssumeRoleResponse, error) {
	return e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
		Authentication: arSig(e.stsSign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken(), "AssumeRole")),
		Role:           role.GetName(), RoleSessionName: "deploy",
	})
}

// TestSessionOfRecreatedUserIsRefused: a GetSessionToken session belongs to
// the user that got it. Once that user is deleted and a user of the same
// name is created, the old credentials neither authenticate nor assume a
// role, on any replica and after a restart, while the new user's own key
// works (#176).
func TestSessionOfRecreatedUserIsRefused(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			alice := e.keyedUser(t, "alice", allowAll)
			role := e.trustingRole(t, ctx, "deployer", alice.user)
			old := e.sessionToken(t, ctx, alice)
			if _, err := e.auth.Authenticate(ctx, e.signedWith(old)); err != nil {
				t.Fatalf("session before the delete: %v", err)
			}

			name := alice.user.GetName()
			del := &iamv1.DeleteAccessKeyRequest{Name: name + "/accessKeys/" + alice.id}
			if _, err := e.keys.DeleteAccessKey(ctx, del); err != nil {
				t.Fatal(err)
			}
			e.attach(t, ctx, "alice")
			if _, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: name}); err != nil {
				t.Fatal(err)
			}
			again := e.createUser(t, ctx, "alice")
			if again.GetStatus().GetUniqueId() == alice.user.GetStatus().GetUniqueId() {
				t.Fatal("the recreated user kept the old unique id")
			}
			e.attach(t, ctx, "alice", alice.user.GetSpec().GetAttachedPolicies()...)
			k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: again.GetName()})
			if err != nil {
				t.Fatal(err)
			}
			n := k.GetAccessKey().GetName()
			fresh := keyed{user: again, id: n[strings.LastIndex(n, "/")+1:], secretKey: k.GetSecretAccessKey()}

			restarted := newEnvOn(t, b, &now)
			restarted.nonce = 1000
			for _, r := range []*env{e, restarted} {
				for range 2 {
					_, err := r.auth.Authenticate(ctx, r.signedWith(old))
					wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidToken")
					_, err = r.assumeWith(ctx, old, role)
					wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidToken")
				}
				a, err := r.auth.Authenticate(ctx, r.signFor("s3", fresh.id, fresh.secretKey, ""))
				if err != nil || a.GetPrincipal().GetUniqueId() != again.GetStatus().GetUniqueId() {
					t.Fatalf("the new user's own key: %v %v", a, err)
				}
			}
		})
	}
}

// TestSessionRefusedWhenUserRecreatedAfterValidate: the user of a
// GetSessionToken session is deleted and created again after sts.Validate
// read it and before the session is described or evaluated. Authenticate
// refuses the session instead of answering with the new user's identity,
// and AssumeRole and a console session never evaluate the new user's
// policies for it (#176).
func TestSessionRefusedWhenUserRecreatedAfterValidate(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			r := &recreating{Backend: bk.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, r, &now)
			ctx := t.Context()
			alice := e.keyedUser(t, "alice", allowAll)
			spare := e.createUser(t, ctx, "spare")
			role := e.trustingRole(t, ctx, "deployer", alice.user)
			e.setPassword(t, ctx, "alice", testPassword)
			sess := e.sessionToken(t, ctx, alice)
			newID, oldID := spare.GetStatus().GetUniqueId(), alice.user.GetStatus().GetUniqueId()
			uidOf := func(name string) string {
				t.Helper()
				u, err := store.Get[iam.User](ctx, store.Scoped(r.Backend, proj), name)
				if err != nil {
					t.Fatal(err)
				}
				return u.Object.UID
			}
			uid, oldUID := uidOf("spare"), uidOf("alice")
			restore := func() {
				t.Helper()
				r.at("alice", 1, oldID, oldUID)
				if _, err := r.Get(ctx, iam.KindUser, proj+"/alice"); err != nil {
					t.Fatal(err)
				}
			}

			// Read 1 is sts.Validate, read 2 is sessionPrincipal.
			r.at("alice", 2, newID, uid)
			a, err := e.auth.Authenticate(ctx, e.signedWith(sess))
			if a.GetPrincipal().GetUniqueId() == newID {
				t.Fatalf("the old session was described as the new user: %v", a)
			}
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
			restore()

			// AssumeRole reads the user in Authenticate (1, 2), in
			// Resolve (3), and in Authorize (4).
			r.at("alice", 4, newID, uid)
			ar, err := e.assumeWith(ctx, sess, role)
			if ar.GetCredentials().GetAccessKeyId() != "" {
				t.Fatalf("AssumeRole evaluated the new user's policies for the old session: %v", ar)
			}
			wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
			restore()

			// A console session reads the user when it is checked (1) and
			// in ConsoleCaller (2).
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: testPassword})
			if err != nil {
				t.Fatal(err)
			}
			r.at("alice", 2, newID, uid)
			ar, err = e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
				Authentication: &iamv1.AssumeRoleRequest_ConsoleSessionToken{ConsoleSessionToken: l.GetSessionToken()},
				Role:           role.GetName(), RoleSessionName: "deploy",
			})
			if ar.GetCredentials().GetAccessKeyId() != "" {
				t.Fatalf("a console session acted as the recreated user: %v", ar)
			}
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidToken")
			restore()

			// With the user back, each path still works.
			if _, err := e.auth.Authenticate(ctx, e.signedWith(sess)); err != nil {
				t.Fatalf("session after restore: %v", err)
			}
			if _, err := e.assumeWith(ctx, sess, role); err != nil {
				t.Fatalf("AssumeRole after restore: %v", err)
			}
		})
	}
}
