package grpcapi_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestRevokeSessionsMemstore runs the #37 suite on two replicas sharing
// one in-memory backend.
func TestRevokeSessionsMemstore(t *testing.T) {
	testRevokeSessions(t, memstore.New())
}

// TestRevokeSessionsOnAPIServer runs it on kubestore against a real
// kube-apiserver with deploy/crds. It skips without KUBEBUILDER_ASSETS.
func TestRevokeSessionsOnAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set")
	}
	te := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "deploy", "crds")}, ErrorIfCRDPathMissing: true}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := te.Stop(); err != nil {
			t.Error(err)
		}
	})
	cfg.QPS, cfg.Burst = 1000, 2000
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "vws-iam-"}}
	if err := c.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	testRevokeSessions(t, kubestore.New(c, ns.Name))
}

func testRevokeSessions(t *testing.T, b store.Backend) {
	a, rb, kid, secret := replicas(t, b)
	ctx := t.Context()
	// alice may assume deployer.
	pol := a.createPolicy(t, ctx, "assume", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`)
	if _, err := a.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{User: &iamv1.User{Name: parentName + "/users/alice", Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}}}); err != nil {
		t.Fatal(err)
	}
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:vws:iam::acme:user/alice"},"Action":"sts:AssumeRole"}]}`
	op, err := a.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{Parent: parentName, RoleId: "deployer", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}}})
	if err != nil {
		t.Fatal(err)
	}
	role := unpack(t, op, &iamv1.Role{})

	userSess, err := a.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(a.stsSign(kid, secret, "", "GetSessionToken"))})
	if err != nil {
		t.Fatal(err)
	}
	roleSess, err := a.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Authentication: arSig(a.stsSign(kid, secret, "", "AssumeRole")), Role: role.GetName(), RoleSessionName: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	use := func(e *env, c *iamv1.Credentials) error {
		_, err := e.auth.Authenticate(ctx, e.sign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken()))
		return err
	}
	for _, e := range []*env{a, rb} {
		if use(e, userSess.GetCredentials()) != nil || use(e, roleSess.GetCredentials()) != nil {
			t.Fatal("sessions must work before revocation")
		}
	}

	// Revoke alice's sessions on replica B.
	*a.now = a.now.Add(time.Second)
	revokedAt := *a.now
	const rid = "6f1c0a3e-8f7b-4b8e-9c55-2a7e4d0f1b23"
	op, err = rb.users.RevokeUserSessions(ctx, &iamv1.RevokeUserSessionsRequest{Name: parentName + "/users/alice", RequestId: rid})
	if err != nil {
		t.Fatal(err)
	}
	u := unpack(t, op, &iamv1.User{})
	if !u.GetStatus().GetSessionsRevokeTime().AsTime().Equal(revokedAt) {
		t.Fatalf("sessions_revoke_time %v, want %v", u.GetStatus().GetSessionsRevokeTime().AsTime(), revokedAt)
	}
	// Refused on both replicas and after a restart; the role session is not.
	for _, e := range []*env{a, rb, newEnvOn(t, b, a.now)} {
		wantErr(t, use(e, userSess.GetCredentials()), codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
		if err := use(e, roleSess.GetCredentials()); err != nil {
			t.Fatalf("role session must survive a user revocation: %v", err)
		}
	}
	// A request_id replay returns the original operation and does not move
	// the revocation time.
	*a.now = a.now.Add(time.Minute)
	again, err := a.users.RevokeUserSessions(ctx, &iamv1.RevokeUserSessionsRequest{Name: parentName + "/users/alice", RequestId: rid})
	if err != nil || again.GetName() != op.GetName() {
		t.Fatalf("replay %v %v, want operation %s", again.GetName(), err, op.GetName())
	}
	got, err := a.users.GetUser(ctx, &iamv1.GetUserRequest{Name: parentName + "/users/alice"})
	if err != nil || !got.GetStatus().GetSessionsRevokeTime().AsTime().Equal(revokedAt) {
		t.Fatalf("after replay %v %v", got.GetStatus().GetSessionsRevokeTime(), err)
	}
	// Sessions issued after the revocation work.
	fresh, err := rb.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(rb.stsSign(kid, secret, "", "GetSessionToken"))})
	if err != nil || use(a, fresh.GetCredentials()) != nil {
		t.Fatalf("fresh session %v", err)
	}

	// Revoke the role's sessions on replica A; B refuses the role session.
	*a.now = a.now.Add(time.Second)
	op, err = a.roles.RevokeRoleSessions(ctx, &iamv1.RevokeRoleSessionsRequest{Name: role.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	if r := unpack(t, op, &iamv1.Role{}); !r.GetStatus().GetSessionsRevokeTime().AsTime().Equal(*a.now) {
		t.Fatalf("role sessions_revoke_time %v", r.GetStatus().GetSessionsRevokeTime())
	}
	wantErr(t, use(rb, roleSess.GetCredentials()), codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")

	// Hostile and missing targets.
	_, err = a.users.RevokeUserSessions(ctx, &iamv1.RevokeUserSessionsRequest{Name: parentName + "/users/nobody"})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	_, err = a.roles.RevokeRoleSessions(ctx, &iamv1.RevokeRoleSessionsRequest{Name: parentName + "/users/alice"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Fatalf("a user name on RevokeRoleSessions: %v", err)
	}
}

// TestRevokeSessionsAuthz checks the authorization console-api performs
// before calling Revoke*Sessions: iam:RevokeUserSessions /
// iam:RevokeRoleSessions on the target ARN, with explicit Deny winning.
func TestRevokeSessionsAuthz(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	admin := e.createUser(t, ctx, "admin")
	pol := e.createPolicy(t, ctx, "revoke", `{"Version":"2012-10-17","Statement":[
		{"Sid":"Alice","Effect":"Allow","Action":"iam:RevokeUserSessions","Resource":"arn:vws:iam::acme:user/alice"},
		{"Sid":"Roles","Effect":"Allow","Action":"iam:RevokeRoleSessions","Resource":"arn:vws:iam::acme:role/*"},
		{"Sid":"NotProd","Effect":"Deny","Action":"iam:RevokeRoleSessions","Resource":"arn:vws:iam::acme:role/prod"}]}`)
	if _, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{User: &iamv1.User{Name: admin.GetName(), Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}}}); err != nil {
		t.Fatal(err)
	}
	pr := &iamv1.Principal{Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: admin.GetStatus().GetArn(), Project: proj, UniqueId: admin.GetStatus().GetUniqueId(), Resource: admin.GetName()}
	for _, c := range []struct {
		action, res string
		want        iamv1.Decision
	}{
		{"iam:RevokeUserSessions", "arn:vws:iam::acme:user/alice", iamv1.Decision_DECISION_ALLOW},
		{"iam:RevokeUserSessions", "arn:vws:iam::acme:user/bob", iamv1.Decision_DECISION_DENY_IMPLICIT},
		{"iam:RevokeRoleSessions", "arn:vws:iam::acme:role/deployer", iamv1.Decision_DECISION_ALLOW},
		{"iam:RevokeRoleSessions", "arn:vws:iam::acme:role/prod", iamv1.Decision_DECISION_DENY_EXPLICIT},
		{"iam:RevokeRoleSessions", "arn:vws:iam::acme:user/alice", iamv1.Decision_DECISION_DENY_IMPLICIT},
	} {
		r, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: pr, Action: c.action, Resources: []string{c.res}})
		if err != nil || r.GetDecision() != c.want {
			t.Errorf("%s on %s = %v %v, want %v", c.action, c.res, r.GetDecision(), err, c.want)
		}
	}
}
