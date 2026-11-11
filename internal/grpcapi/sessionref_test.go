package grpcapi_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const refPolicy = `{"Version":"2012-10-17","Statement":[
	{"Effect":"Allow","Action":["sts:AssumeRole","s3:GetObject"],"Resource":"*"}]}`

const refTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
	`"Principal":{"AWS":"arn:vws:iam::acme:user/alice"},"Action":"sts:AssumeRole"}]}`

// refSessions holds alice, her access key and the sessions the session
// reference tests use.
type refSessions struct {
	a, b       *env
	kid, sec   string
	role       *iamv1.Role
	roleSess   *iamv1.Credentials
	userSess   *iamv1.Credentials
	roleSess2  *iamv1.Credentials
	bobSess    *iamv1.Credentials
	rolePr     *iamv1.Principal
	userPr     *iamv1.Principal
	rolePr2    *iamv1.Principal
	bobPr      *iamv1.Principal
	roleRef    string
	userRef    string
	roleRef2   string
	bobRef     string
	revokeRole func(*testing.T, *env)
	revokeUser func(*testing.T, *env)
}

func setupSessionRefs(t *testing.T, b store.Backend) *refSessions {
	t.Helper()
	a, rb, kid, secret := replicas(t, b)
	ctx := t.Context()
	pol := a.createPolicy(t, ctx, "refs", refPolicy)
	attach := func(user *iamv1.User) {
		t.Helper()
		if _, err := a.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
			User:       &iamv1.User{Name: user.GetName(), Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}}},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	alice, err := a.users.GetUser(ctx, &iamv1.GetUserRequest{Name: parentName + "/users/alice"})
	if err != nil {
		t.Fatal(err)
	}
	attach(alice)
	bob := a.createUser(t, ctx, "bob")
	attach(bob)
	bobKey, err := a.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: bob.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	bobKid := bobKey.GetAccessKey().GetName()[strings.LastIndex(bobKey.GetAccessKey().GetName(), "/")+1:]

	op, err := a.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
		Parent: parentName, RoleId: "deployer",
		Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: refTrust, AttachedPolicies: []string{pol.GetName()}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &refSessions{a: a, b: rb, kid: kid, sec: secret, role: unpack(t, op, &iamv1.Role{})}

	assume := func(name string) *iamv1.Credentials {
		t.Helper()
		r, err := a.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
			Authentication: arSig(a.stsSign(kid, secret, "", "AssumeRole")), Role: s.role.GetName(), RoleSessionName: name,
		})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetCredentials()
	}
	userToken := func(id, sec string) *iamv1.Credentials {
		t.Helper()
		sig := gstSig(a.stsSign(id, sec, "", "GetSessionToken"))
		r, err := a.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: sig})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetCredentials()
	}
	s.roleSess, s.roleSess2 = assume("s1"), assume("s2")
	s.userSess, s.bobSess = userToken(kid, secret), userToken(bobKid, bobKey.GetSecretAccessKey())
	s.rolePr, s.roleRef = s.authenticate(t, a, s.roleSess)
	s.rolePr2, s.roleRef2 = s.authenticate(t, a, s.roleSess2)
	s.userPr, s.userRef = s.authenticate(t, a, s.userSess)
	s.bobPr, s.bobRef = s.authenticate(t, a, s.bobSess)

	s.revokeUser = func(t *testing.T, e *env) {
		t.Helper()
		*a.now = a.now.Add(time.Second)
		if _, err := e.users.RevokeUserSessions(ctx, &iamv1.RevokeUserSessionsRequest{Name: alice.GetName()}); err != nil {
			t.Fatal(err)
		}
	}
	s.revokeRole = func(t *testing.T, e *env) {
		t.Helper()
		*a.now = a.now.Add(time.Second)
		if _, err := e.roles.RevokeRoleSessions(ctx, &iamv1.RevokeRoleSessionsRequest{Name: s.role.GetName()}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// authenticate is the gateway's Authenticate of an STS session: the
// principal it describes and the session reference.
func (s *refSessions) authenticate(t *testing.T, e *env, c *iamv1.Credentials) (*iamv1.Principal, string) {
	t.Helper()
	req := e.sign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken())
	resp, ref, err := e.api.AuthenticateRef(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if ref == "" {
		t.Fatal("an STS session has no reference")
	}
	return resp.GetPrincipal(), ref
}

func authorizeRef(t *testing.T, e *env, pr *iamv1.Principal, ref string) *iamv1.AuthorizeResponse {
	t.Helper()
	resp, err := e.api.AuthorizeRef(t.Context(), &iamv1.AuthorizeRequest{Principal: pr, Action: "s3:GetObject"}, ref)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func wantDecision(t *testing.T, resp *iamv1.AuthorizeResponse, want iamv1.Decision, reason string) {
	t.Helper()
	if resp.GetDecision() != want || !strings.Contains(resp.GetReason(), reason) {
		t.Fatalf("decision %v %q, want %v containing %q", resp.GetDecision(), resp.GetReason(), want, reason)
	}
}

// TestSessionRefMemstore runs the #20 suite on two replicas sharing one
// in-memory backend.
func TestSessionRefMemstore(t *testing.T) {
	testSessionRef(t, memstore.New())
}

func TestSessionRefEtcd(t *testing.T) {
	testSessionRef(t, etcdBackend(t))
}

func testSessionRef(t *testing.T, b store.Backend) {
	s := setupSessionRefs(t, b)
	ctx := t.Context()
	allow := iamv1.Decision_DECISION_ALLOW
	implicit := iamv1.Decision_DECISION_DENY_IMPLICIT

	// A long-term key has no reference, and Authorize without one is as before.
	resp, ref, err := s.a.api.AuthenticateRef(ctx, s.a.sign(s.kid, s.sec, ""))
	if err != nil || ref != "" {
		t.Fatalf("long-term key: ref %q, err %v", ref, err)
	}
	wantDecision(t, authorizeRef(t, s.a, resp.GetPrincipal(), ""), allow, "")

	// Before any revocation, every session is allowed on both replicas, as
	// many times as it is asked (checking a reference is stateless).
	for range 2 {
		for _, e := range []*env{s.a, s.b} {
			wantDecision(t, authorizeRef(t, e, s.rolePr, s.roleRef), allow, "")
			wantDecision(t, authorizeRef(t, e, s.userPr, s.userRef), allow, "")
		}
	}
	// A second Authenticate of the same session gives a reference just as good.
	_, again := s.authenticate(t, s.b, s.roleSess)
	wantDecision(t, authorizeRef(t, s.a, s.rolePr, again), allow, "")

	// A reference must describe the principal it travels with.
	for name, c := range map[string]struct {
		pr  *iamv1.Principal
		ref string
	}{
		"another session of the role":   {s.rolePr, s.roleRef2},
		"the first session for the 2nd": {s.rolePr2, s.roleRef},
		"a role reference for a user":   {s.userPr, s.roleRef},
		"a user reference for a role":   {s.rolePr, s.userRef},
		"another user's reference":      {s.userPr, s.bobRef},
		"the first user for the second": {s.bobPr, s.userRef},
	} {
		wantDecision(t, authorizeRef(t, s.b, c.pr, c.ref), implicit, "does not match the principal")
		if t.Failed() {
			t.Fatalf("%s was not refused", name)
		}
	}

	// An MFA claim needs a session issued with MFA, checked before the
	// device lookup.
	for _, pr := range []*iamv1.Principal{s.userPr, s.rolePr} {
		claim, ok := proto.Clone(pr).(*iamv1.Principal)
		if !ok {
			t.Fatal("clone")
		}
		claim.MfaAuthenticated = true
		ref := s.userRef
		if pr == s.rolePr {
			ref = s.roleRef
		}
		wantDecision(t, authorizeRef(t, s.a, claim, ref), implicit, "issued without MFA")
	}

	// A hostile reference is a refusal, not an allow and not a crash.
	tampered := []byte(s.roleRef)
	tampered[len(tampered)-2] ^= 1
	for name, ref := range map[string]string{
		"garbage":       "garbage",
		"dots":          "...",
		"too long":      strings.Repeat("A", 5000),
		"tampered":      string(tampered),
		"session token": s.roleSess.GetSessionToken(),
		"other key":     "k2." + s.roleRef[strings.LastIndexByte(s.roleRef, '.')+1:],
	} {
		wantDecision(t, authorizeRef(t, s.a, s.rolePr, ref), implicit, "session revoked or invalid")
		if t.Failed() {
			t.Fatalf("%s was not refused", name)
		}
	}

	// Revoking alice's sessions on B refuses her user session on every
	// replica and on a restarted one, and leaves the role session and bob's.
	s.revokeUser(t, s.b)
	restarted := newEnvOn(t, b, s.a.now)
	for _, e := range []*env{s.a, s.b, restarted} {
		wantDecision(t, authorizeRef(t, e, s.userPr, s.userRef), implicit, "session revoked or invalid")
		wantDecision(t, authorizeRef(t, e, s.rolePr, s.roleRef), allow, "")
		wantDecision(t, authorizeRef(t, e, s.bobPr, s.bobRef), allow, "")
	}

	// Revoking the role's sessions on A refuses both its sessions on B.
	s.revokeRole(t, s.a)
	for _, e := range []*env{s.a, s.b, restarted} {
		wantDecision(t, authorizeRef(t, e, s.rolePr, s.roleRef), implicit, "session revoked or invalid")
		wantDecision(t, authorizeRef(t, e, s.rolePr2, s.roleRef2), implicit, "session revoked or invalid")
		wantDecision(t, authorizeRef(t, e, s.bobPr, s.bobRef), allow, "")
	}

	// A session issued after the revocations is allowed.
	op, err := s.a.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
		Authentication: arSig(s.a.stsSign(s.kid, s.sec, "", "AssumeRole")), Role: s.role.GetName(), RoleSessionName: "s3",
	})
	if err != nil {
		t.Fatal(err)
	}
	pr, ref := s.authenticate(t, s.b, op.GetCredentials())
	wantDecision(t, authorizeRef(t, s.a, pr, ref), allow, "")

	// Past its expiry a session reference is refused, however fresh the principal.
	*s.a.now = s.a.now.Add(13 * time.Hour)
	wantDecision(t, authorizeRef(t, s.b, s.bobPr, s.bobRef), implicit, "session revoked or invalid")
}

// roleGetFailer fails the failAt-th Get of a role (counting from gets = 0).
type roleGetFailer struct {
	store.Backend
	gets, failAt atomic.Int32
}

func (f *roleGetFailer) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	var role iam.Role
	if kind == role.Kind() && f.gets.Add(1) == f.failAt.Load() {
		return store.Entry{}, errors.New("store down")
	}
	return f.Backend.Get(ctx, kind, key)
}

// TestSessionRefStoreFailureFailsClosed: when the store fails while the
// reference is checked (the second role read of the request, after Authorize
// itself read the role), the answer is an error, never an allow and never a
// revocation message that would hide an outage.
func TestSessionRefStoreFailureFailsClosed(t *testing.T) {
	f := &roleGetFailer{Backend: memstore.New()}
	s := setupSessionRefs(t, f)
	wantDecision(t, authorizeRef(t, s.a, s.rolePr, s.roleRef), iamv1.Decision_DECISION_ALLOW, "")

	f.gets.Store(0)
	f.failAt.Store(2)
	req := &iamv1.AuthorizeRequest{Principal: s.rolePr, Action: "s3:GetObject"}
	resp, err := s.a.api.AuthorizeRef(t.Context(), req, s.roleRef)
	if err == nil || resp != nil {
		t.Fatalf("store failure: %v %v", resp, err)
	}
	if got := f.gets.Load(); got != 2 {
		t.Fatalf("the failure hit read %d, want the reference check (2)", got)
	}
	f.failAt.Store(0)
	wantDecision(t, authorizeRef(t, s.a, s.rolePr, s.roleRef), iamv1.Decision_DECISION_ALLOW, "")
}
