package grpcapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/sigv4"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/totp"
)

const proj = "acme"

var parentName = "projects/" + proj

type env struct {
	users    iamv1.UserServiceClient
	groups   iamv1.GroupServiceClient
	roles    iamv1.RoleServiceClient
	policies iamv1.PolicyServiceClient
	keys     iamv1.AccessKeyServiceClient
	mfa      iamv1.MfaDeviceServiceClient
	auth     iamv1.AuthServiceClient
	token    iamv1.TokenServiceClient
	ops      longrunningpb.OperationsClient
	now      *time.Time
	nonce    int
	api      *grpcapi.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	now := time.Now().UTC()
	return newEnvOn(t, memstore.New(), &now)
}

// newEnvOn starts one server (one replica) on b. Envs built on the same
// b and clock act as replicas of one deployment.
func newEnvOn(t *testing.T, b store.Backend, now *time.Time) *env {
	t.Helper()
	keys, err := secret.NewKeyring("k1", map[string][]byte{"k1": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpcapi.ServerOptions()...)
	api := grpcapi.New(b, keys, grpcapi.WithClock(func() time.Time { return *now }))
	grpcapi.Register(srv, api)
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(grpcapi.ClientServiceConfig))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cc.Close(); err != nil {
			t.Error(err)
		}
	})
	return &env{
		users: iamv1.NewUserServiceClient(cc), groups: iamv1.NewGroupServiceClient(cc), roles: iamv1.NewRoleServiceClient(cc),
		policies: iamv1.NewPolicyServiceClient(cc), keys: iamv1.NewAccessKeyServiceClient(cc), mfa: iamv1.NewMfaDeviceServiceClient(cc),
		auth: iamv1.NewAuthServiceClient(cc), token: iamv1.NewTokenServiceClient(cc), ops: longrunningpb.NewOperationsClient(cc), now: now, api: api,
	}
}

func unpack[T proto.Message](t *testing.T, op *longrunningpb.Operation, out T) T {
	t.Helper()
	if !op.GetDone() || op.GetResponse() == nil {
		t.Fatalf("operation not done with a response: %v", op)
	}
	if err := op.GetResponse().UnmarshalTo(out); err != nil {
		t.Fatal(err)
	}
	return out
}

// wantErr checks the gRPC code, the ErrorInfo reason and the AWS code.
func wantErr(t *testing.T, err error, code codes.Code, reason, aws string) {
	t.Helper()
	st := status.Convert(err)
	if st.Code() != code {
		t.Fatalf("code %v, want %v (%v)", st.Code(), code, err)
	}
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			if ei.GetDomain() != grpcapi.ErrorDomain || ei.GetReason() != reason || ei.GetMetadata()[grpcapi.AWSCodeKey] != aws {
				t.Fatalf("ErrorInfo %v, want %s/%s", ei, reason, aws)
			}
			return
		}
	}
	t.Fatalf("no ErrorInfo in %v", err)
}

func (e *env) createUser(t *testing.T, ctx context.Context, n string) *iamv1.User {
	t.Helper()
	op, err := e.users.CreateUser(ctx, &iamv1.CreateUserRequest{Parent: parentName, UserId: n, User: &iamv1.User{Spec: &iamv1.UserSpec{}}})
	if err != nil {
		t.Fatal(err)
	}
	return unpack(t, op, &iamv1.User{})
}

func (e *env) createPolicy(t *testing.T, ctx context.Context, n, doc string) *iamv1.Policy {
	t.Helper()
	op, err := e.policies.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{Parent: parentName, PolicyId: n, Policy: &iamv1.Policy{Spec: &iamv1.PolicySpec{Document: doc}}})
	if err != nil {
		t.Fatal(err)
	}
	return unpack(t, op, &iamv1.Policy{})
}

func TestUserLifecycleAndOperations(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	req := &iamv1.CreateUserRequest{
		Parent: parentName, UserId: "alice", RequestId: "6f1c2d1e-0000-4000-8000-000000000001",
		User: &iamv1.User{Labels: map[string]string{"team": "a"}, Spec: &iamv1.UserSpec{Path: "/eng/"}},
	}

	// validate_only writes nothing.
	vreq := proto.CloneOf(req)
	vreq.ValidateOnly, vreq.RequestId = true, ""
	if _, err := e.users.CreateUser(ctx, vreq); err != nil {
		t.Fatal(err)
	}
	if _, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: parentName + "/users/alice"}); status.Code(err) != codes.NotFound {
		t.Fatalf("validate_only persisted: %v", err)
	}

	op1, err := e.users.CreateUser(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	u := unpack(t, op1, &iamv1.User{})
	if u.GetStatus().GetArn() != "arn:vws:iam::acme:user/eng/alice" || !strings.HasPrefix(u.GetStatus().GetUniqueId(), "AIDA") || u.GetGeneration() != 1 || u.GetEtag() == "" {
		t.Fatalf("user %v", u)
	}
	// Replay with the same request id returns the same operation.
	op2, err := e.users.CreateUser(ctx, req)
	if err != nil || op2.GetName() != op1.GetName() {
		t.Fatalf("replay: %v %v", op2.GetName(), err)
	}
	// Same request id, different request.
	other := proto.CloneOf(req)
	other.UserId = "bob"
	_, err = e.users.CreateUser(ctx, other)
	wantErr(t, err, codes.Aborted, "IDEMPOTENCY_CONFLICT", "IdempotentParameterMismatch")
	got, err := e.ops.GetOperation(ctx, &longrunningpb.GetOperationRequest{Name: op1.GetName()})
	if err != nil || !proto.Equal(got, op1) {
		t.Fatalf("GetOperation: %v", err)
	}
	_, err = e.ops.GetOperation(ctx, &longrunningpb.GetOperationRequest{Name: "projects/other/" + strings.SplitN(op1.GetName(), "/", 3)[2]})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")

	_, err = e.users.CreateUser(ctx, &iamv1.CreateUserRequest{Parent: parentName, UserId: "ALICE", User: &iamv1.User{Spec: &iamv1.UserSpec{}}})
	wantErr(t, err, codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
	_, err = e.users.CreateUser(ctx, &iamv1.CreateUserRequest{Parent: parentName, UserId: "bad name", User: &iamv1.User{Spec: &iamv1.UserSpec{}}})
	wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")

	// Update: stale etag, bad mask, then a labels-only update.
	_, err = e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{User: &iamv1.User{Name: u.GetName(), Etag: "stale"}})
	wantErr(t, err, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	_, err = e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{User: &iamv1.User{Name: u.GetName()}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"status"}}})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	op, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{User: &iamv1.User{Name: u.GetName(), Etag: u.GetEtag(), Labels: map[string]string{"team": "b"}}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}})
	if err != nil {
		t.Fatal(err)
	}
	u2 := unpack(t, op, &iamv1.User{})
	if u2.GetLabels()["team"] != "b" || u2.GetGeneration() != 2 || u2.GetSpec().GetPath() != "/eng/" {
		t.Fatalf("updated %v", u2)
	}

	// Pagination.
	for _, n := range []string{"carol", "bob", "dave"} {
		e.createUser(t, ctx, n)
	}
	var names []string
	tok := ""
	for {
		resp, err := e.users.ListUsers(ctx, &iamv1.ListUsersRequest{Parent: parentName, PageSize: 3, PageToken: tok})
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range resp.GetUsers() {
			names = append(names, x.GetName()[strings.LastIndex(x.GetName(), "/")+1:])
		}
		if tok = resp.GetNextPageToken(); tok == "" {
			break
		}
	}
	if strings.Join(names, ",") != "alice,bob,carol,dave" {
		t.Fatalf("pages %v", names)
	}
	_, err = e.users.ListUsers(ctx, &iamv1.ListUsersRequest{Parent: parentName, PageToken: "!!"})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")

	// Delete conflicts like AWS, then deletes.
	k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()})
	wantErr(t, err, codes.FailedPrecondition, "DEPENDENCY_MISSING", "DeleteConflict")
	if _, err := e.keys.DeleteAccessKey(ctx, &iamv1.DeleteAccessKeyRequest{Name: k.GetAccessKey().GetName()}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()}); err != nil {
		t.Fatal(err)
	}
	_, err = e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	if _, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName(), AllowMissing: true}); err != nil {
		t.Fatal(err)
	}
	_, err = e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: "users/x"})
	wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
}

func TestAccessKeysAndQuota(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	var first *iamv1.CreateAccessKeyResponse
	for i := range 2 {
		k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
		if err != nil {
			t.Fatal(err)
		}
		if len(k.GetSecretAccessKey()) != 40 || k.GetAccessKey().GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE {
			t.Fatalf("key %d: %v", i, k.GetAccessKey())
		}
		first = k
	}
	_, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
	op, err := e.keys.UpdateAccessKey(ctx, &iamv1.UpdateAccessKeyRequest{AccessKey: &iamv1.AccessKey{Name: first.GetAccessKey().GetName(), Spec: &iamv1.AccessKeySpec{State: iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE}}})
	if err != nil {
		t.Fatal(err)
	}
	if k := unpack(t, op, &iamv1.AccessKey{}); k.GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE || k.GetGeneration() != 2 {
		t.Fatalf("updated %v", k)
	}
	list, err := e.keys.ListAccessKeys(ctx, &iamv1.ListAccessKeysRequest{Parent: u.GetName()})
	if err != nil || len(list.GetAccessKeys()) != 2 {
		t.Fatalf("list %v %v", list, err)
	}
	// The secret is never in an operation or a read.
	if strings.Contains(op.String(), first.GetSecretAccessKey()) || strings.Contains(list.String(), first.GetSecretAccessKey()) {
		t.Fatal("secret leaked")
	}
	_, err = e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: parentName + "/users/bob/accessKeys/" + first.GetAccessKey().GetName()[len(u.GetName())+12:]})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
}

func TestAccessKeyExpectedUserPath(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	other := e.createUser(t, ctx, "bob")
	created, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	name := created.GetAccessKey().GetName()
	update := func(state iamv1.AccessKeyState, expected string, validateOnly bool) (*longrunningpb.Operation, error) {
		return e.keys.UpdateAccessKey(ctx, &iamv1.UpdateAccessKeyRequest{
			AccessKey:        &iamv1.AccessKey{Name: name, Spec: &iamv1.AccessKeySpec{State: state}},
			ExpectedUserPath: expected,
			ValidateOnly:     validateOnly,
		})
	}
	unchanged := func() {
		t.Helper()
		got, err := e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if got.GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE || got.GetGeneration() != 1 {
			t.Fatalf("key changed after a refused write: %v", got)
		}
	}

	// The caller authorized on another user or project must not change the key.
	for _, expected := range []string{other.GetName(), "projects/other/users/alice"} {
		_, err := update(iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE, expected, false)
		wantErr(t, err, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
		unchanged()
	}
	_, err = update(iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE, other.GetName(), true)
	wantErr(t, err, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
	unchanged()
	_, err = update(iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE, "alice", false)
	wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
	unchanged()

	// The key's own parent user path succeeds even with another case, because
	// IAM names fold. Omitting the field keeps the old behavior.
	op, err := update(iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE, parentName+"/users/ALICE", false)
	if err != nil {
		t.Fatal(err)
	}
	k := unpack(t, op, &iamv1.AccessKey{})
	if k.GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE || k.GetGeneration() != 2 {
		t.Fatalf("matched update: %v", k)
	}
	if _, err := update(iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE, "", false); err != nil {
		t.Fatalf("update without expected_user_path: %v", err)
	}

	// Delete applies the same precondition and deletes nothing on a mismatch.
	_, err = e.keys.DeleteAccessKey(ctx, &iamv1.DeleteAccessKeyRequest{Name: name, ExpectedUserPath: other.GetName()})
	wantErr(t, err, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
	if _, err := e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: name}); err != nil {
		t.Fatalf("mismatch deleted the key: %v", err)
	}
	del := &iamv1.DeleteAccessKeyRequest{Name: name, ExpectedUserPath: u.GetName()}
	if _, err := e.keys.DeleteAccessKey(ctx, del); err != nil {
		t.Fatal(err)
	}
	_, err = e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: name})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")

	// A second key is still deletable without the optional field, and a
	// missing key with allow_missing stays idempotent.
	second, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	plain := &iamv1.DeleteAccessKeyRequest{Name: second.GetAccessKey().GetName()}
	if _, err := e.keys.DeleteAccessKey(ctx, plain); err != nil {
		t.Fatal(err)
	}
	missing := &iamv1.DeleteAccessKeyRequest{Name: name, ExpectedUserPath: other.GetName(), AllowMissing: true}
	if _, err := e.keys.DeleteAccessKey(ctx, missing); err != nil {
		t.Fatalf("allow_missing delete after the key is gone: %v", err)
	}
}

func (e *env) sign(id, secretKey, token string) *iamv1.AuthenticateRequest {
	date := e.now.Format("20060102")
	amz := e.now.Format("20060102T150405Z")
	canonical := "GET\n/\n\nhost:s3.vws.local\nx-amz-date:" + amz + "\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	h := sha256.Sum256([]byte(canonical))
	sts := "AWS4-HMAC-SHA256\n" + amz + "\n" + date + "/kr-1/s3/aws4_request\n" + hex.EncodeToString(h[:])
	return &iamv1.AuthenticateRequest{
		AccessKeyId: id, Date: date, Region: "kr-1", Service: "s3", CanonicalRequest: canonical,
		StringToSign: sts, Signature: sigv4.Sign([]byte(secretKey), date, "kr-1", "s3", sts), SessionToken: token,
	}
}

// stsSign signs an STS request as a client would; console-api forwards
// it in the request's authentication oneof. Each call is a distinct
// request (fresh nonce), so the replay guard does not refuse it.
func (e *env) stsSign(id, secretKey, token, action string) *iamv1.AuthenticateRequest {
	e.nonce++
	date := e.now.Format("20060102")
	amz := e.now.Format("20060102T150405Z")
	canonical := "POST\n/\nAction=" + action + "&Nonce=" + strconv.Itoa(e.nonce) + "&Version=2011-06-15\nhost:sts.vws.local\nx-amz-date:" + amz + "\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	h := sha256.Sum256([]byte(canonical))
	sts := "AWS4-HMAC-SHA256\n" + amz + "\n" + date + "/kr-1/sts/aws4_request\n" + hex.EncodeToString(h[:])
	return &iamv1.AuthenticateRequest{
		AccessKeyId: id, Date: date, Region: "kr-1", Service: "sts", CanonicalRequest: canonical,
		StringToSign: sts, Signature: sigv4.Sign([]byte(secretKey), date, "kr-1", "sts", sts), SessionToken: token,
	}
}

func gstSig(r *iamv1.AuthenticateRequest) *iamv1.GetSessionTokenRequest_Sigv4 {
	return &iamv1.GetSessionTokenRequest_Sigv4{Sigv4: r}
}

func arSig(r *iamv1.AuthenticateRequest) *iamv1.AssumeRoleRequest_Sigv4 {
	return &iamv1.AssumeRoleRequest_Sigv4{Sigv4: r}
}

func TestAuthenticateAuthorize(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	pol := e.createPolicy(t, ctx, "s3read", `{"Version":"2012-10-17","Statement":[
		{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
		{"Sid":"NoSecret","Effect":"Deny","Action":"s3:GetObject","Resource":"arn:vws:s3:::secret/*"},
		{"Sid":"NeedMFA","Effect":"Allow","Action":"s3:DeleteObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`)
	if _, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: u.GetName(), Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
	}); err != nil {
		t.Fatal(err)
	}
	k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	id := k.GetAccessKey().GetName()[strings.LastIndex(k.GetAccessKey().GetName(), "/")+1:]

	resp, err := e.auth.Authenticate(ctx, e.sign(id, k.GetSecretAccessKey(), ""))
	if err != nil {
		t.Fatal(err)
	}
	pr := resp.GetPrincipal()
	if resp.GetAccount() != proj || resp.GetArn() != "arn:vws:iam::acme:user/alice" || pr.GetType() != iamv1.PrincipalType_PRINCIPAL_TYPE_USER || pr.GetUniqueId() != u.GetStatus().GetUniqueId() {
		t.Fatalf("authenticate %v", resp)
	}
	bad := e.sign(id, k.GetSecretAccessKey(), "")
	bad.Signature = strings.Repeat("0", 64)
	_, err = e.auth.Authenticate(ctx, bad)
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "SignatureDoesNotMatch")
	_, err = e.auth.Authenticate(ctx, e.sign("AKIAAAAAAAAAAAAAAAAA", k.GetSecretAccessKey(), ""))
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
	*e.now = e.now.Add(time.Hour)
	stale := e.sign(id, k.GetSecretAccessKey(), "")
	*e.now = e.now.Add(-time.Hour)
	_, err = e.auth.Authenticate(ctx, stale)
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "RequestTimeTooSkewed")
	got, err := e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: k.GetAccessKey().GetName()})
	if err != nil || got.GetStatus().GetLastUsedService() != "s3" {
		t.Fatalf("last used not recorded: %v %v", got.GetStatus(), err)
	}

	authorize := func(pr *iamv1.Principal, action string, res []string, c map[string]*iamv1.ContextValues) *iamv1.AuthorizeResponse {
		t.Helper()
		r, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: pr, Action: action, Resources: res, Context: c})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := authorize(pr, "s3:GetObject", []string{"arn:vws:s3:::pub/a"}, nil); r.GetDecision() != iamv1.Decision_DECISION_ALLOW || r.GetMatchedStatement() != "Read" {
		t.Fatalf("allow: %v", r)
	}
	if r := authorize(pr, "s3:GetObject", []string{"arn:vws:s3:::pub/a", "arn:vws:s3:::secret/b"}, nil); r.GetDecision() != iamv1.Decision_DECISION_DENY_EXPLICIT || r.GetMatchedStatement() != "NoSecret" {
		t.Fatalf("explicit deny across resources: %v", r)
	}
	if r := authorize(pr, "s3:PutObject", nil, nil); r.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT {
		t.Fatalf("implicit: %v", r)
	}
	// A client cannot set server-owned keys.
	forged := map[string]*iamv1.ContextValues{"aws:MultiFactorAuthPresent": {Values: []string{"true"}}}
	if r := authorize(pr, "s3:DeleteObject", nil, forged); r.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT {
		t.Fatalf("forged MFA context honored: %v", r)
	}
	// An MFA claim without an enabled device is rejected by the recheck.
	mfaClaim := proto.CloneOf(pr)
	mfaClaim.MfaAuthenticated = true
	if r := authorize(mfaClaim, "s3:DeleteObject", nil, nil); r.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT || !strings.Contains(r.GetReason(), "MFA") {
		t.Fatalf("MFA claim: %v", r)
	}
	// A forged identity is rejected.
	forgedID := proto.CloneOf(pr)
	forgedID.UniqueId = "AIDAXXXXXXXXXXXXXXXXX"
	if r := authorize(forgedID, "s3:GetObject", nil, nil); r.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT {
		t.Fatalf("forged principal: %v", r)
	}
	_, err = e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: pr, Action: "nocolon"})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")

	// The attached policy cannot be deleted.
	_, err = e.policies.DeletePolicy(ctx, &iamv1.DeletePolicyRequest{Name: pol.GetName()})
	wantErr(t, err, codes.FailedPrecondition, "DEPENDENCY_MISSING", "DeleteConflict")
}

func enableMFA(t *testing.T, e *env, ctx context.Context, user string) string {
	t.Helper()
	d, err := e.mfa.CreateVirtualMfaDevice(ctx, &iamv1.CreateVirtualMfaDeviceRequest{Parent: parentName, MfaDeviceId: user + "-phone", MfaDevice: &iamv1.MfaDevice{}})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(d.GetBase32StringSeed())
	if err != nil {
		t.Fatal(err)
	}
	step := totp.Step(*e.now)
	if _, err := e.mfa.EnableMfaDevice(ctx, &iamv1.EnableMfaDeviceRequest{
		Name: d.GetMfaDevice().GetName(), User: parentName + "/users/" + user,
		AuthenticationCode_1: totp.Code(seed, step-1, totp.Digits), AuthenticationCode_2: totp.Code(seed, step, totp.Digits),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: d.GetMfaDevice().GetName()})
	if err != nil || got.GetStatus().GetUser() != parentName+"/users/"+user || got.GetStatus().GetEnableTime() == nil {
		t.Fatalf("device %v %v", got, err)
	}
	*e.now = e.now.Add(30 * time.Second)
	return d.GetBase32StringSeed() + "|" + got.GetStatus().GetSerialNumber()
}

func code(t *testing.T, e *env, seedB32 string) string {
	t.Helper()
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seedB32)
	if err != nil {
		t.Fatal(err)
	}
	return totp.Code(seed, totp.Step(*e.now), totp.Digits)
}

func TestLoginMFAAndSessions(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	_, err := e.users.SetLoginProfile(ctx, &iamv1.SetLoginProfileRequest{Name: u.GetName(), Password: "short"})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	if _, err := e.users.SetLoginProfile(ctx, &iamv1.SetLoginProfileRequest{Name: u.GetName(), Password: "correct horse battery"}); err != nil {
		t.Fatal(err)
	}
	_, err = e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: "wrong password!"})
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
	_, err = e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "nobody", Password: "correct horse battery"})
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
	l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: "correct horse battery"})
	if err != nil || l.GetPrincipal().GetMfaAuthenticated() || len(l.GetSessionToken()) < 40 {
		t.Fatalf("login %v %v", l, err)
	}

	pair := strings.SplitN(enableMFA(t, e, ctx, "alice"), "|", 2)
	seed, serial := pair[0], pair[1]
	_, err = e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()})
	wantErr(t, err, codes.FailedPrecondition, "DEPENDENCY_MISSING", "DeleteConflict")
	_, err = e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: "correct horse battery"})
	wantErr(t, err, codes.Unauthenticated, "MFA_REQUIRED", "MultiFactorAuthenticationRequired")
	_, err = e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: "correct horse battery", TotpCode: "000000"})
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidAuthenticationCode")
	l, err = e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: "correct horse battery", TotpCode: code(t, e, seed)})
	if err != nil || !l.GetPrincipal().GetMfaAuthenticated() {
		t.Fatalf("mfa login %v %v", l, err)
	}
	v, err := e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()})
	if err != nil || v.GetPrincipal().GetArn() != "arn:vws:iam::acme:user/alice" || !v.GetPrincipal().GetMfaAuthenticated() {
		t.Fatalf("validate %v %v", v, err)
	}
	// The MFA principal from the session passes the Authorize recheck.
	r, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: v.GetPrincipal(), Action: "s3:GetObject"})
	if err != nil || strings.Contains(r.GetReason(), "principal rejected") {
		t.Fatalf("authorize session principal %v %v", r, err)
	}
	// GetSessionToken with MFA.
	*e.now = e.now.Add(30 * time.Second)
	// The caller comes from the session, not from the request (vws-proto#28).
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Caller: l.GetPrincipal()}) //nolint:staticcheck // proves the deprecated caller field is ignored
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken")
	// An IAM user's console session is not a long-term credential: only
	// the root user may call GetSessionToken with a console session.
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: &iamv1.GetSessionTokenRequest_ConsoleSessionToken{ConsoleSessionToken: l.GetSessionToken()}, SerialNumber: serial, TokenCode: code(t, e, seed)})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
	// The MFA code is verified server-side: a wrong one is refused.
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")), SerialNumber: serial, TokenCode: "000000"})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	st, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")), SerialNumber: serial, TokenCode: code(t, e, seed)})
	if err != nil || !strings.HasPrefix(st.GetCredentials().GetAccessKeyId(), "ASIA") {
		t.Fatalf("session token %v", err)
	}
	a, err := e.auth.Authenticate(ctx, e.sign(st.GetCredentials().GetAccessKeyId(), st.GetCredentials().GetSecretAccessKey(), st.GetCredentials().GetSessionToken()))
	if err != nil || !a.GetPrincipal().GetMfaAuthenticated() || a.GetExpireTime() == nil {
		t.Fatalf("authenticate session %v %v", a, err)
	}
	_, err = e.auth.Authenticate(ctx, e.sign(st.GetCredentials().GetAccessKeyId(), st.GetCredentials().GetSecretAccessKey(), ""))
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken")
	// Temporary credentials cannot call GetSessionToken (AWS rule), now detectable.
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(e.stsSign(st.GetCredentials().GetAccessKeyId(), st.GetCredentials().GetSecretAccessKey(), st.GetCredentials().GetSessionToken(), "GetSessionToken"))})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")

	if _, err := e.auth.Logout(ctx, &iamv1.LogoutRequest{SessionToken: l.GetSessionToken()}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.Logout(ctx, &iamv1.LogoutRequest{SessionToken: l.GetSessionToken()}); err != nil {
		t.Fatal("logout not idempotent:", err)
	}
	_, err = e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()})
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")

	if _, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: "correct horse battery", TotpCode: code(t, e, seed)}); err == nil {
		t.Fatal("TOTP code replayed in the same step")
	}
	*e.now = e.now.Add(13 * time.Hour)
	_, err = e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: "unknown"})
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
}

func TestAssumeRole(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	pol := e.createPolicy(t, ctx, "assume", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`)
	if _, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: u.GetName(), Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
	}); err != nil {
		t.Fatal(err)
	}
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:vws:iam::acme:user/alice"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"ext-1"}}}]}`
	op, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{Parent: parentName, RoleId: "deployer", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}}})
	if err != nil {
		t.Fatal(err)
	}
	role := unpack(t, op, &iamv1.Role{})
	caller := &iamv1.Principal{Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: u.GetStatus().GetArn(), Project: proj, UniqueId: u.GetStatus().GetUniqueId(), Resource: u.GetName()}
	key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
	alice := func() *iamv1.AssumeRoleRequest_Sigv4 {
		return arSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "AssumeRole"))
	}

	// A caller field alone authenticates nothing (vws-proto#28).
	_, err = e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Role: role.GetName(), Caller: caller, RoleSessionName: "s1", ExternalId: "ext-1"}) //nolint:staticcheck // proves the deprecated caller field is ignored
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken")
	// A bad signature in the forwarded request is rejected by vws-iam itself.
	_, err = e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Authentication: arSig(e.stsSign(kid, strings.Repeat("x", 40), "", "AssumeRole")), Role: role.GetName(), RoleSessionName: "s1", ExternalId: "ext-1"})
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "SignatureDoesNotMatch")
	// Signed as mallory but claiming alice: the caller field is ignored, so
	// mallory is the caller and the trust policy (alice only) refuses her.
	mallory := e.createUser(t, ctx, "mallory")
	mkey, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: mallory.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	mkid := mkey.GetAccessKey().GetName()[strings.LastIndex(mkey.GetAccessKey().GetName(), "/")+1:]
	_, err = e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Authentication: arSig(e.stsSign(mkid, mkey.GetSecretAccessKey(), "", "AssumeRole")), Role: role.GetName(), Caller: caller, RoleSessionName: "s1", ExternalId: "ext-1"}) //nolint:staticcheck // proves the deprecated caller field is ignored
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")

	_, err = e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Authentication: alice(), Role: role.GetName(), RoleSessionName: "s1"})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	resp, err := e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Authentication: alice(), Role: role.GetName(), Caller: caller, RoleSessionName: "s1", ExternalId: "ext-1"}) //nolint:staticcheck // proves the deprecated caller field is ignored
	if err != nil {
		t.Fatal(err)
	}
	ar := resp.GetAssumedRoleUser()
	if ar.GetArn() != "arn:vws:sts::acme:assumed-role/deployer/s1" || ar.GetUniqueId() != role.GetStatus().GetUniqueId()+":s1" {
		t.Fatalf("assumed %v", ar)
	}
	c := resp.GetCredentials()
	if d := c.GetExpireTime().AsTime().Sub(*e.now); d > time.Hour || d < time.Hour-time.Second {
		t.Fatalf("default duration %v", c.GetExpireTime().AsTime().Sub(*e.now))
	}
	a, err := e.auth.Authenticate(ctx, e.sign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken()))
	if err != nil || a.GetPrincipal().GetType() != iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE || a.GetArn() != ar.GetArn() {
		t.Fatalf("authenticate role session %v %v", a, err)
	}
	r, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: a.GetPrincipal(), Action: "s3:GetObject"})
	if err != nil || r.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT || strings.Contains(r.GetReason(), "rejected") {
		t.Fatalf("role authorize %v %v", r, err)
	}
	// Cross-project and role sessions of a recreated role are refused.
	_, err = e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Authentication: alice(), Role: "projects/other/roles/deployer", RoleSessionName: "s1", ExternalId: "ext-1"})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	if _, err := e.roles.DeleteRole(ctx, &iamv1.DeleteRoleRequest{Name: role.GetName()}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{Parent: parentName, RoleId: "deployer", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}}}); err != nil {
		t.Fatal(err)
	}
	_, err = e.auth.Authenticate(ctx, e.sign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken()))
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
}

func TestGroupsAndPolicyVersions(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.createUser(t, ctx, "alice")
	op, err := e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{Parent: parentName, GroupId: "devs", Group: &iamv1.Group{Spec: &iamv1.GroupSpec{Members: []string{parentName + "/users/alice"}}}})
	if err != nil {
		t.Fatal(err)
	}
	g := unpack(t, op, &iamv1.Group{})
	u, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: parentName + "/users/alice"})
	if err != nil || len(u.GetStatus().GetGroups()) != 1 || u.GetStatus().GetGroups()[0] != g.GetName() {
		t.Fatalf("membership %v %v", u.GetStatus(), err)
	}
	_, err = e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{Parent: parentName, GroupId: "ops", Group: &iamv1.Group{Spec: &iamv1.GroupSpec{Members: []string{parentName + "/users/ghost"}}}})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	_, err = e.groups.DeleteGroup(ctx, &iamv1.DeleteGroupRequest{Name: g.GetName()})
	wantErr(t, err, codes.FailedPrecondition, "DEPENDENCY_MISSING", "DeleteConflict")

	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	_, err = e.policies.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{Parent: parentName, PolicyId: "bad", Policy: &iamv1.Policy{Spec: &iamv1.PolicySpec{Document: "{"}}})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "MalformedPolicyDocument")
	pol := e.createPolicy(t, ctx, "p", doc)
	for i := 2; i <= 5; i++ {
		op, err := e.policies.CreatePolicyVersion(ctx, &iamv1.CreatePolicyVersionRequest{Parent: pol.GetName(), PolicyVersion: &iamv1.PolicyVersion{Spec: &iamv1.PolicyVersionSpec{Document: doc, SetAsDefault: i == 5}}})
		if err != nil {
			t.Fatal(err)
		}
		if v := unpack(t, op, &iamv1.PolicyVersion{}); !strings.HasSuffix(v.GetName(), "/versions/v"+string(rune('0'+i))) {
			t.Fatalf("version name %s", v.GetName())
		}
	}
	_, err = e.policies.CreatePolicyVersion(ctx, &iamv1.CreatePolicyVersionRequest{Parent: pol.GetName(), PolicyVersion: &iamv1.PolicyVersion{Spec: &iamv1.PolicyVersionSpec{Document: doc}}})
	wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
	_, err = e.policies.DeletePolicyVersion(ctx, &iamv1.DeletePolicyVersionRequest{Name: pol.GetName() + "/versions/v5"})
	wantErr(t, err, codes.FailedPrecondition, "DEPENDENCY_MISSING", "DeleteConflict")
	if _, err := e.policies.DeletePolicyVersion(ctx, &iamv1.DeletePolicyVersionRequest{Name: pol.GetName() + "/versions/v1"}); err != nil {
		t.Fatal(err)
	}
	vs, err := e.policies.ListPolicyVersions(ctx, &iamv1.ListPolicyVersionsRequest{Parent: pol.GetName()})
	if err != nil || len(vs.GetPolicyVersions()) != 4 {
		t.Fatalf("versions %v %v", vs, err)
	}
	_, err = e.policies.UpdatePolicy(ctx, &iamv1.UpdatePolicyRequest{Policy: &iamv1.Policy{Name: pol.GetName(), Spec: &iamv1.PolicySpec{Document: `{"Version":"2012-10-17","Statement":[]}`}}})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	tooMany := make([]string, 11)
	for i := range tooMany {
		tooMany[i] = pol.GetName()
	}
	_, err = e.groups.UpdateGroup(ctx, &iamv1.UpdateGroupRequest{Group: &iamv1.Group{Name: g.GetName(), Spec: &iamv1.GroupSpec{AttachedPolicies: tooMany}}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}}})
	wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
}

type flaky struct {
	longrunningpb.UnimplementedOperationsServer
	calls int
}

func (f *flaky) GetOperation(context.Context, *longrunningpb.GetOperationRequest) (*longrunningpb.Operation, error) {
	f.calls++
	if f.calls < 3 {
		return nil, status.Error(codes.Unavailable, "try again")
	}
	return &longrunningpb.Operation{Name: "ok", Done: true}, nil
}

// TestClientServiceConfigRetries checks the published service config:
// UNAVAILABLE is retried transparently.
func TestClientServiceConfigRetries(t *testing.T) {
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	f := &flaky{}
	longrunningpb.RegisterOperationsServer(srv, f)
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(grpcapi.ClientServiceConfig))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := cc.Close(); err != nil {
			t.Error(err)
		}
	}()
	op, err := longrunningpb.NewOperationsClient(cc).GetOperation(t.Context(), &longrunningpb.GetOperationRequest{Name: "x"})
	if err != nil || op.GetName() != "ok" || f.calls != 3 {
		t.Fatalf("op=%v err=%v calls=%d", op, err, f.calls)
	}
}

// TestSTSAuthenticationOneof covers vws-proto v0.3.0 and the follow-ups of
// #30: the caller comes only from the authentication oneof, a missing one
// is UNAUTHENTICATED, and a forwarded SigV4 request cannot be replayed for
// another service or action, reused, or used outside the X-Amz-Date window.
func TestSTSAuthenticationOneof(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
	secret := key.GetSecretAccessKey()
	caller := &iamv1.Principal{Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: u.GetStatus().GetArn(), Project: proj, UniqueId: u.GetStatus().GetUniqueId(), Resource: u.GetName()}

	// Missing authentication: UNAUTHENTICATED, even with a caller field.
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Caller: caller}) //nolint:staticcheck // proves the deprecated caller field is ignored
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken")
	_, err = e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Role: parentName + "/roles/r", Caller: caller, RoleSessionName: "s1"}) //nolint:staticcheck // proves the deprecated caller field is ignored
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken")

	// Signed for another service (s3) or another STS action.
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(e.sign(kid, secret, ""))})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(e.stsSign(kid, secret, "", "AssumeRole"))})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")

	// The same signed request works once; a replay is refused.
	signed := e.stsSign(kid, secret, "", "GetSessionToken")
	if _, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(signed)}); err != nil {
		t.Fatal(err)
	}
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(signed)})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")

	// Outside the X-Amz-Date window.
	stale := e.stsSign(kid, secret, "", "GetSessionToken")
	*e.now = e.now.Add(16 * time.Minute)
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(stale)})
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "RequestTimeTooSkewed")
}

// TestSTSMFAIsVerifiedAndLocksOut checks that SerialNumber/TokenCode are
// verified server-side through internal/mfa, including its lockout.
func TestSTSMFAIsVerifiedAndLocksOut(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	seed, serial, _ := strings.Cut(enableMFA(t, e, ctx, "alice"), "|")
	key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
	gst := func(code string) error {
		_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
			SerialNumber: serial, TokenCode: code,
			Authentication: gstSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")),
		})
		return err
	}
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
		SerialNumber:   serial,
		Authentication: gstSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")),
	})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	for range 5 {
		wantErr(t, gst("000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	}
	// Locked: even the right code is refused.
	wantErr(t, gst(code(t, e, seed)), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	*e.now = e.now.Add(15 * time.Minute)
	if err := gst(code(t, e, seed)); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
}

// TestMfaSerialIncludesPath: a virtual MFA device created with a path has
// that path in its serial number (vws.iam.v1.MfaDeviceSpec.path), and STS
// resolves the full serial, not just the final name, back to the device.
func TestMfaSerialIncludesPath(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	const want = "arn:vws:iam::acme:mfa/team/alice-phone"
	d, err := e.mfa.CreateVirtualMfaDevice(ctx, &iamv1.CreateVirtualMfaDeviceRequest{
		Parent: parentName, MfaDeviceId: "alice-phone",
		MfaDevice: &iamv1.MfaDevice{Spec: &iamv1.MfaDeviceSpec{Path: "/team/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.GetMfaDevice().GetStatus().GetSerialNumber(); got != want {
		t.Fatalf("create serial_number = %q, want %q", got, want)
	}
	got, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: d.GetMfaDevice().GetName()})
	if err != nil || got.GetStatus().GetSerialNumber() != want {
		t.Fatalf("get serial_number = %q, want %q: %v", got.GetStatus().GetSerialNumber(), want, err)
	}
	list, err := e.mfa.ListMfaDevices(ctx, &iamv1.ListMfaDevicesRequest{Parent: parentName})
	if err != nil || len(list.GetMfaDevices()) != 1 || list.GetMfaDevices()[0].GetStatus().GetSerialNumber() != want {
		t.Fatalf("list serial_number: %v %v", list, err)
	}

	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(d.GetBase32StringSeed())
	if err != nil {
		t.Fatal(err)
	}
	step := totp.Step(*e.now)
	if _, err := e.mfa.EnableMfaDevice(ctx, &iamv1.EnableMfaDeviceRequest{
		Name: d.GetMfaDevice().GetName(), User: u.GetName(),
		AuthenticationCode_1: totp.Code(seed, step-1, totp.Digits), AuthenticationCode_2: totp.Code(seed, step, totp.Digits),
	}); err != nil {
		t.Fatal(err)
	}
	*e.now = e.now.Add(30 * time.Second)
	u, err = e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: u.GetName()})
	if err != nil || len(u.GetStatus().GetMfaDevices()) != 1 || u.GetStatus().GetMfaDevices()[0] != want {
		t.Fatalf("user mfa devices = %v: %v", u.GetStatus().GetMfaDevices(), err)
	}

	key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
	session := func(serial string) error {
		_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
			SerialNumber: serial, TokenCode: code(t, e, d.GetBase32StringSeed()),
			Authentication: gstSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")),
		})
		return err
	}
	wantErr(t, session("arn:vws:iam::acme:mfa/other/alice-phone"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	if err := session(want); err != nil {
		t.Fatalf("path serial: %v", err)
	}
}

// TestConsoleSessionAuthentication: a user's console session may assume a
// role (its MFA carried over) but may not call GetSessionToken (root-only).
func TestConsoleSessionAuthentication(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	pol := e.createPolicy(t, ctx, "assume", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`)
	if _, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: u.GetName(), Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.users.SetLoginProfile(ctx, &iamv1.SetLoginProfileRequest{Name: u.GetName(), Password: "correct horse battery"}); err != nil {
		t.Fatal(err)
	}
	seed, _, _ := strings.Cut(enableMFA(t, e, ctx, "alice"), "|")
	l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: "correct horse battery", TotpCode: code(t, e, seed)})
	if err != nil {
		t.Fatal(err)
	}
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:vws:iam::acme:user/alice"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}]}`
	op, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{Parent: parentName, RoleId: "admin", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}}})
	if err != nil {
		t.Fatal(err)
	}
	role := unpack(t, op, &iamv1.Role{})
	console := &iamv1.AssumeRoleRequest_ConsoleSessionToken{ConsoleSessionToken: l.GetSessionToken()}
	resp, err := e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Role: role.GetName(), RoleSessionName: "s1", Authentication: console})
	if err != nil || !resp.GetAssumedRoleUser().GetMfaAuthenticated() {
		t.Fatalf("console assume %v %v", resp, err)
	}
	_, err = e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: &iamv1.GetSessionTokenRequest_ConsoleSessionToken{ConsoleSessionToken: l.GetSessionToken()}})
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	// After logout the token authenticates nothing.
	if _, err := e.auth.Logout(ctx, &iamv1.LogoutRequest{SessionToken: l.GetSessionToken()}); err != nil {
		t.Fatal(err)
	}
	_, err = e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{Role: role.GetName(), RoleSessionName: "s1", Authentication: console})
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
}

// TestMfaDeviceLockoutStatus: GetMfaDevice and ListMfaDevices report the
// stored failed-attempt count and, only while it runs, the lockout
// (vws-proto#32).
func TestMfaDeviceLockoutStatus(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	seed, serial, _ := strings.Cut(enableMFA(t, e, ctx, "alice"), "|")
	key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
	gst := func(code string) error {
		_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
			SerialNumber: serial, TokenCode: code,
			Authentication: gstSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")),
		})
		return err
	}
	dev := parentName + "/mfaDevices/alice-phone"
	status := func(want int32, locked time.Time) {
		t.Helper()
		d, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: dev})
		if err != nil {
			t.Fatal(err)
		}
		l, err := e.mfa.ListMfaDevices(ctx, &iamv1.ListMfaDevicesRequest{Parent: parentName})
		if err != nil || len(l.GetMfaDevices()) != 1 {
			t.Fatalf("list %v %v", l, err)
		}
		for _, st := range []*iamv1.MfaDeviceStatus{d.GetStatus(), l.GetMfaDevices()[0].GetStatus()} {
			if st.GetFailedAttempts() != want {
				t.Fatalf("failed_attempts %d, want %d", st.GetFailedAttempts(), want)
			}
			if locked.IsZero() != (st.GetLockedUntil() == nil) || (!locked.IsZero() && !st.GetLockedUntil().AsTime().Equal(locked)) {
				t.Fatalf("locked_until %v, want %v", st.GetLockedUntil(), locked)
			}
		}
	}
	status(0, time.Time{})
	wantErr(t, gst("000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	status(1, time.Time{})
	// Neither the seed nor a current code is exposed by Get or List.
	d, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: dev})
	if err != nil {
		t.Fatal(err)
	}
	l, err := e.mfa.ListMfaDevices(ctx, &iamv1.ListMfaDevicesRequest{Parent: parentName})
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{prototext.Format(d), prototext.Format(l)} {
		if strings.Contains(out, seed) || strings.Contains(out, code(t, e, seed)) {
			t.Fatalf("MFA device output exposes a seed or code: %s", out)
		}
	}
	for range 4 {
		wantErr(t, gst("000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	}
	// The 5th failure locks for 15 minutes and starts a new count.
	status(0, e.now.Add(15*time.Minute))
	*e.now = e.now.Add(15*time.Minute + time.Second)
	status(0, time.Time{})
	if err := gst(code(t, e, seed)); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
}

func TestCreatePolicyNameLength(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	t.Run("128", func(t *testing.T) {
		ctx := t.Context()
		now := time.Now().UTC()
		b := memstore.New()
		e := newEnvOn(t, b, &now)
		name := strings.Repeat("a", 128)
		req := &iamv1.CreatePolicyRequest{
			Parent: parentName, PolicyId: name, RequestId: "6f1c2d1e-0000-4000-8000-000000000128",
			Policy: &iamv1.Policy{Spec: &iamv1.PolicySpec{Document: doc}},
		}
		op1, err := e.policies.CreatePolicy(ctx, req)
		if err != nil {
			t.Fatalf("128-character policy: %v", err)
		}
		pol := unpack(t, op1, &iamv1.Policy{})
		if pol.GetName() != parentName+"/policies/"+name {
			t.Fatalf("name %q", pol.GetName())
		}
		if pol.GetStatus().GetArn() != "arn:vws:iam::acme:policy/"+name {
			t.Fatalf("arn %q", pol.GetStatus().GetArn())
		}
		op2, err := e.policies.CreatePolicy(ctx, req)
		if err != nil || op2.GetName() != op1.GetName() {
			t.Fatalf("replay: %v %v", op2.GetName(), err)
		}
		e2 := newEnvOn(t, b, &now)
		got, err := e2.policies.GetPolicy(ctx, &iamv1.GetPolicyRequest{Name: parentName + "/policies/" + name})
		if err != nil {
			t.Fatalf("second server: %v", err)
		}
		if got.GetStatus().GetArn() != "arn:vws:iam::acme:policy/"+name {
			t.Fatalf("second server arn %q", got.GetStatus().GetArn())
		}
		u := e.createUser(t, ctx, "alice")
		if _, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
			User:       &iamv1.User{Name: u.GetName(), Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}}},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
		}); err != nil {
			t.Fatal(err)
		}
		stored, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: u.GetName()})
		if err != nil {
			t.Fatal(err)
		}
		if n := stored.GetSpec().GetAttachedPolicies(); len(n) != 1 || n[0] != pol.GetName() {
			t.Fatalf("attached %q", n)
		}
	})
	t.Run("rejected", func(t *testing.T) {
		e := newEnv(t)
		ctx := t.Context()
		for _, id := range []string{strings.Repeat("b", 129), "", "bad name"} {
			_, err := e.policies.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
				Parent: parentName, PolicyId: id, Policy: &iamv1.Policy{Spec: &iamv1.PolicySpec{Document: doc}},
			})
			wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
			want := `policy id "` + id + `" must match [A-Za-z0-9+=,.@_-]{1,128}`
			if got := status.Convert(err).Message(); got != want {
				t.Errorf("message %q, want %q", got, want)
			}
		}
		u := e.createUser(t, ctx, "alice")
		userID := strings.Repeat("u", 65)
		_, err := e.users.CreateUser(ctx, &iamv1.CreateUserRequest{
			Parent: parentName, UserId: userID, User: &iamv1.User{Spec: &iamv1.UserSpec{}},
		})
		wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
		if got, want := status.Convert(err).Message(), `user id "`+userID+`" must match [A-Za-z0-9+=,.@_-]{1,64}`; got != want {
			t.Errorf("message %q, want %q", got, want)
		}
		inline := strings.Repeat("p", 65)
		_, err = e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
			User:       &iamv1.User{Name: u.GetName(), Spec: &iamv1.UserSpec{InlinePolicies: map[string]string{inline: doc}}},
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.inline_policies"}},
		})
		wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
		if got, want := status.Convert(err).Message(), `inline policy name "`+inline+`"`; got != want {
			t.Errorf("message %q, want %q", got, want)
		}
	})
}
