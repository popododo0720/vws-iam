package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const mfaAgePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
 "Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}}]}`

// TestSessionRefBindsAuthTime: a reference vouches only for the auth_time its
// session was issued with, so a rewritten auth_time cannot reset
// aws:MultiFactorAuthAge.
func TestSessionRefBindsAuthTime(t *testing.T) {
	a, _, kid, sec := replicas(t, memstore.New())
	ctx := t.Context()
	pol := a.createPolicy(t, ctx, "age", mfaAgePolicy)
	if _, err := a.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
		User: &iamv1.User{
			Name: parentName + "/users/alice", Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}},
		},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
	}); err != nil {
		t.Fatal(err)
	}
	dev := enableMFA(t, a, ctx, "alice")
	seed, serial, _ := strings.Cut(dev, "|")
	r, err := a.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
		Authentication: gstSig(a.stsSign(kid, sec, "", "GetSessionToken")), SerialNumber: serial, TokenCode: code(t, a, seed),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := r.GetCredentials()
	resp, ref, err := a.api.AuthenticateRef(ctx, a.sign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken()))
	if err != nil || ref == "" {
		t.Fatalf("authenticate: %v %q", err, ref)
	}
	pr := resp.GetPrincipal()
	got := func(p *iamv1.Principal) *iamv1.AuthorizeResponse {
		out, err := a.api.AuthorizeRef(ctx, &iamv1.AuthorizeRequest{Principal: p, Action: "s3:GetObject"}, ref)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	wantDecision(t, got(pr), iamv1.Decision_DECISION_ALLOW, "")
	*a.now = a.now.Add(2 * time.Hour)
	wantDecision(t, got(pr), iamv1.Decision_DECISION_DENY_IMPLICIT, "")
	forged, ok := proto.Clone(pr).(*iamv1.Principal)
	if !ok {
		t.Fatal("clone")
	}
	forged.AuthTime = timestamppb.New(*a.now)
	wantDecision(t, got(forged), iamv1.Decision_DECISION_DENY_IMPLICIT, "session reference does not match the principal")
}
