package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// TestSessionTokenIAMNeedsMFA: credentials from GetSessionToken without
// MFA cannot call IAM (Authenticate refuses a request signed for iam,
// with the InvalidClientTokenId AWS answers), still sign other services
// and assume a role; with MFA they call IAM per policy. Neither calls an
// STS action other than AssumeRole (AccessDenied). The same holds on
// another replica, after a restart, and on retry (#233).
func TestSessionTokenIAMNeedsMFA(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			alice := e.keyedUser(t, "alice", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
			seed, serial, _ := strings.Cut(enableMFA(t, e, ctx, "alice"), "|")
			trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` +
				alice.user.GetStatus().GetArn() + `"},"Action":"sts:AssumeRole"}]}`
			op, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
				Parent: parentName, RoleId: "deployer", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
			})
			if err != nil {
				t.Fatal(err)
			}
			role := unpack(t, op, &iamv1.Role{})

			gst := func(m bool) *iamv1.Credentials {
				t.Helper()
				signed := e.stsSign(alice.id, alice.secretKey, "", "GetSessionToken")
				req := &iamv1.GetSessionTokenRequest{Authentication: gstSig(signed)}
				if m {
					req.SerialNumber, req.TokenCode = serial, code(t, e, seed)
				}
				resp, err := e.token.GetSessionToken(ctx, req)
				if err != nil {
					t.Fatal(err)
				}
				return resp.GetCredentials()
			}
			plain, withMFA := gst(false), gst(true)
			signed := func(r *env, service string, c *iamv1.Credentials) *iamv1.AuthenticateRequest {
				return r.signFor(service, c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken())
			}

			replica := newEnvOn(t, b, &now)
			replica.nonce = 1000
			for _, r := range []*env{e, replica} {
				for _, service := range []string{"iam", "IAM"} {
					for range 2 {
						_, err := r.auth.Authenticate(ctx, signed(r, service, plain))
						wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
					}
				}
				a, err := r.auth.Authenticate(ctx, signed(r, "s3", plain))
				if err != nil || a.GetPrincipal().GetMfaAuthenticated() {
					t.Fatalf("s3 without MFA: %v %v", a, err)
				}
				d, err := r.api.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: a.GetPrincipal(), Action: "s3:GetObject"})
				if err != nil || d.GetDecision() != iamv1.Decision_DECISION_ALLOW {
					t.Fatalf("s3:GetObject without MFA: %v %v", d, err)
				}

				a, err = r.auth.Authenticate(ctx, signed(r, "iam", withMFA))
				if err != nil || !a.GetPrincipal().GetMfaAuthenticated() {
					t.Fatalf("iam with MFA: %v %v", a, err)
				}
				d, err = r.api.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: a.GetPrincipal(), Action: "iam:CreateAccessKey"})
				if err != nil || d.GetDecision() != iamv1.Decision_DECISION_ALLOW {
					t.Fatalf("iam:CreateAccessKey with MFA: %v %v", d, err)
				}

				for _, c := range []*iamv1.Credentials{plain, withMFA} {
					ar, err := r.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
						Authentication: arSig(r.stsSign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken(), "AssumeRole")),
						Role:           role.GetName(), RoleSessionName: "deploy",
					})
					if err != nil || ar.GetCredentials().GetAccessKeyId() == "" {
						t.Fatalf("AssumeRole from a session: %v %v", ar, err)
					}
					info := r.stsSign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken(), keyInfoAction)
					_, err = r.api.AccessKeyInfo(ctx, info, "", "", alice.id)
					wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
				}
			}

			// The long-term key itself still calls IAM and other STS actions.
			a, err := e.auth.Authenticate(ctx, e.signFor("iam", alice.id, alice.secretKey, ""))
			if err != nil {
				t.Fatalf("iam with the long-term key: %v", err)
			}
			d, err := e.api.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: a.GetPrincipal(), Action: "iam:CreateAccessKey"})
			if err != nil || d.GetDecision() != iamv1.Decision_DECISION_ALLOW {
				t.Fatalf("iam:CreateAccessKey with the long-term key: %v %v", d, err)
			}
			info := e.stsSign(alice.id, alice.secretKey, "", keyInfoAction)
			if got, err := e.api.AccessKeyInfo(ctx, info, "", "", alice.id); err != nil || got != proj {
				t.Fatalf("GetAccessKeyInfo with the long-term key: %q %v", got, err)
			}
		})
	}
}
