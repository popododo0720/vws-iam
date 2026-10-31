package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/sts"
)

const fedAction = "GetFederationToken"

// TestGetFederationToken: a user allowed sts:GetFederationToken gets
// federated user credentials through SigV4, on both store backends; the
// signed request is accepted once, only for this action, with the
// request's aws:SourceIp; a console session is refused; errors carry
// the AWS codes; and a federated session cannot authenticate at the
// gateway until vws-proto can describe it (#107).
func TestGetFederationToken(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			now := time.Now().UTC()
			e := newEnvOn(t, bk.open(), &now)
			ctx := t.Context()
			broker := e.keyedUser(t, "broker", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"sts:GetFederationToken","Resource":"arn:vws:sts::`+proj+`:federated-user/*"},
				{"Effect":"Deny","Action":"sts:GetFederationToken","Resource":"*",
				 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
			nobody := e.keyedUser(t, "nobody", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
			sign := func() *iamv1.AuthenticateRequest { return e.stsSign(broker.id, broker.secretKey, "", fedAction) }
			req := sts.FederationRequest{Name: "bob", Policy: `{"Version":"2012-10-17","Statement":
				{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`}

			once := sign()
			tok, err := e.api.GetFederationToken(ctx, once, "", req)
			if err != nil {
				t.Fatal(err)
			}
			c := tok.Credentials
			if !strings.HasPrefix(c.AccessKeyID, "ASIA") || c.Secret == "" || c.SessionToken == "" ||
				tok.ARN != "arn:vws:sts::"+proj+":federated-user/bob" || tok.FederatedUserID != proj+":bob" {
				t.Fatalf("token %s", tok)
			}
			// The same signed request cannot be used twice; one signed for
			// another action is refused.
			_, err = e.api.GetFederationToken(ctx, once, "", req)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			_, err = e.api.GetFederationToken(ctx, e.stsSign(broker.id, broker.secretKey, "", "GetSessionToken"), "", req)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			// No permission, and an IP-conditioned Deny on the SigV4 address.
			_, err = e.api.GetFederationToken(ctx, e.stsSign(nobody.id, nobody.secretKey, "", fedAction), "", req)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			from := sign()
			from.SourceIp = "10.1.2.3"
			_, err = e.api.GetFederationToken(ctx, from, "", req)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			// The federated credentials cannot call it again: for now they
			// do not authenticate at all (see the end of this test); the
			// AccessDenied of a federated caller is TestGetFederationTokenCallers.
			_, err = e.api.GetFederationToken(ctx, e.stsSign(c.AccessKeyID, c.Secret, c.SessionToken, fedAction), "", req)
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")

			// AWS error codes.
			arn := "arn:vws:iam::" + proj + ":policy/broker-policy"
			for _, bad := range []struct {
				req          sts.FederationRequest
				code         codes.Code
				reason, want string
			}{
				{sts.FederationRequest{Name: "b"}, codes.InvalidArgument, "INVALID_SPEC", "ValidationError"},
				{
					sts.FederationRequest{Name: "bob", Duration: time.Minute},
					codes.InvalidArgument, "INVALID_SPEC", "ValidationError",
				},
				{sts.FederationRequest{Name: "bob", Policy: "{"}, codes.InvalidArgument, "INVALID_SPEC", "MalformedPolicyDocument"},
				{
					sts.FederationRequest{Name: "bob", PolicyARNs: []string{"arn:vws:iam::" + proj + ":policy/missing"}},
					codes.InvalidArgument, "INVALID_SPEC", "MalformedPolicyDocument",
				},
				{
					sts.FederationRequest{
						Name: "bob", Policy: req.Policy + strings.Repeat(" ", 2000-len(req.Policy)),
						PolicyARNs: []string{arn, arn},
					},
					codes.InvalidArgument, "INVALID_SPEC", "PackedPolicyTooLarge",
				},
			} {
				_, err = e.api.GetFederationToken(ctx, sign(), "", bad.req)
				wantErr(t, err, bad.code, bad.reason, bad.want)
			}
			// No authentication, and a console session.
			_, err = e.api.GetFederationToken(ctx, nil, "", req)
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken")
			const pw = "correct horse battery"
			lp := &iamv1.SetLoginProfileRequest{Name: broker.user.GetName(), Password: pw}
			if _, err := e.users.SetLoginProfile(ctx, lp); err != nil {
				t.Fatal(err)
			}
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "broker", Password: pw})
			if err != nil {
				t.Fatal(err)
			}
			_, err = e.api.GetFederationToken(ctx, nil, l.GetSessionToken(), req)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")

			// The gateway cannot be given a principal for a federated
			// session yet, so it fails closed instead of acting as broker.
			_, err = e.auth.Authenticate(ctx, e.sign(c.AccessKeyID, c.Secret, c.SessionToken))
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
		})
	}
}
