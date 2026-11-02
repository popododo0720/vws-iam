package grpcapi_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/oidctest"
)

const (
	wiIssuer   = "https://token.ci.test"
	wiName     = "token.ci.test"
	wiProvARN  = "arn:vws:iam::" + proj + ":oidc-provider/" + wiName
	wiRoleARN  = "arn:vws:iam::" + proj + ":role/ci-deploy"
	wiClientID = "sts.vws.test"
)

// wiToken signs an ID token for sub that is valid at now.
func wiToken(t *testing.T, idp *oidctest.IdP, now time.Time, sub string, mutate func(map[string]any)) string {
	t.Helper()
	c := map[string]any{
		"iss": wiIssuer, "sub": sub, "aud": wiClientID,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(c)
	}
	tok, err := idp.Token("RS256", c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestAssumeRoleWithWebIdentity: an ID token signed by a configured OIDC
// provider gets role credentials, on both store backends, that the
// gateway's Authenticate refuses until it can carry the web identity
// (#209); every failure carries the AWS error code; a RoleArn of no
// project is AccessDenied; and without WithOIDC (no OIDC provider store
// yet, #208) every call is InvalidIdentityToken.
func TestAssumeRoleWithWebIdentity(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			now := time.Now().UTC()
			idp, err := oidctest.New(wiIssuer)
			if err != nil {
				t.Fatal(err)
			}
			other, err := oidctest.New(wiIssuer)
			if err != nil {
				t.Fatal(err)
			}
			b := bk.open()
			providers := oidctest.Providers{ByARN: map[string]sts.OIDCProvider{wiProvARN: idp.Provider(wiProvARN, wiClientID)}}
			e := newEnvOn(t, b, &now, grpcapi.WithOIDC(providers))
			ctx := t.Context()
			trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"` + wiProvARN + `"},
				"Action":"sts:AssumeRoleWithWebIdentity",
				"Condition":{"StringEquals":{"` + wiName + `:aud":"` + wiClientID + `"}}}]}`
			if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
				Parent: parentName, RoleId: "ci-deploy", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
			}); err != nil {
				t.Fatal(err)
			}
			good := wiToken(t, idp, now, "repo:vws/app", nil)
			req := sts.WebIdentityRequest{RoleARN: wiRoleARN, RoleSessionName: "build-1", Token: good}

			out, err := e.api.AssumeRoleWithWebIdentity(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			c := out.Credentials
			if c.AssumedRoleARN != "arn:vws:sts::"+proj+":assumed-role/ci-deploy/build-1" ||
				!strings.HasSuffix(out.AssumedRoleID, ":build-1") || out.SubjectFromWebIdentityToken != "repo:vws/app" ||
				out.Provider != wiIssuer || out.Audience != wiClientID {
				t.Fatalf("session %s %+v", out, out)
			}
			if strings.Contains(fmt.Sprint(out)+fmt.Sprint(req), good) {
				t.Fatal("String prints the token")
			}
			if d := c.Expiration.Sub(now); d > time.Hour || d < time.Hour-time.Second {
				t.Fatalf("default duration %v", d)
			}
			_, err = e.auth.Authenticate(ctx, e.sign(c.AccessKeyID, c.Secret, c.SessionToken))
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")

			with := func(f func(map[string]any)) sts.WebIdentityRequest {
				r := req
				r.Token = wiToken(t, idp, now, "repo:vws/app", f)
				return r
			}
			forged, err := other.Token("RS256", map[string]any{
				"iss": wiIssuer, "sub": "repo:vws/app", "aud": wiClientID,
				"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name             string
				req              sts.WebIdentityRequest
				code             codes.Code
				reason, awsError string
			}{
				{
					"no token",
					sts.WebIdentityRequest{RoleARN: wiRoleARN, RoleSessionName: "build-1"},
					codes.InvalidArgument, "INVALID_SPEC", "ValidationError",
				},
				{
					"not a JWT",
					sts.WebIdentityRequest{RoleARN: wiRoleARN, RoleSessionName: "build-1", Token: "not.a.jwt!"},
					codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken",
				},
				{
					"other key",
					sts.WebIdentityRequest{RoleARN: wiRoleARN, RoleSessionName: "build-1", Token: forged},
					codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken",
				},
				{
					"unknown provider", with(func(c map[string]any) { c["iss"] = "https://other.ci.test" }),
					codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken",
				},
				{
					"wrong audience", with(func(c map[string]any) { c["aud"] = "someone-else" }),
					codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken",
				},
				{
					"expired", with(func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }),
					codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken",
				},
				{"role not granted", sts.WebIdentityRequest{
					RoleARN: "arn:vws:iam::" + proj + ":role/other", RoleSessionName: "build-1", Token: good,
				}, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied"},
				{"no project", sts.WebIdentityRequest{
					RoleARN: "arn:vws:iam::NOT_A_PROJECT:role/ci-deploy", RoleSessionName: "build-1", Token: good,
				}, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied"},
				{"malformed policy", sts.WebIdentityRequest{
					RoleARN: wiRoleARN, RoleSessionName: "build-1", Token: good, Policy: "{",
				}, codes.InvalidArgument, "INVALID_SPEC", "MalformedPolicyDocument"},
			} {
				_, err := e.api.AssumeRoleWithWebIdentity(ctx, tc.req)
				t.Run(tc.name, func(t *testing.T) { wantErr(t, err, tc.code, tc.reason, tc.awsError) })
			}

			// The gateway-observed source IP is aws:SourceIp of the trust
			// evaluation: an IP-conditioned Deny refuses a caller in its
			// range, and an IP in the request itself is ignored.
			ipTrust := strings.TrimSuffix(trust, "]}") + `,{"Effect":"Deny","Principal":"*",
				"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}}]}`
			if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
				Parent: parentName, RoleId: "ci-ip", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: ipTrust}},
			}); err != nil {
				t.Fatal(err)
			}
			ipReq := req
			ipReq.RoleARN = "arn:vws:iam::" + proj + ":role/ci-ip"
			_, err = e.api.AssumeRoleWithWebIdentityFrom(ctx, ipReq, "203.0.113.9")
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			spoofed := ipReq
			spoofed.SourceIP = "198.51.100.1"
			_, err = e.api.AssumeRoleWithWebIdentityFrom(ctx, spoofed, "203.0.113.9")
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			_, err = e.api.AssumeRoleWithWebIdentity(ctx, spoofed)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			if _, err := e.api.AssumeRoleWithWebIdentityFrom(ctx, ipReq, "198.51.100.1"); err != nil {
				t.Fatalf("outside the denied range: %v", err)
			}

			// Provider keys that cannot be read are IDPCommunicationError,
			// with no backend detail.
			down := newEnvOn(t, b, &now, grpcapi.WithOIDC(oidctest.Providers{
				Err: fmt.Errorf("%w: jwks fetch: dial 10.0.0.1:443", sts.ErrIDPCommunication),
			}))
			_, err = down.api.AssumeRoleWithWebIdentity(ctx, req)
			wantErr(t, err, codes.Unavailable, "", "IDPCommunicationError")
			if strings.Contains(err.Error(), "10.0.0.1") {
				t.Fatalf("detail leaked: %v", err)
			}
			if errors.Is(err, sts.ErrIDPCommunication) {
				t.Fatal("sentinel crossed the wire")
			}

			// Fail closed with no OIDC providers configured.
			off := newEnvOn(t, b, &now)
			_, err = off.api.AssumeRoleWithWebIdentity(ctx, req)
			wantErr(t, err, codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken")
		})
	}
}

// TestAssumeRoleWithWebIdentitySessionIdentity: on both store backends, a
// web identity session signs a further STS AssumeRole with its
// <provider>:sub restored as a trusted key, so the next role's trust
// policy can deny on it; neither the session nor one chained from it
// authenticates at the gateway (#209); and Authorize ignores web identity
// keys in the request context.
func TestAssumeRoleWithWebIdentitySessionIdentity(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			now := time.Now().UTC()
			idp, err := oidctest.New(wiIssuer)
			if err != nil {
				t.Fatal(err)
			}
			e := newEnvOn(t, bk.open(), &now, grpcapi.WithOIDC(oidctest.Providers{
				ByARN: map[string]sts.OIDCProvider{wiProvARN: idp.Provider(wiProvARN, wiClientID)},
			}))
			ctx := t.Context()
			assume := map[string]string{"sts": `{"Version":"2012-10-17","Statement":
				{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`}
			role := func(id, trust string) {
				t.Helper()
				if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
					Parent: parentName, RoleId: id,
					Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust, InlinePolicies: assume}},
				}); err != nil {
					t.Fatal(err)
				}
			}
			role("ci-deploy", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"`+
				wiProvARN+`"},"Action":"sts:AssumeRoleWithWebIdentity"}]}`)
			chainTrust := func(sub string) string {
				return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + proj +
					`"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",` +
					`"Condition":{"StringEquals":{"` + wiName + `:sub":"` + sub + `"}}}]}`
			}
			role("deny-app", chainTrust("repo:vws/app"))
			role("deny-other", chainTrust("repo:vws/other"))
			out, err := e.api.AssumeRoleWithWebIdentity(ctx, sts.WebIdentityRequest{
				RoleARN: wiRoleARN, RoleSessionName: "build-1", Token: wiToken(t, idp, now, "repo:vws/app", nil),
			})
			if err != nil {
				t.Fatal(err)
			}
			c := out.Credentials
			chain := func(roleID string) (*iamv1.AssumeRoleResponse, error) {
				return e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
					Authentication: arSig(e.stsSign(c.AccessKeyID, c.Secret, c.SessionToken, "AssumeRole")),
					Role:           parentName + "/roles/" + roleID, RoleSessionName: "chain",
				})
			}
			_, err = chain("deny-app")
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			next, err := chain("deny-other")
			if err != nil {
				t.Fatal(err)
			}
			nc := next.GetCredentials()
			for name, req := range map[string]*iamv1.AuthenticateRequest{
				"web identity session": e.sign(c.AccessKeyID, c.Secret, c.SessionToken),
				"chained session":      e.sign(nc.GetAccessKeyId(), nc.GetSecretAccessKey(), nc.GetSessionToken()),
			} {
				_, err := e.auth.Authenticate(ctx, req)
				t.Run(name, func(t *testing.T) {
					wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
				})
			}

			// A client cannot claim a web identity in Authorize.
			u := e.keyedUser(t, "bob", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
				"Condition":{"StringEquals":{"`+wiName+`:sub":"repo:vws/app"}}},
				{"Effect":"Allow","Action":"s3:PutObject","Resource":"*",
				"Condition":{"StringEquals":{"aws:FederatedProvider":"`+wiProvARN+`"}}},
				{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*",
				"Condition":{"StringEquals":{"s3:prefix":"app"}}}]}`).user
			pr := &iamv1.Principal{
				Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: u.GetStatus().GetArn(), Project: proj,
				UniqueId: u.GetStatus().GetUniqueId(), Resource: u.GetName(),
			}
			// Control: other request keys still reach the evaluation.
			d, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{
				Principal: pr, Action: "s3:ListBucket",
				Context: map[string]*iamv1.ContextValues{"s3:prefix": {Values: []string{"app"}}},
			})
			if err != nil || d.GetDecision() != iamv1.Decision_DECISION_ALLOW {
				t.Fatalf("Authorize with s3:prefix: %v, %v; want ALLOW", d, err)
			}
			for _, tc := range []struct{ action, key, value string }{
				{"s3:GetObject", wiName + ":sub", "repo:vws/app"},
				{"s3:GetObject", strings.ToUpper(wiName) + ":SUB", "repo:vws/app"},
				{"s3:PutObject", "aws:FederatedProvider", wiProvARN},
				{"s3:PutObject", "AWS:federatedprovider", wiProvARN},
			} {
				d, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{
					Principal: pr, Action: tc.action,
					Context: map[string]*iamv1.ContextValues{tc.key: {Values: []string{tc.value}}},
				})
				if err != nil || d.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT {
					t.Errorf("Authorize with client %s: %v, %v; want DENY_IMPLICIT", tc.key, d, err)
				}
			}
		})
	}
}
