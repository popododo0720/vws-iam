package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

const (
	samlAud     = "https://signin.vws.test/saml"
	samlSPID    = "urn:amazon:webservices"
	samlIssuer  = "https://idp.corp.test/"
	samlIdpARN  = "arn:vws:iam::" + proj + ":saml-provider/corp"
	samlRoleARN = "arn:vws:iam::" + proj + ":role/saml-dev"
)

// TestAssumeRoleWithSAML: a SAML response signed by a configured provider
// gets role credentials, on both store backends, that the gateway's
// Authenticate refuses until it can carry the SAML identity (#202); every
// failure carries the AWS error code; a RoleArn of no project is
// AccessDenied; and without WithSAML (no SAML provider store yet, #106)
// every call is InvalidIdentityToken.
func TestAssumeRoleWithSAML(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			now := time.Now().UTC()
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			b := bk.open()
			sp := sts.SAMLServiceProvider{Audience: samlSPID, SignInURL: samlAud}
			e := newEnvOn(t, b, &now, grpcapi.WithSAML(samltest.Providers{samlIdpARN: idp.Provider(samlIdpARN)}, sp))
			ctx := t.Context()
			trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"` + samlIdpARN + `"},
				"Action":"sts:AssumeRoleWithSAML","Condition":{"StringEquals":{"SAML:aud":"` + samlAud + `"}}}]}`
			if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
				Parent: parentName, RoleId: "saml-dev", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
			}); err != nil {
				t.Fatal(err)
			}
			good := samltest.Assertion{
				Issuer: samlIssuer, Audience: samlSPID, Recipient: samlAud, Destination: samlAud,
				NameID: "alice@corp.test", NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				Roles: []string{samlRoleARN + "," + samlIdpARN}, SessionName: "alice",
				NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
				ConfirmNotOnOrAfter: now.Add(5 * time.Minute),
			}
			resp := func(a samltest.Assertion) string {
				t.Helper()
				r, err := idp.Response(a, samltest.SignAssertion)
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			req := sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: resp(good)}

			out, err := e.api.AssumeRoleWithSAML(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			c := out.Credentials
			if c.AssumedRoleARN != "arn:vws:sts::"+proj+":assumed-role/saml-dev/alice" ||
				!strings.HasSuffix(out.AssumedRoleID, ":alice") || out.Subject != "alice@corp.test" ||
				out.SubjectType != "persistent" || out.Issuer != samlIssuer || out.Audience != samlAud {
				t.Fatalf("session %s %+v", out, out)
			}
			if d := c.Expiration.Sub(now); d > time.Hour || d < time.Hour-time.Second {
				t.Fatalf("default duration %v", d)
			}
			// The gateway cannot carry the session's saml:* keys to
			// Authorize yet (#202), so Authenticate refuses the session.
			_, err = e.auth.Authenticate(ctx, e.sign(c.AccessKeyID, c.Secret, c.SessionToken))
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")

			expired, rejected := good, good
			expired.NotOnOrAfter = now.Add(-time.Second)
			rejected.Status = "urn:oasis:names:tc:SAML:2.0:status:Requester"
			for _, tc := range []struct {
				name             string
				req              sts.SAMLRequest
				code             codes.Code
				reason, awsError string
			}{
				{
					"no assertion",
					sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN},
					codes.InvalidArgument, "INVALID_SPEC", "ValidationError",
				},
				{
					"not base64",
					sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: "!!!!not-base64"},
					codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken",
				},
				{"unknown provider", sts.SAMLRequest{
					RoleARN: samlRoleARN, PrincipalARN: "arn:vws:iam::" + proj + ":saml-provider/other", Assertion: req.Assertion,
				}, codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken"},
				{
					"expired",
					sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: resp(expired)},
					codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken",
				},
				{
					"IdP rejected",
					sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: resp(rejected)},
					codes.PermissionDenied, "ACCESS_DENIED", "IDPRejectedClaim",
				},
				{"role not granted", sts.SAMLRequest{
					RoleARN: "arn:vws:iam::" + proj + ":role/other", PrincipalARN: samlIdpARN, Assertion: req.Assertion,
				}, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied"},
				{"no project", sts.SAMLRequest{
					RoleARN: "arn:vws:iam::NOT_A_PROJECT:role/saml-dev", PrincipalARN: samlIdpARN, Assertion: req.Assertion,
				}, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied"},
				{"malformed policy", sts.SAMLRequest{
					RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: req.Assertion, Policy: "{",
				}, codes.InvalidArgument, "INVALID_SPEC", "MalformedPolicyDocument"},
			} {
				_, err := e.api.AssumeRoleWithSAML(ctx, tc.req)
				t.Run(tc.name, func(t *testing.T) { wantErr(t, err, tc.code, tc.reason, tc.awsError) })
			}

			// Fail closed with no SAML providers configured.
			off := newEnvOn(t, b, &now)
			_, err = off.api.AssumeRoleWithSAML(ctx, req)
			wantErr(t, err, codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken")
		})
	}
}

// TestAssumeRoleWithSAMLSessionIdentity: on both store backends, a SAML
// session signs a further STS AssumeRole with its saml:sub restored as a
// trusted key, so the next role's trust policy can deny on it; neither
// the SAML session nor a session chained from it authenticates at the
// gateway, whose Authorize cannot see their SAML identity yet (#202);
// and Authorize ignores saml:* keys in the request context.
func TestAssumeRoleWithSAMLSessionIdentity(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			now := time.Now().UTC()
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			sp := sts.SAMLServiceProvider{Audience: samlSPID, SignInURL: samlAud}
			e := newEnvOn(t, bk.open(), &now, grpcapi.WithSAML(samltest.Providers{samlIdpARN: idp.Provider(samlIdpARN)}, sp))
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
			role("saml-dev", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"`+
				samlIdpARN+`"},"Action":"sts:AssumeRoleWithSAML"}]}`)
			chainTrust := func(sub string) string {
				return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + proj +
					`"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",` +
					`"Condition":{"StringEquals":{"saml:sub":"` + sub + `"}}}]}`
			}
			role("deny-alice", chainTrust("alice@corp.test"))
			role("deny-bob", chainTrust("bob@corp.test"))
			r, err := idp.Response(samltest.Assertion{
				Issuer: samlIssuer, Audience: samlSPID, Recipient: samlAud, Destination: samlAud,
				NameID: "alice@corp.test", NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				Roles: []string{samlRoleARN + "," + samlIdpARN}, SessionName: "alice",
				NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
				ConfirmNotOnOrAfter: now.Add(5 * time.Minute),
			}, samltest.SignAssertion)
			if err != nil {
				t.Fatal(err)
			}
			out, err := e.api.AssumeRoleWithSAML(ctx, sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: r})
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
			_, err = chain("deny-alice")
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			next, err := chain("deny-bob")
			if err != nil {
				t.Fatal(err)
			}
			nc := next.GetCredentials()
			for name, req := range map[string]*iamv1.AuthenticateRequest{
				"SAML session":    e.sign(c.AccessKeyID, c.Secret, c.SessionToken),
				"chained session": e.sign(nc.GetAccessKeyId(), nc.GetSecretAccessKey(), nc.GetSessionToken()),
			} {
				_, err := e.auth.Authenticate(ctx, req)
				t.Run(name, func(t *testing.T) {
					wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
				})
			}

			// A client cannot claim a SAML identity in Authorize.
			u := e.keyedUser(t, "bob", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
				"Condition":{"StringEquals":{"saml:sub":"alice@corp.test"}}},
				{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*",
				"Condition":{"StringEquals":{"s3:prefix":"alice"}}}]}`).user
			pr := &iamv1.Principal{
				Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: u.GetStatus().GetArn(), Project: proj,
				UniqueId: u.GetStatus().GetUniqueId(), Resource: u.GetName(),
			}
			// Control: other request keys still reach the evaluation.
			d, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{
				Principal: pr, Action: "s3:ListBucket",
				Context: map[string]*iamv1.ContextValues{"s3:prefix": {Values: []string{"alice"}}},
			})
			if err != nil || d.GetDecision() != iamv1.Decision_DECISION_ALLOW {
				t.Fatalf("Authorize with s3:prefix: %v, %v; want ALLOW", d, err)
			}
			for _, key := range []string{"saml:sub", "SAML:sub"} {
				d, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{
					Principal: pr, Action: "s3:GetObject",
					Context: map[string]*iamv1.ContextValues{key: {Values: []string{"alice@corp.test"}}},
				})
				if err != nil || d.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT {
					t.Errorf("Authorize with client %s: %v, %v; want DENY_IMPLICIT", key, d, err)
				}
			}
		})
	}
}
