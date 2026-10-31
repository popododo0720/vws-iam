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
	samlIssuer  = "https://idp.corp.test/"
	samlIdpARN  = "arn:vws:iam::" + proj + ":saml-provider/corp"
	samlRoleARN = "arn:vws:iam::" + proj + ":role/saml-dev"
)

// TestAssumeRoleWithSAML: a SAML response signed by a configured provider
// gets role credentials that authenticate at the gateway as the assumed
// role, on both store backends; every failure carries the AWS error code;
// a RoleArn of no project is AccessDenied; and without WithSAML (no SAML
// provider store yet, #106) every call is InvalidIdentityToken.
func TestAssumeRoleWithSAML(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			now := time.Now().UTC()
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			b := bk.open()
			e := newEnvOn(t, b, &now, grpcapi.WithSAML(samltest.Providers{samlIdpARN: idp.Provider(samlIdpARN)}, samlAud))
			ctx := t.Context()
			trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"` + samlIdpARN + `"},
				"Action":"sts:AssumeRoleWithSAML","Condition":{"StringEquals":{"SAML:aud":"` + samlAud + `"}}}]}`
			if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
				Parent: parentName, RoleId: "saml-dev", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
			}); err != nil {
				t.Fatal(err)
			}
			good := samltest.Assertion{
				Issuer: samlIssuer, Audience: samlAud, Recipient: samlAud, Destination: samlAud,
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
			a, err := e.auth.Authenticate(ctx, e.sign(c.AccessKeyID, c.Secret, c.SessionToken))
			if err != nil || a.GetPrincipal().GetType() != iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE ||
				a.GetArn() != c.AssumedRoleARN {
				t.Fatalf("authenticate SAML session %v %v", a, err)
			}

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
