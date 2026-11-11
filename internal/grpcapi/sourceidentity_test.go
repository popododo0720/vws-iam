package grpcapi_test

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

// TestSAMLSourceIdentityAtGateway: on every test store backend, the
// SourceIdentity of a SAML assertion stays in the session: Authorize sees
// it as aws:SourceIdentity for the SAML session and a role session chained
// from it, on a restarted server and on every repeat, and a client's
// aws:SourceIdentity neither gives a session one nor replaces it; a role
// whose trust policy requires it can be chained to only from a session that
// holds it (#359).
func TestSAMLSourceIdentityAtGateway(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			sp := sts.SAMLServiceProvider{Audience: samlSPID, SignInURL: samlAud}
			e := newEnvOn(t, b, &now, grpcapi.WithSAML(samltest.Providers{samlIdpARN: idp.Provider(samlIdpARN)}, sp))
			ctx := t.Context()
			deny := func(action, value string) string {
				return `{"Effect":"Deny","Action":"` + action + `","Resource":"*",` +
					`"Condition":{"StringEquals":{"aws:SourceIdentity":"` + value + `"}}}`
			}
			inline := map[string]string{
				"sts": `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
					`"Action":["sts:AssumeRole","sts:SetSourceIdentity"],"Resource":"*"}}`,
				"s3": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},` +
					deny("s3:GetObject", "alice") + `,` + deny("s3:PutObject", "bob") + `]}`,
			}
			role := func(id, trust string) {
				t.Helper()
				if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
					Parent: parentName, RoleId: id,
					Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust, InlinePolicies: inline}},
				}); err != nil {
					t.Fatal(err)
				}
			}
			role("si-dev", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Federated":"`+
				samlIdpARN+`"},"Action":["sts:AssumeRoleWithSAML","sts:SetSourceIdentity"]}}`)
			role("si-next", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"`+proj+
				`"},"Action":["sts:AssumeRole","sts:SetSourceIdentity"],`+
				`"Condition":{"StringEquals":{"aws:SourceIdentity":"alice"}}}}`)
			session := func(sourceIdentity string) sts.SAMLRoleSession {
				t.Helper()
				r, err := idp.Response(samltest.Assertion{
					Issuer: samlIssuer, Audience: samlSPID, Recipient: samlAud, Destination: samlAud,
					NameID: samlSub, NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
					Roles:       []string{"arn:vws:iam::" + proj + ":role/si-dev," + samlIdpARN},
					SessionName: "alice", SourceIdentity: sourceIdentity,
					NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
					ConfirmNotOnOrAfter: now.Add(5 * time.Minute),
				}, samltest.SignAssertion)
				if err != nil {
					t.Fatal(err)
				}
				out, err := e.api.AssumeSAMLRole(ctx, sts.SAMLRequest{
					RoleARN: "arn:vws:iam::" + proj + ":role/si-dev", PrincipalARN: samlIdpARN, Assertion: r,
				})
				if err != nil {
					t.Fatal(err)
				}
				if out.SourceIdentity != sourceIdentity {
					t.Fatalf("SourceIdentity %q, want %q", out.SourceIdentity, sourceIdentity)
				}
				return out
			}
			g := &samlGateway{e: e, b: b}
			si, plain := session("alice").Credentials, session("").Credentials
			plainSig := e.stsSign(plain.AccessKeyID, plain.Secret, plain.SessionToken, "AssumeRole")
			_, err = g.assume(ctx, plainSig, "si-next", "chain")
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			chain, err := g.assume(ctx, e.stsSign(si.AccessKeyID, si.Secret, si.SessionToken, "AssumeRole"), "si-next", "chain")
			if err != nil {
				t.Fatal(err)
			}
			cc := chain.GetCredentials()
			siP := g.authenticate(t, si.AccessKeyID, si.Secret, si.SessionToken)
			chainP := g.authenticate(t, cc.GetAccessKeyId(), cc.GetSecretAccessKey(), cc.GetSessionToken())
			plainP := g.authenticate(t, plain.AccessKeyID, plain.Secret, plain.SessionToken)

			restarted := newEnvOn(t, b, &now)
			for range 2 {
				for _, srv := range []*env{e, restarted} {
					for name, p := range map[string]*iamv1.Principal{
						"SAML session": siP, "chained session": chainP, "AssumeRole principal": chain.GetAssumedRoleUser(),
					} {
						expect(t, name+" GetObject", decide(t, srv, p, "s3:GetObject"), explicit)
						expect(t, name+" PutObject", decide(t, srv, p, "s3:PutObject"), allow)
						for _, key := range []string{"aws:SourceIdentity", "AWS:sourceidentity"} {
							expect(t, name+" replaced by bob via "+key,
								decide(t, srv, p, "s3:PutObject", key, "bob"), allow)
							expect(t, name+" hiding via "+key,
								decide(t, srv, p, "s3:GetObject", key, "bob"), explicit)
						}
					}
					expect(t, "plain session GetObject", decide(t, srv, plainP, "s3:GetObject"), allow)
					expect(t, "plain session claiming alice",
						decide(t, srv, plainP, "s3:GetObject", "aws:SourceIdentity", "alice"), allow)
				}
			}
			resp, err := restarted.auth.Authenticate(ctx, restarted.sign(si.AccessKeyID, si.Secret, si.SessionToken))
			if err != nil {
				t.Fatal(err)
			}
			expect(t, "restarted Authenticate", decide(t, restarted, resp.GetPrincipal(), "s3:GetObject"), explicit)
		})
	}
}
