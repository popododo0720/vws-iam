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

// TestAssumeRoleWithSAMLReusedAssertion: vws-iam keeps no SAML assertion
// replay cache, as AWS does (#379). The same assertion is exchanged again,
// also on a restarted server, and each exchange issues new working
// credentials, until its NotOnOrAfter: from that instant it is
// ExpiredToken, on each store backend.
func TestAssumeRoleWithSAMLReusedAssertion(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			// Whole seconds, as the assertion carries its times.
			now := time.Now().UTC().Truncate(time.Second)
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			b := bk.open()
			saml := grpcapi.WithSAML(samltest.Providers{samlIdpARN: idp.Provider(samlIdpARN)},
				sts.SAMLServiceProvider{Audience: samlSPID, SignInURL: samlAud})
			e := newEnvOn(t, b, &now, saml)
			ctx := t.Context()
			trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"` + samlIdpARN +
				`"},"Action":"sts:AssumeRoleWithSAML"}]}`
			if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
				Parent: parentName, RoleId: "saml-dev", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
			}); err != nil {
				t.Fatal(err)
			}
			notOnOrAfter := now.Add(5 * time.Minute)
			assertion, err := idp.Response(samltest.Assertion{
				Issuer: samlIssuer, Audience: samlSPID, Recipient: samlAud, Destination: samlAud,
				NameID: "alice@corp.test", NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				Roles: []string{samlRoleARN + "," + samlIdpARN}, SessionName: "alice",
				NotBefore: now.Add(-time.Minute), NotOnOrAfter: notOnOrAfter, ConfirmNotOnOrAfter: notOnOrAfter,
			}, samltest.SignAssertion)
			if err != nil {
				t.Fatal(err)
			}
			req := sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: assertion}

			restarted := newEnvOn(t, b, &now, saml)
			seen := map[string]bool{}
			for i, srv := range []*env{e, e, restarted} {
				if i == 2 {
					now = notOnOrAfter.Add(-time.Second)
				}
				out, err := srv.api.AssumeSAMLRole(ctx, req)
				if err != nil {
					t.Fatalf("exchange %d: %v", i+1, err)
				}
				c := out.Credentials
				if seen[c.AccessKeyID] || seen[c.Secret] || seen[c.SessionToken] {
					t.Fatalf("exchange %d repeated earlier credentials", i+1)
				}
				seen[c.AccessKeyID], seen[c.Secret], seen[c.SessionToken] = true, true, true
				if _, err := srv.auth.Authenticate(ctx, srv.sign(c.AccessKeyID, c.Secret, c.SessionToken)); err != nil {
					t.Fatalf("exchange %d credentials: %v", i+1, err)
				}
			}

			now = notOnOrAfter
			for _, srv := range []*env{e, restarted} {
				_, err := srv.api.AssumeSAMLRole(ctx, req)
				wantErr(t, err, codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken")
			}
		})
	}
}
