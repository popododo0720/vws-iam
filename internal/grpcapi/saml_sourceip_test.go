package grpcapi_test

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

func TestAssumeRoleWithSAMLTrustedSourceIP(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			option := grpcapi.WithSAML(
				samltest.Providers{samlIdpARN: idp.Provider(samlIdpARN)},
				sts.SAMLServiceProvider{Audience: samlSPID, SignInURL: samlAud},
			)
			trust := `{"Version":"2012-10-17",
"Statement":[{"Effect":"Allow",
"Principal":{"Federated":"` + samlIdpARN + `"},
"Action":"sts:AssumeRoleWithSAML"},
{"Effect":"Deny",
"Principal":{"Federated":"` + samlIdpARN + `"},
"Action":"sts:AssumeRoleWithSAML",
"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}]}`
			if _, err := store.Create(t.Context(), store.Scoped(b, proj), iam.Role{
				Name:             "saml-dev",
				ID:               iam.NewUniqueID("AROA"),
				AssumeRolePolicy: trust,
			}); err != nil {
				t.Fatal(err)
			}
			assertion, err := idp.Response(samltest.Assertion{
				Issuer:              samlIssuer,
				Audience:            samlSPID,
				Recipient:           samlAud,
				Destination:         samlAud,
				NameID:              "alice@corp.test",
				NameIDFormat:        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				Roles:               []string{samlRoleARN + "," + samlIdpARN},
				SessionName:         "alice",
				NotBefore:           now.Add(-time.Minute),
				NotOnOrAfter:        now.Add(5 * time.Minute),
				ConfirmNotOnOrAfter: now.Add(5 * time.Minute),
			}, samltest.SignAssertion)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				e := newEnvOn(t, b, &now, option)
				req := sts.SAMLRequest{
					RoleARN:      samlRoleARN,
					PrincipalARN: samlIdpARN,
					Assertion:    assertion,
					SourceIP:     "198.51.100.9",
				}
				_, err := e.api.AssumeSAMLRoleFrom(t.Context(), req, "192.0.2.9")
				wantAWS(t, err, codes.PermissionDenied, "AccessDenied")
				req.SourceIP = "192.0.2.9"
				if _, err := e.api.AssumeSAMLRoleFrom(t.Context(), req, "198.51.100.9"); err != nil {
					t.Fatal(err)
				}
				_, err = e.api.AssumeSAMLRole(t.Context(), req)
				wantAWS(t, err, codes.PermissionDenied, "AccessDenied")
				_, err = e.api.AssumeSAMLRoleFrom(t.Context(), req, "192.0.2.9:443")
				wantAWS(t, err, codes.PermissionDenied, "AccessDenied")
			}
		})
	}
}
