package sts_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

func TestPublicOperationsNameInternalFailures(t *testing.T) {
	e := setup(t)
	caller := e.caller(t, "alice")
	role, user := e.sessions(t)
	ref := e.mint(t, role)
	service := func(kind iam.Kind) *sts.Service {
		return sts.New(downOn{e.b, kind}, e.keys, e.az, acct, e.clk.now)
	}
	f := fedSetup(t)
	broker := f.caller(t, "broker")
	fed := sts.New(downOn{f.b, iam.KindUser}, f.keys, f.az, acct, f.clk.now)
	saml := samlSetup(t)
	assertion := saml.response(t, saml.claims(), samltest.SignAssertion)
	providers := samltest.Providers{samlIdpARN: saml.idp.Provider(samlIdpARN)}
	samlSvc := sts.New(downOn{saml.b, iam.KindRole}, saml.keys, saml.az, acct, saml.clk.now,
		sts.WithSAML(providers, samlSP))
	info := keyInfoSetup(t)
	infoStore := store.Scoped(info.root, acct)
	infoSvc := sts.New(infoStore, info.keys, authz.New(infoStore, acct, info.clk.now), acct, info.clk.now,
		sts.WithKeyIndex(downOn{info.root, iam.KindKeyIndex}))
	id := info.key(t, info.own, "nobody")
	cases := []struct {
		op  string
		run func() error
	}{
		{"AssumeRole", func() error {
			_, err := service(iam.KindRole).AssumeRole(t.Context(), caller, nil, adminARN, "diagnostic-session", 0,
				sts.SessionPolicies{}, sts.MFA{})
			return err
		}},
		{"GetSessionToken", func() error {
			_, err := service(iam.KindUser).GetSessionToken(t.Context(), caller, time.Hour, sts.MFA{})
			return err
		}},
		{"GetFederationToken", func() error {
			_, err := fed.GetFederationToken(t.Context(), broker, nil, sts.FederationRequest{Name: "diagnostic-session"})
			return err
		}},
		{"AssumeRoleWithSAML", func() error {
			_, err := samlSvc.AssumeRoleWithSAML(t.Context(), samlReq(assertion))
			return err
		}},
		{"CheckSessionRef", func() error {
			_, err := service(iam.KindRole).CheckSessionRef(t.Context(), ref)
			return err
		}},
		{"GetAccessKeyInfo", func() error {
			_, err := infoSvc.GetAccessKeyInfo(t.Context(), info.caller, nil, id)
			return err
		}},
		{"Resolve", func() error {
			_, err := service(iam.KindUser).Resolve(t.Context(), sts.Credential{
				AccessKeyID: user.AccessKeyID, SessionToken: user.SessionToken,
			})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			err := tc.run()
			if !errors.Is(err, store.ErrUnavailable) || !strings.HasPrefix(err.Error(), "sts."+tc.op+": ") {
				t.Fatalf("operation or cause missing: %v", err)
			}
			for _, value := range []string{
				role.AccessKeyID, user.AccessKeyID, role.SessionToken, user.SessionToken,
				role.Secret, user.Secret, ref, id, assertion, "diagnostic-session", "alice@corp.test",
			} {
				if value != "" && strings.Contains(err.Error(), value) {
					t.Fatal("request credential or claim in diagnostic error")
				}
			}
		})
	}
}
