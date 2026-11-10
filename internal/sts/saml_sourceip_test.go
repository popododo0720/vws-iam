package sts_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

func TestAssumeRoleWithSAMLSourceIP(t *testing.T) {
	e := samlSetup(t)
	req := samlReq(e.response(t, e.claims(), samltest.SignAssertion))
	allow := `{"Effect":"Allow",
"Principal":{"Federated":"` + samlIdpARN + `"},
"Action":["sts:AssumeRoleWithSAML",
"sts:SetSourceIdentity"]`
	cases := []struct {
		name, statement, ip string
		denied              bool
	}{
		{
			"deny inside",
			allow + `},
{"Effect":"Deny",
"Principal":{"Federated":"` + samlIdpARN + `"},
"Action":"sts:AssumeRoleWithSAML",
"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`,
			"192.0.2.9",
			true,
		},
		{
			"deny outside",
			allow + `},
{"Effect":"Deny",
"Principal":{"Federated":"` + samlIdpARN + `"},
"Action":"sts:AssumeRoleWithSAML",
"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`,
			"198.51.100.9",
			false,
		},
		{
			"allow inside",
			allow + `,
"Condition":{"IpAddress":{"AWS:SOURCEIP":"192.0.2.0/24"}}}`,
			"192.0.2.9",
			false,
		},
		{
			"allow outside",
			allow + `,
"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`,
			"198.51.100.9",
			true,
		},
		{
			"mapped IPv4",
			allow + `,
"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`,
			"::ffff:192.0.2.9",
			false,
		},
		{
			"IPv6",
			allow + `,
"Condition":{"IpAddress":{"aws:SourceIp":"2001:db8::/32"}}}`,
			"2001:db8::9",
			false,
		},
		{
			"missing deny",
			allow + `},
{"Effect":"Deny",
"Principal":{"Federated":"` + samlIdpARN + `"},
"Action":"sts:AssumeRoleWithSAML",
"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`,
			"",
			true,
		},
		{
			"missing allow",
			allow + `,
"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`,
			"",
			true,
		},
		{
			"missing IfExists",
			allow + `,
"Condition":{"IpAddressIfExists":{"aws:SourceIp":"192.0.2.0/24"}}}`,
			"",
			true,
		},
		{"missing unconditioned", allow + `}`, "", false},
	}
	for _, ip := range []string{"not-an-address", "192.0.2.9:443", "192.0.2.9/24", "fe80::1%eth0", " 192.0.2.9"} {
		cases = append(cases, struct {
			name, statement, ip string
			denied              bool
		}{"invalid " + ip, allow + `}`, ip, true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.Mutate(t.Context(), e.b, "saml-dev", func(r *iam.Role) error {
				r.AssumeRolePolicy = `{"Version":"2012-10-17",
"Statement":[` + tc.statement + `]}`
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			req.SourceIP = tc.ip
			for range 2 {
				_, err := e.svc.AssumeRoleWithSAML(t.Context(), req)
				if tc.denied {
					if !errors.Is(err, sts.ErrAccessDenied) {
						t.Fatalf("wanted AccessDenied: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(req.String(), req.Assertion) {
				t.Fatal("request logs assertion")
			}
		})
	}
}
