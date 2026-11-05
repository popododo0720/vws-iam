package authz_test

import (
	"context"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestAuthorizeSessionTokenSession: a GetSessionToken session issued
// without MFA cannot call IAM (iam:PassRole, a permission only, stays),
// one issued with MFA can, and neither calls an STS action except
// sts:AssumeRole and sts:GetCallerIdentity, whatever the policies allow,
// for a root session too; other services and long-term callers are
// decided by policy alone (#233).
func TestAuthorizeSessionTokenSession(t *testing.T) {
	b := setup(t)
	put(t, b, iam.User{Name: "admin", ID: "6", InlinePolicies: map[string]string{"all": allowAllDoc}})
	a := authz.New(b, acct, nil)
	ctx := context.Background()
	session := func(kind authz.PrincipalKind, name string, mfa bool) authz.Principal {
		return authz.Principal{Kind: kind, Name: name, SessionToken: true, SessionMFA: mfa}
	}
	longTerm := authz.Principal{Kind: authz.User, Name: "admin"}
	for _, c := range []struct {
		name   string
		p      authz.Principal
		action string
		ok     bool
	}{
		{"no MFA, IAM", session(authz.User, "admin", false), "iam:CreateAccessKey", false},
		{"no MFA, IAM any case", session(authz.User, "admin", false), "IAM:ListUsers", false},
		{"no MFA, PassRole", session(authz.User, "admin", false), "iam:PassRole", true},
		{"no MFA, AssumeRole", session(authz.User, "admin", false), "sts:AssumeRole", true},
		{"no MFA, GetCallerIdentity", session(authz.User, "admin", false), "sts:GetCallerIdentity", true},
		{"no MFA, other STS", session(authz.User, "admin", false), "sts:DecodeAuthorizationMessage", false},
		{"no MFA, other service", session(authz.User, "admin", false), "ec2:RunInstances", true},
		{"no MFA, policy still decides", session(authz.User, "alice", false), "ec2:TerminateInstances", false},
		{"MFA, IAM", session(authz.User, "admin", true), "iam:CreateAccessKey", true},
		{"MFA, IAM needs a policy", session(authz.User, "alice", true), "iam:CreateAccessKey", false},
		{"MFA, AssumeRole", session(authz.User, "admin", true), "sts:AssumeRole", true},
		{"MFA, other STS", session(authz.User, "admin", true), "sts:GetAccessKeyInfo", false},
		{"MFA, other STS any case", session(authz.User, "admin", true), "STS:GetFederationToken", false},
		{"root no MFA, IAM", session(authz.Root, "", false), "iam:DeleteUser", false},
		{"root no MFA, other service", session(authz.Root, "", false), "s3:PutObject", true},
		{"root no MFA, AssumeRole", session(authz.Root, "", false), "sts:AssumeRole", true},
		{"root MFA, IAM", session(authz.Root, "", true), "iam:DeleteUser", true},
		{"root MFA, other STS", session(authz.Root, "", true), "sts:DecodeAuthorizationMessage", false},
		{"long-term key, IAM", longTerm, "iam:CreateAccessKey", true},
		{"long-term key, STS", longTerm, "sts:GetAccessKeyInfo", true},
	} {
		d, err := a.Authorize(ctx, c.p, c.action, "*", nil)
		if err != nil || d.Allowed != c.ok {
			t.Errorf("%s: %s = %+v, %v; want allowed %v", c.name, c.action, d, err, c.ok)
		}
		if !c.ok && c.p.Name != "alice" && !strings.Contains(d.Reason, "GetSessionToken session") {
			t.Errorf("%s: reason %q does not name the session", c.name, d.Reason)
		}
	}
}
