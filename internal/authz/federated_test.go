package authz_test

import (
	"context"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
)

const allowAllDoc = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`

// TestAuthorizeFederatedSession: a GetFederationToken session has only
// the intersection of its user's policies and its session policies
// (none means nothing), inline or managed, a managed session policy is
// read at each evaluation, and IAM and STS (except GetCallerIdentity)
// are refused whatever the policies allow, for a root caller too.
func TestAuthorizeFederatedSession(t *testing.T) {
	b := setup(t)
	put(t, b, iam.User{Name: "admin", ID: "6", InlinePolicies: map[string]string{"all": allowAllDoc}})
	put(t, b, iam.Policy{Name: "Gone", ID: "7", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1", Document: allowAllDoc}}})
	a := authz.New(b, acct, func() time.Time { return time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC) })
	ctx := context.Background()
	s3Read := "arn:vws:iam::" + acct + ":policy/S3Read"
	gone := "arn:vws:iam::" + acct + ":policy/Gone"
	s3All := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`
	fed := func(kind authz.PrincipalKind, name string, inline []string, arns ...string) authz.Principal {
		return authz.Principal{
			Kind: kind, Name: name, ARN: "arn:vws:sts::" + acct + ":federated-user/bob",
			SessionPolicies: inline, SessionPolicyARNs: arns, Federated: true,
		}
	}
	for _, c := range []struct {
		name   string
		p      authz.Principal
		action string
		ok     bool
	}{
		{"no session policy", fed(authz.User, "alice", nil), "s3:GetObject", false},
		{"managed session policy", fed(authz.User, "alice", nil, s3Read), "s3:GetObject", true},
		{"managed narrows the group grant", fed(authz.User, "alice", nil, s3Read), "ec2:RunInstances", false},
		{"inline intersects", fed(authz.User, "alice", []string{allowAllDoc}), "ec2:RunInstances", true},
		{"cannot exceed the user", fed(authz.User, "alice", []string{allowAllDoc}), "s3:PutObject", false},
		{"user deny still wins", fed(authz.User, "alice", []string{allowAllDoc}), "ec2:TerminateInstances", false},
		{"union of session policies", fed(authz.User, "admin", []string{s3All}, s3Read), "s3:PutObject", true},
		{"no IAM", fed(authz.User, "admin", []string{allowAllDoc}), "iam:CreateUser", false},
		{"no IAM, any case", fed(authz.User, "admin", []string{allowAllDoc}), "IAM:ListUsers", false},
		{"no STS", fed(authz.User, "admin", []string{allowAllDoc}), "sts:AssumeRole", false},
		{"no nested federation", fed(authz.User, "admin", []string{allowAllDoc}), "sts:GetFederationToken", false},
		{"GetCallerIdentity", fed(authz.User, "admin", []string{allowAllDoc}), "sts:GetCallerIdentity", true},
		{"root without policy", fed(authz.Root, "", nil), "s3:GetObject", false},
		{"root narrowed", fed(authz.Root, "", []string{s3All}), "s3:PutObject", true},
		{"root narrowed, other service", fed(authz.Root, "", []string{s3All}), "ec2:RunInstances", false},
		{"root no IAM", fed(authz.Root, "", []string{allowAllDoc}), "iam:DeleteUser", false},
	} {
		d, err := a.Authorize(ctx, c.p, c.action, "*", nil)
		if err != nil || d.Allowed != c.ok {
			t.Errorf("%s: %s = %+v, %v; want allowed %v", c.name, c.action, d, err, c.ok)
		}
	}

	// A managed session policy is read at evaluation: once deleted it
	// grants nothing, and the evaluation does not fail.
	p := fed(authz.User, "admin", nil, gone)
	if d, err := a.Authorize(ctx, p, "s3:GetObject", "*", nil); err != nil || !d.Allowed {
		t.Fatalf("before delete: %+v, %v", d, err)
	}
	if err := b.Delete(ctx, iam.KindPolicy, "Gone", ""); err != nil {
		t.Fatal(err)
	}
	if d, err := a.Authorize(ctx, p, "s3:GetObject", "*", nil); err != nil || d.Allowed {
		t.Fatalf("after delete: %+v, %v", d, err)
	}

	// The federated session acts as the federated user, not the IAM user.
	cond := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*",
		"Condition":{"StringEquals":{"aws:PrincipalArn":"arn:vws:sts::` + acct + `:federated-user/bob"}}}}`
	if d, err := a.Authorize(ctx, fed(authz.User, "admin", []string{cond}), "s3:GetObject", "*", nil); err != nil || !d.Allowed {
		t.Fatalf("principal arn: %+v, %v", d, err)
	}
	user := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*",
		"Condition":{"StringEquals":{"aws:username":"admin"}}}}`
	if d, err := a.Authorize(ctx, fed(authz.User, "admin", []string{user}), "s3:GetObject", "*", nil); err != nil || d.Allowed {
		t.Fatalf("aws:username is not the IAM user's: %+v, %v", d, err)
	}

	// ManagedPolicyExists answers for this project's policies only.
	for arn, want := range map[string]bool{s3Read: true, gone: false, "arn:vws:iam::111111111111:policy/S3Read": false} {
		if got, err := a.ManagedPolicyExists(ctx, arn); err != nil || got != want {
			t.Errorf("ManagedPolicyExists(%s) = %v, %v; want %v", arn, got, err, want)
		}
	}
}
