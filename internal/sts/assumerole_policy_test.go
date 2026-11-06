package sts_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
)

const fedAdminARN = "arn:vws:iam::" + acct + ":role/admin"

// assumeWith assumes the admin role as broker with sp and returns the
// validated session's principal.
func assumeWith(
	t *testing.T, svc *sts.Service, broker sts.Caller, sp sts.SessionPolicies,
) (sts.Credentials, authz.Principal) {
	t.Helper()
	ctx := context.Background()
	creds, err := svc.AssumeRole(ctx, broker, nil, fedAdminARN, "scoped", 0, sp, sts.MFA{})
	if err != nil {
		t.Fatalf("AssumeRole: %v", err)
	}
	sess, err := svc.Validate(ctx, creds.AccessKeyID, creds.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	return creds, sess.Principal
}

func allowed(t *testing.T, e fedEnv, p authz.Principal, action string) bool {
	t.Helper()
	d, err := e.az.Authorize(context.Background(), p, action, "arn:vws:s3:::b/k", nil)
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	return d.Allowed
}

func TestAssumeRoleSessionPolicies(t *testing.T) {
	e := fedSetup(t)
	ctx := context.Background()
	broker := e.caller(t, "broker")

	// The role allows s3:*; without session policies the session has it all.
	_, p := assumeWith(t, e.svc, broker, sts.SessionPolicies{})
	if !allowed(t, e, p, "s3:PutObject") || !allowed(t, e, p, "s3:GetObject") {
		t.Fatal("unscoped session lost role permissions")
	}
	// An empty, non-nil PolicyARNs is no session policy, not "nothing".
	_, p = assumeWith(t, e.svc, broker, sts.SessionPolicies{PolicyARNs: []string{}})
	if !allowed(t, e, p, "s3:PutObject") {
		t.Fatal("empty PolicyArns narrowed the session to nothing")
	}

	// A managed session policy narrows the role to s3:GetObject.
	creds, p := assumeWith(t, e.svc, broker, sts.SessionPolicies{PolicyARNs: []string{s3ReadARN}})
	if !allowed(t, e, p, "s3:GetObject") || allowed(t, e, p, "s3:PutObject") {
		t.Fatalf("managed session policy did not narrow: %+v", p)
	}
	want := (len(s3ReadARN)*100 + sts.MaxPackedPolicyChars - 1) / sts.MaxPackedPolicyChars
	if creds.PackedPolicySize != want {
		t.Fatalf("PackedPolicySize %d, want %d", creds.PackedPolicySize, want)
	}

	// Inline and managed together: each allows what it names, never more
	// than the role.
	_, p = assumeWith(t, e.svc, broker, sts.SessionPolicies{Policy: s3PutOnly, PolicyARNs: []string{s3ReadARN}})
	if !allowed(t, e, p, "s3:GetObject") || !allowed(t, e, p, "s3:PutObject") || allowed(t, e, p, "s3:DeleteObject") {
		t.Fatal("inline plus managed session policies")
	}
	// A session policy never widens: the role does not allow ec2.
	_, p = assumeWith(t, e.svc, broker,
		sts.SessionPolicies{Policy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`})
	if allowed(t, e, p, "ec2:RunInstances") {
		t.Fatal("session policy widened the role")
	}

	// A restart (a new service on the same store and KEK) keeps the scope.
	creds, _ = assumeWith(t, e.svc, broker, sts.SessionPolicies{PolicyARNs: []string{s3ReadARN}})
	restarted := sts.New(e.b, e.keys, authz.New(e.b, acct, e.clk.now), acct, e.clk.now)
	sess, err := restarted.Validate(ctx, creds.AccessKeyID, creds.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed(t, e, sess.Principal, "s3:GetObject") || allowed(t, e, sess.Principal, "s3:PutObject") {
		t.Fatal("session scope lost across restart")
	}

	// A role session chained from a scoped one gets only its own session
	// policies, as in AWS.
	first, _ := assumeWith(t, e.svc, broker, sts.SessionPolicies{Policy: `{"Version":"2012-10-17","Statement":
		{"Effect":"Allow","Action":["sts:AssumeRole","s3:GetObject"],"Resource":"*"}}`})
	fs, err := e.svc.Validate(ctx, first.AccessKeyID, first.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	chained, err := e.svc.AssumeRole(ctx, fs.Caller(), nil, fedAdminARN, "chained", 0,
		sts.SessionPolicies{Policy: s3PutOnly}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := e.svc.Validate(ctx, chained.AccessKeyID, chained.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if allowed(t, e, cs.Principal, "s3:GetObject") || !allowed(t, e, cs.Principal, "s3:PutObject") {
		t.Fatal("chained session inherited the earlier session policies")
	}

	// A repeat issues another, equally scoped session.
	again, p := assumeWith(t, e.svc, broker, sts.SessionPolicies{PolicyARNs: []string{s3ReadARN}})
	if again.AccessKeyID == creds.AccessKeyID || allowed(t, e, p, "s3:PutObject") {
		t.Fatal("repeat AssumeRole")
	}

	// The managed policy is read at each evaluation: once it is deleted,
	// the session fails closed instead of losing its narrowing.
	if err := e.b.Delete(ctx, iam.KindPolicy, "S3Read", ""); err != nil {
		t.Fatal(err)
	}
	if d, err := e.az.Authorize(ctx, sess.Principal, "s3:GetObject", "*", nil); err == nil || d.Allowed {
		t.Fatalf("deleted managed session policy: %+v %v", d, err)
	}
}

func TestAssumeRoleSessionPolicyErrors(t *testing.T) {
	e := fedSetup(t)
	ctx := context.Background()
	callers := map[string]sts.Caller{"broker": e.caller(t, "broker"), "nobody": e.caller(t, "nobody")}
	arns := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = s3ReadARN
		}
		return out
	}
	cases := []struct {
		name string
		sp   sts.SessionPolicies
		want error
	}{
		{
			"policy too long",
			sts.SessionPolicies{Policy: s3PutOnly + strings.Repeat(" ", sts.MaxPackedPolicyChars)},
			sts.ErrInvalidRequest,
		},
		{"policy alphabet", sts.SessionPolicies{Policy: strings.Replace(s3PutOnly, "*", "Ā", 1)}, sts.ErrInvalidRequest},
		{"policy control char", sts.SessionPolicies{Policy: "\x00" + s3PutOnly}, sts.ErrInvalidRequest},
		{"malformed policy", sts.SessionPolicies{Policy: `{"Version":"2012-10-17"}`}, policy.ErrMalformed},
		{"eleven arns", sts.SessionPolicies{PolicyARNs: arns(11)}, sts.ErrInvalidRequest},
		{"short arn", sts.SessionPolicies{PolicyARNs: []string{"arn:vws:iam::x:p"}}, sts.ErrInvalidRequest},
		{"long arn", sts.SessionPolicies{PolicyARNs: []string{s3ReadARN + strings.Repeat("x", 2048)}}, sts.ErrInvalidRequest},
		{
			"packed too large",
			sts.SessionPolicies{Policy: s3PutOnly + strings.Repeat(" ", 1800), PolicyARNs: arns(10)},
			sts.ErrPackedPolicyTooLarge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Parameters are checked before the caller's permissions: an
			// unauthorized caller gets the same validation error.
			for _, user := range []string{"broker", "nobody"} {
				_, err := e.svc.AssumeRole(ctx, callers[user], nil, fedAdminARN, "bad", 0, tc.sp, sts.MFA{})
				if !errors.Is(err, tc.want) {
					t.Fatalf("%s: %v, want %v", user, err, tc.want)
				}
			}
		})
	}

	// A managed session policy must be one of this project's.
	for _, arn := range []string{
		"arn:vws:iam::" + acct + ":policy/Missing",
		"arn:vws:iam::other:policy/S3Read",
		"arn:vws:iam::" + acct + ":policy/team/S3Read", // path does not match
	} {
		_, err := e.svc.AssumeRole(ctx, callers["broker"], nil, fedAdminARN, "bad", 0,
			sts.SessionPolicies{PolicyARNs: []string{arn}}, sts.MFA{})
		if !errors.Is(err, policy.ErrMalformed) {
			t.Fatalf("%s: %v", arn, err)
		}
		// A caller without sts:AssumeRole learns nothing about the policy.
		_, err = e.svc.AssumeRole(ctx, callers["nobody"], nil, fedAdminARN, "bad", 0,
			sts.SessionPolicies{PolicyARNs: []string{arn}}, sts.MFA{})
		if !errors.Is(err, sts.ErrAccessDenied) {
			t.Fatalf("unauthorized %s: %v", arn, err)
		}
	}

	// Nothing above issued a session or wrote to the store.
	ps, err := store.List[iam.Policy](ctx, e.b)
	if err != nil || len(ps) != 1 {
		t.Fatalf("policies after errors: %d %v", len(ps), err)
	}
}
