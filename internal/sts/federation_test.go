package sts_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/sts"
)

const (
	s3ReadARN  = "arn:vws:iam::" + acct + ":policy/S3Read"
	s3PutOnly  = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}}`
	fedBobARN  = "arn:vws:sts::" + acct + ":federated-user/bob"
	fedAllowed = `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"sts:GetFederationToken","Resource":"arn:vws:sts::` + acct + `:federated-user/*"},
		{"Effect":"Allow","Action":["s3:*","sts:AssumeRole"],"Resource":"*"},
		{"Effect":"Deny","Action":"sts:GetFederationToken","Resource":"*",
		 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`
)

type fedEnv struct {
	b    store.Backend
	clk  *clock
	keys *secret.Keyring
	az   *authz.Authorizer
	svc  *sts.Service
}

func fedSetup(t *testing.T) fedEnv {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring("kek-1", map[string][]byte{"kek-1": k})
	if err != nil {
		t.Fatal(err)
	}
	b := memstore.New()
	put(t, b, iam.Policy{Name: "S3Read", ID: "p1", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{
		ID:       "v1",
		Document: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`,
	}}})
	put(t, b, iam.User{Name: "broker", ID: "AIDABROKER", InlinePolicies: map[string]string{"fed": fedAllowed}})
	put(t, b, iam.User{Name: "nobody", ID: "AIDANOBODY"})
	put(t, b, iam.Role{
		Name: "admin", ID: "AROAADMIN", MaxSessionDuration: time.Hour,
		AssumeRolePolicy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"` + acct +
			`"},"Action":"sts:AssumeRole"}}`,
		InlinePolicies: map[string]string{"fed": fedAllowed},
	})
	clk := &clock{t: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)}
	az := authz.New(b, acct, clk.now)
	return fedEnv{b: b, clk: clk, keys: keys, az: az, svc: sts.New(b, keys, az, acct, clk.now)}
}

func (e fedEnv) caller(t *testing.T, user string) sts.Caller {
	t.Helper()
	cred, err := accesskey.New(e.b, e.b, acct, e.keys, e.clk.now).Create(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.svc.Resolve(context.Background(), sts.Credential{AccessKeyID: cred.AccessKeyID})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e fedEnv) session(t *testing.T, creds sts.Credentials) sts.Session {
	t.Helper()
	s, err := e.svc.Validate(context.Background(), creds.AccessKeyID, creds.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e fedEnv) allowed(t *testing.T, s sts.Session, action string) bool {
	t.Helper()
	d, err := e.az.Authorize(context.Background(), s.Principal, action, "*", s.Context())
	if err != nil {
		t.Fatal(err)
	}
	return d.Allowed
}

// TestGetFederationToken: an IAM user with long-term credentials gets a
// federated user session whose permissions are the intersection of its
// own and the session policies; the session is a sealed token that a
// restarted service accepts until it expires.
func TestGetFederationToken(t *testing.T) {
	e := fedSetup(t)
	ctx := context.Background()
	tok, err := e.svc.GetFederationToken(ctx, e.caller(t, "broker"), nil, sts.FederationRequest{
		Name: "bob", Policy: s3PutOnly, PolicyARNs: []string{s3ReadARN},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := tok.Credentials
	if tok.ARN != fedBobARN || tok.FederatedUserID != acct+":bob" {
		t.Fatalf("federated user %s %s", tok.ARN, tok.FederatedUserID)
	}
	if !strings.HasPrefix(c.AccessKeyID, "ASIA") || len(c.Secret) != 40 || c.SessionToken == "" {
		t.Fatalf("credentials %s", c)
	}
	if !c.Expiration.Equal(e.clk.t.Add(sts.DefaultFederationDuration)) {
		t.Fatalf("expiration %v", c.Expiration)
	}
	want := (len(s3PutOnly) + len(s3ReadARN)) * 100 / sts.MaxPackedPolicyChars
	if tok.PackedPolicySize < want || tok.PackedPolicySize > want+1 {
		t.Fatalf("PackedPolicySize %d, want about %d", tok.PackedPolicySize, want)
	}
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprint(c), c.SessionToken} {
		if strings.Contains(s, c.Secret) {
			t.Fatal("secret leaks through String or the token")
		}
	}

	s := e.session(t, c)
	if !s.Federated || s.SessionName != "bob" || s.Principal.ARN != fedBobARN || s.Principal.Name != "broker" {
		t.Fatalf("session %+v", s)
	}
	for action, ok := range map[string]bool{
		"s3:GetObject":     true,  // managed session policy, allowed to broker
		"s3:PutObject":     true,  // inline session policy, allowed to broker
		"s3:DeleteObject":  false, // broker may, no session policy does
		"ec2:RunInstances": false,
		"iam:ListUsers":    false,
		"sts:AssumeRole":   false, // allowed to broker, refused to a federated session
	} {
		if got := e.allowed(t, s, action); got != ok {
			t.Errorf("%s: allowed %v, want %v", action, got, ok)
		}
	}

	// Nothing about the session lives in memory.
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	if _, err := restarted.Validate(ctx, c.AccessKeyID, c.SessionToken); err != nil {
		t.Fatal(err)
	}
	e.clk.t = e.clk.t.Add(sts.DefaultFederationDuration)
	if _, err := e.svc.Validate(ctx, c.AccessKeyID, c.SessionToken); !errors.Is(err, sts.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
}

// TestGetFederationTokenWithoutPolicyHasNoPermissions: as in AWS, a
// session without session policies can do nothing, even for a caller
// allowed everything.
func TestGetFederationTokenWithoutPolicyHasNoPermissions(t *testing.T) {
	e := fedSetup(t)
	ctx := context.Background()
	tok, err := e.svc.GetFederationToken(ctx, e.caller(t, "broker"), nil, sts.FederationRequest{Name: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if tok.PackedPolicySize != 0 {
		t.Fatalf("PackedPolicySize %d", tok.PackedPolicySize)
	}
	s := e.session(t, tok.Credentials)
	for _, action := range []string{"s3:GetObject", "s3:PutObject", "sts:GetFederationToken"} {
		if e.allowed(t, s, action) {
			t.Errorf("%s allowed without a session policy", action)
		}
	}
}

// TestGetFederationTokenCallers: only long-term credentials of an IAM
// user or the root user may call it, with sts:GetFederationToken on the
// federated user; a root session is capped at one hour and still
// narrowed by its session policies.
func TestGetFederationTokenCallers(t *testing.T) {
	e := fedSetup(t)
	ctx := context.Background()
	broker := e.caller(t, "broker")
	req := sts.FederationRequest{Name: "bob", Policy: s3PutOnly}

	st, err := e.svc.GetSessionToken(ctx, broker, time.Hour, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	temp, err := e.svc.Resolve(ctx, sts.Credential{AccessKeyID: st.AccessKeyID, SessionToken: st.SessionToken})
	if err != nil {
		t.Fatal(err)
	}
	ar, err := e.svc.AssumeRole(ctx, broker, nil, "arn:vws:iam::"+acct+":role/admin", "s1", 0, "", sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	role, err := e.svc.Resolve(ctx, sts.Credential{AccessKeyID: ar.AccessKeyID, SessionToken: ar.SessionToken})
	if err != nil {
		t.Fatal(err)
	}
	fed, err := e.svc.GetFederationToken(ctx, broker, nil, sts.FederationRequest{Name: "bob", Policy: fedAllowed})
	if err != nil {
		t.Fatal(err)
	}
	fedCaller := e.session(t, fed.Credentials).Caller()
	for name, c := range map[string]sts.Caller{
		"session token": temp, "assumed role": role, "federated user": fedCaller,
		"no permission": e.caller(t, "nobody"), "unresolved": {},
	} {
		if _, err := e.svc.GetFederationToken(ctx, c, nil, req); !errors.Is(err, sts.ErrAccessDenied) {
			t.Errorf("%s: %v, want AccessDenied", name, err)
		}
	}
	// A federated session cannot assume a role either.
	if _, err := e.svc.AssumeRole(ctx, fedCaller, nil, "arn:vws:iam::"+acct+":role/admin", "s2", 0, "",
		sts.MFA{}); !errors.Is(err, sts.ErrAccessDenied) {
		t.Errorf("federated AssumeRole: %v", err)
	}
	// The trusted request context applies.
	from := map[string][]string{"aws:SourceIp": {"10.1.2.3"}}
	if _, err := e.svc.GetFederationToken(ctx, broker, from, req); !errors.Is(err, sts.ErrAccessDenied) {
		t.Errorf("IP-conditioned deny: %v", err)
	}

	root := sts.RootCaller(false, time.Time{})
	for _, d := range []time.Duration{0, 2 * time.Hour, sts.MaxFederationDuration} {
		r := sts.FederationRequest{Name: "ops", Duration: d, Policy: s3PutOnly}
		tok, err := e.svc.GetFederationToken(ctx, root, nil, r)
		if err != nil {
			t.Fatal(err)
		}
		if got := tok.Credentials.Expiration.Sub(e.clk.t); got != sts.RootFederationMaxDuration {
			t.Fatalf("root %v: lasts %v", d, got)
		}
		s := e.session(t, tok.Credentials)
		if !e.allowed(t, s, "s3:PutObject") || e.allowed(t, s, "s3:GetObject") || e.allowed(t, s, "iam:CreateUser") {
			t.Fatal("root federated session is not narrowed by its session policy")
		}
	}
	tok, err := e.svc.GetFederationToken(ctx, root, nil, sts.FederationRequest{Name: "ops", Duration: 30 * time.Minute})
	if err != nil || tok.Credentials.Expiration.Sub(e.clk.t) != 30*time.Minute {
		t.Fatalf("root 30m: %v, %v", tok.Credentials.Expiration, err)
	}
}

// TestGetFederationTokenRevokedWithUser: revoking the user's sessions,
// or deleting and recreating the user, ends its federated sessions.
func TestGetFederationTokenRevokedWithUser(t *testing.T) {
	e := fedSetup(t)
	ctx := context.Background()
	broker := e.caller(t, "broker")
	issue := func() sts.Credentials {
		tok, err := e.svc.GetFederationToken(ctx, broker, nil, sts.FederationRequest{Name: "bob"})
		if err != nil {
			t.Fatal(err)
		}
		return tok.Credentials
	}
	c := issue()
	if err := e.svc.RevokeSessions(ctx, authz.User, "broker"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Validate(ctx, c.AccessKeyID, c.SessionToken); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("revoked: %v", err)
	}
	c = issue()
	if err := e.b.Delete(ctx, iam.KindUser, "broker", ""); err != nil {
		t.Fatal(err)
	}
	put(t, e.b, iam.User{Name: "broker", ID: "AIDAOTHER", InlinePolicies: map[string]string{"fed": fedAllowed}})
	if _, err := e.svc.Validate(ctx, c.AccessKeyID, c.SessionToken); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("recreated user: %v", err)
	}
}

// TestGetFederationTokenValidation: the AWS parameter constraints and
// error codes, checked before anything is issued.
func TestGetFederationTokenValidation(t *testing.T) {
	e := fedSetup(t)
	ctx := context.Background()
	broker := e.caller(t, "broker")
	pad := func(n int) string { return s3PutOnly + strings.Repeat(" ", n-len(s3PutOnly)) }
	arns := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = s3ReadARN
		}
		return out
	}
	for _, c := range []struct {
		name string
		req  sts.FederationRequest
		want error // nil means success
	}{
		{"min name", sts.FederationRequest{Name: "ab"}, nil},
		{"max name", sts.FederationRequest{Name: strings.Repeat("a", 32)}, nil},
		{"name charset", sts.FederationRequest{Name: "a_b+c=d,e.f@g-h"}, nil},
		{"empty name", sts.FederationRequest{}, sts.ErrInvalidRequest},
		{"short name", sts.FederationRequest{Name: "a"}, sts.ErrInvalidRequest},
		{"long name", sts.FederationRequest{Name: strings.Repeat("a", 33)}, sts.ErrInvalidRequest},
		{"name with space", sts.FederationRequest{Name: "bo b"}, sts.ErrInvalidRequest},
		{"name with slash", sts.FederationRequest{Name: "bo/b"}, sts.ErrInvalidRequest},
		{"name with newline", sts.FederationRequest{Name: "bob\n"}, sts.ErrInvalidRequest},
		{"non-ASCII name", sts.FederationRequest{Name: "böb"}, sts.ErrInvalidRequest},
		{"min duration", sts.FederationRequest{Name: "bob", Duration: 900 * time.Second}, nil},
		{"max duration", sts.FederationRequest{Name: "bob", Duration: 129600 * time.Second}, nil},
		{"short duration", sts.FederationRequest{Name: "bob", Duration: 899 * time.Second}, sts.ErrInvalidRequest},
		{"long duration", sts.FederationRequest{Name: "bob", Duration: 129601 * time.Second}, sts.ErrInvalidRequest},
		{"negative duration", sts.FederationRequest{Name: "bob", Duration: -time.Second}, sts.ErrInvalidRequest},
		{"policy at limit", sts.FederationRequest{Name: "bob", Policy: pad(2048)}, nil},
		{"policy over limit", sts.FederationRequest{Name: "bob", Policy: pad(2049)}, sts.ErrInvalidRequest},
		{"policy control character", sts.FederationRequest{Name: "bob", Policy: s3PutOnly + "\x00"}, sts.ErrInvalidRequest},
		{"policy outside latin-1", sts.FederationRequest{Name: "bob", Policy: s3PutOnly + "\u0100"}, sts.ErrInvalidRequest},
		{"malformed policy", sts.FederationRequest{Name: "bob", Policy: `{"Version":`}, policy.ErrMalformed},
		{"policy with principal", sts.FederationRequest{Name: "bob", Policy: `{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}}`}, policy.ErrMalformed},
		{"ten policy arns", sts.FederationRequest{Name: "bob", PolicyARNs: arns(10)}, nil},
		{"eleven policy arns", sts.FederationRequest{Name: "bob", PolicyARNs: arns(11)}, sts.ErrInvalidRequest},
		{
			"short policy arn",
			sts.FederationRequest{Name: "bob", PolicyARNs: []string{"arn:vws:iam::x"}},
			sts.ErrInvalidRequest,
		},
		{"unknown policy arn", sts.FederationRequest{
			Name:       "bob",
			PolicyARNs: []string{"arn:vws:iam::" + acct + ":policy/Missing"},
		}, policy.ErrMalformed},
		{"other project policy arn", sts.FederationRequest{
			Name:       "bob",
			PolicyARNs: []string{"arn:vws:iam::111111111111:policy/S3Read"},
		}, policy.ErrMalformed},
		{
			"packed too large",
			sts.FederationRequest{Name: "bob", Policy: pad(2000), PolicyARNs: arns(2)},
			sts.ErrPackedPolicyTooLarge,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			tok, err := e.svc.GetFederationToken(ctx, broker, nil, c.req)
			switch {
			case c.want == nil && err != nil:
				t.Fatalf("unexpected error %v", err)
			case c.want != nil && !errors.Is(err, c.want):
				t.Fatalf("got %v, want %v", err, c.want)
			case c.want != nil && tok.Credentials.SessionToken != "":
				t.Fatal("credentials returned with an error")
			}
		})
	}
}
