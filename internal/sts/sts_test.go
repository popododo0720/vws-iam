package sts_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/sts"
)

const acct = "000000000000"

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type env struct {
	b    store.Backend
	clk  *clock
	svc  *sts.Service
	az   *authz.Authorizer
	keys *secret.Keyring
}

func put[T iam.Object](t *testing.T, b store.Backend, o T) {
	if _, err := store.Create(context.Background(), b, o); err != nil {
		t.Fatal(err)
	}
}

const assumeAny = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`

func setup(t *testing.T) env {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring("kek-1", map[string][]byte{"kek-1": k})
	if err != nil {
		t.Fatal(err)
	}
	b := memstore.New()
	put(t, b, iam.User{Name: "alice", ID: "1", InlinePolicies: map[string]string{"assume": assumeAny}})
	put(t, b, iam.User{Name: "eve", ID: "2", InlinePolicies: map[string]string{"assume": assumeAny}})
	put(t, b, iam.User{Name: "bob", ID: "3"})
	put(t, b, iam.Role{Name: "admin", ID: "4", MaxSessionDuration: 12 * time.Hour,
		AssumeRolePolicy: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:vws:iam::` + acct + `:user/alice","arn:vws:iam::` + acct + `:user/bob"]},"Action":"sts:AssumeRole"}]}`,
		InlinePolicies:   map[string]string{"all": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`}})
	put(t, b, iam.Role{Name: "mfa-only", ID: "5",
		AssumeRolePolicy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"` + acct + `"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`,
		InlinePolicies:   map[string]string{"ec2": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*"}}`}})
	clk := &clock{t: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)}
	az := authz.New(b, acct, clk.now)
	return env{b: b, clk: clk, svc: sts.New(b, keys, az, acct, clk.now), az: az, keys: keys}
}

func user(name string, mfa bool) sts.Caller {
	return sts.Caller{Principal: authz.Principal{Kind: authz.User, Name: name}, MFA: mfa}
}

const adminARN = "arn:vws:iam::" + acct + ":role/admin"

func TestAssumeRoleCredentialsWorkThenExpire(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	creds, err := e.svc.AssumeRole(ctx, user("alice", false), adminARN, "deploy-1", 15*time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(creds.AccessKeyID, "ASIA") || len(creds.Secret) != 40 || creds.AssumedRoleARN != "arn:vws:sts::"+acct+":assumed-role/admin/deploy-1" {
		t.Fatalf("credentials %s %s", creds, creds.AssumedRoleARN)
	}
	if strings.Contains(fmt.Sprint(creds), creds.Secret) || strings.Contains(creds.SessionToken, creds.Secret) {
		t.Fatal("secret leaks through String or the token")
	}
	sess, err := e.svc.Validate(creds.AccessKeyID, creds.SessionToken)
	if err != nil || sess.Secret != creds.Secret {
		t.Fatalf("validate: %v", err)
	}
	d, err := e.az.Authorize(ctx, sess.Principal, "s3:PutObject", "arn:vws:s3:::b/k", sess.Context())
	if err != nil || !d.Allowed {
		t.Fatalf("role session not authorized: %+v %v", d, err)
	}
	e.clk.t = e.clk.t.Add(15 * time.Minute)
	if _, err := e.svc.Validate(creds.AccessKeyID, creds.SessionToken); !errors.Is(err, sts.ErrExpired) {
		t.Fatalf("expired session: %v", err)
	}
}

func TestTokenIsBoundTamperEvidentAndSurvivesRestart(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	c1, err := e.svc.AssumeRole(ctx, user("alice", false), adminARN, "s1", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	c2, err := e.svc.AssumeRole(ctx, user("alice", false), adminARN, "s2", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Validate(c2.AccessKeyID, c1.SessionToken); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("token reused with another key id: %v", err)
	}
	b := []byte(c1.SessionToken)
	b[len(b)-2] ^= 1
	for _, tok := range []string{string(b), "", "kek-1.", "x." + strings.SplitN(c1.SessionToken, ".", 2)[1], "garbage"} {
		if _, err := e.svc.Validate(c1.AccessKeyID, tok); !errors.Is(err, sts.ErrInvalidToken) {
			t.Fatalf("bad token %.20q: %v", tok, err)
		}
	}
	// A restarted service with the same keyring accepts the token: nothing
	// about the session lives in memory.
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	if _, err := restarted.Validate(c1.AccessKeyID, c1.SessionToken); err != nil {
		t.Fatal(err)
	}
}

func TestUntrustedPrincipalIsDenied(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	// eve may call sts:AssumeRole, but the trust policy does not name her.
	if _, err := e.svc.AssumeRole(ctx, user("eve", false), adminARN, "x1", 0, ""); !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("eve: %v", err)
	}
	// bob is trusted but has no sts:AssumeRole permission.
	if _, err := e.svc.AssumeRole(ctx, user("bob", false), adminARN, "x1", 0, ""); !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("bob: %v", err)
	}
	for _, arn := range []string{"arn:vws:iam::999999999999:role/admin", "arn:vws:iam::" + acct + ":role/missing", "arn:vws:iam::" + acct + ":role/dev/admin", "admin"} {
		if _, err := e.svc.AssumeRole(ctx, user("alice", false), arn, "x1", 0, ""); !errors.Is(err, sts.ErrAccessDenied) {
			t.Fatalf("%s: %v", arn, err)
		}
	}
}

func TestMFAConditionAndPropagation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role := "arn:vws:iam::" + acct + ":role/mfa-only"
	if _, err := e.svc.AssumeRole(ctx, user("alice", false), role, "m1", 0, ""); !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("without MFA: %v", err)
	}
	creds, err := e.svc.AssumeRole(ctx, user("alice", true), role, "m1", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := e.svc.Validate(creds.AccessKeyID, creds.SessionToken)
	if err != nil || !sess.MFA || sess.Context()["aws:MultiFactorAuthPresent"][0] != "true" {
		t.Fatalf("MFA not propagated: %v %+v", err, sess)
	}
	// GetSessionToken carries MFA into a user session.
	st, err := e.svc.GetSessionToken(ctx, user("alice", true), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	us, err := e.svc.Validate(st.AccessKeyID, st.SessionToken)
	if err != nil || !us.MFA || us.Principal.Kind != authz.User || us.Principal.Name != "alice" {
		t.Fatalf("user session %v %+v", err, us)
	}
	if _, err := e.svc.AssumeRole(ctx, us.Caller(nil), role, "m2", 0, ""); err != nil {
		t.Fatalf("MFA session could not assume: %v", err)
	}
	if _, err := e.svc.GetSessionToken(ctx, us.Caller(nil), time.Hour); !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("GetSessionToken from a session: %v", err)
	}
}

func TestSessionPolicyNarrows(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	creds, err := e.svc.AssumeRole(ctx, user("alice", false), adminARN, "narrow", 0, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := e.svc.Validate(creds.AccessKeyID, creds.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := e.az.Authorize(ctx, sess.Principal, "s3:GetObject", "arn:vws:s3:::b/k", nil); err != nil || !d.Allowed {
		t.Fatalf("GetObject: %+v %v", d, err)
	}
	if d, err := e.az.Authorize(ctx, sess.Principal, "ec2:RunInstances", "*", nil); err != nil || d.Allowed {
		t.Fatalf("RunInstances allowed through a narrowing session policy: %+v %v", d, err)
	}
	if _, err := e.svc.AssumeRole(ctx, user("alice", false), adminARN, "bad", 0, `{"Version":"2012-10-17"}`); !errors.Is(err, policy.ErrMalformed) {
		t.Fatalf("malformed session policy: %v", err)
	}
}

func TestDurationAndNameBounds(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for _, d := range []time.Duration{14 * time.Minute, 12*time.Hour + time.Second} {
		if _, err := e.svc.AssumeRole(ctx, user("alice", false), adminARN, "d1", d, ""); !errors.Is(err, sts.ErrInvalidRequest) {
			t.Fatalf("%s: %v", d, err)
		}
	}
	if c, err := e.svc.AssumeRole(ctx, user("alice", false), adminARN, "d1", 12*time.Hour, ""); err != nil || !c.Expiration.Equal(e.clk.t.Add(12*time.Hour)) {
		t.Fatalf("12h: %v %v", err, c.Expiration)
	}
	for _, n := range []string{"", "a", "has space", strings.Repeat("x", 65)} {
		if _, err := e.svc.AssumeRole(ctx, user("alice", false), adminARN, n, 0, ""); !errors.Is(err, sts.ErrInvalidRequest) {
			t.Fatalf("name %q: %v", n, err)
		}
	}
	// Role chaining caps the session at one hour.
	c, err := e.svc.GetSessionToken(ctx, user("alice", false), 0)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.svc.Validate(c.AccessKeyID, c.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AssumeRole(ctx, s.Caller(nil), adminARN, "chain", 2*time.Hour, ""); !errors.Is(err, sts.ErrInvalidRequest) {
		t.Fatalf("chained 2h: %v", err)
	}
	if _, err := e.svc.GetSessionToken(ctx, user("alice", false), 37*time.Hour); !errors.Is(err, sts.ErrInvalidRequest) {
		t.Fatalf("37h session token: %v", err)
	}
}
