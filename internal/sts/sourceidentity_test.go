package sts_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

const (
	assumeAndSI = `{"Version":"2012-10-17","Statement":{"Effect":"Allow",
		"Action":["sts:AssumeRole","sts:SetSourceIdentity"],"Resource":"*"}}`
)

// sourceIdentityOf is the source identity of the session c on svc, as
// Validate and the checked session reference report it, and as their
// request context keys carry it.
func sourceIdentityOf(ctx context.Context, t *testing.T, svc *sts.Service, c sts.Credentials) string {
	t.Helper()
	sess, err := svc.Validate(ctx, c.AccessKeyID, c.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := svc.MintSessionRef(c.AccessKeyID, c.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := svc.CheckSessionRef(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	refCtx := map[string][]string{}
	checked.AddSessionContext(refCtx)
	ctxKey, refKey := sess.Context()["aws:SourceIdentity"], refCtx["aws:SourceIdentity"]
	if !slices.Equal(ctxKey, refKey) || (sess.SourceIdentity == "") != (ctxKey == nil) ||
		(ctxKey != nil && !slices.Equal(ctxKey, []string{sess.SourceIdentity})) {
		t.Fatalf("source identity %q, session context %v, reference context %v", sess.SourceIdentity, ctxKey, refKey)
	}
	return sess.SourceIdentity
}

// TestSAMLSourceIdentityIsSealed: the SourceIdentity attribute of a SAML
// assertion is kept in the session token and its reference, also on a
// restarted service and for a repeated assertion; an assertion without it
// gives a session without one (#359).
func TestSAMLSourceIdentityIsSealed(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	for range 2 {
		got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
		if err != nil {
			t.Fatal(err)
		}
		for _, svc := range []*sts.Service{e.svc, restarted} {
			if si := sourceIdentityOf(ctx, t, svc, got.Credentials); si != "alice" {
				t.Fatalf("source identity %q, want alice", si)
			}
		}
	}
	a := e.claims()
	a.SourceIdentity = ""
	got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
	if err != nil {
		t.Fatal(err)
	}
	if si := sourceIdentityOf(ctx, t, restarted, got.Credentials); si != "" {
		t.Fatalf("source identity %q without the attribute", si)
	}
}

// TestChainedAssumeRoleKeepsSourceIdentity: a role session chained from a
// SAML session keeps its source identity, through any number of hops and
// a restart; trust and permission policies see it as aws:SourceIdentity
// and sts:SourceIdentity; both must allow sts:SetSourceIdentity; a
// different SourceIdentity is AccessDenied; a client's copy of either key
// is dropped (#359).
func TestChainedAssumeRoleKeepsSourceIdentity(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	inline := func(role, doc string) {
		t.Helper()
		if _, err := store.Mutate(ctx, e.b, role, func(r *iam.Role) error {
			r.InlinePolicies["sts"] = doc
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	inline("saml-dev", assumeAndSI)
	inline("admin", assumeAndSI)
	if _, err := store.Mutate(ctx, e.b, "broker", func(u *iam.User) error {
		u.InlinePolicies["sts"] = assumeAndSI
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	trust := func(actions, cond string) {
		t.Helper()
		if cond != "" {
			cond = `,"Condition":{"StringEquals":` + cond + `}`
		}
		if _, err := store.Mutate(ctx, e.b, "admin", func(r *iam.Role) error {
			r.AssumeRolePolicy = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"` +
				acct + `"},"Action":` + actions + cond + `}}`
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := e.svc.Validate(ctx, got.Credentials.AccessKeyID, got.Credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	samlCaller, broker := sess.Caller(), e.caller(t, "broker")
	const both = `["sts:AssumeRole","sts:SetSourceIdentity"]`
	for _, tc := range []struct {
		name, actions, cond string
		caller              sts.Caller
		reqCtx              map[string][]string
		param               string
		want                error
		wantSI              string
	}{
		{"chained keeps it", both, `{"aws:SourceIdentity":"alice"}`, samlCaller, nil, "", nil, "alice"},
		{"chained sees sts:SourceIdentity", both, `{"sts:SourceIdentity":"alice"}`, samlCaller, nil, "", nil, "alice"},
		{"chained repeats it", both, `{"aws:SourceIdentity":"alice"}`, samlCaller, nil, "alice", nil, "alice"},
		{"chained changes it", both, "", samlCaller, nil, "bob", sts.ErrAccessDenied, ""},
		{"chained other value in trust", both, `{"aws:SourceIdentity":"bob"}`, samlCaller, nil, "", sts.ErrAccessDenied, ""},
		{"trust lacks sts:SetSourceIdentity", `"sts:AssumeRole"`, "", samlCaller, nil, "", sts.ErrAccessDenied, ""},
		{
			"client aws:SourceIdentity", both, `{"aws:SourceIdentity":"alice"}`, broker,
			map[string][]string{"AWS:SourceIdentity": {"alice"}},
			"", sts.ErrAccessDenied, "",
		},
		{
			"client sts:SourceIdentity", both, `{"sts:SourceIdentity":"alice"}`, broker,
			map[string][]string{"sts:sourceidentity": {"alice"}},
			"", sts.ErrAccessDenied, "",
		},
		{
			"client replaces the session's", both, `{"aws:SourceIdentity":"bob"}`, samlCaller,
			map[string][]string{"aws:SourceIdentity": {"bob"}},
			"", sts.ErrAccessDenied, "",
		},
		{"user sets it", both, `{"sts:SourceIdentity":"bob"}`, broker, nil, "bob", nil, "bob"},
		{"user sets it without trust", `"sts:AssumeRole"`, "", broker, nil, "bob", sts.ErrAccessDenied, ""},
		{"user without one", `"sts:AssumeRole"`, "", broker, nil, "", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust(tc.actions, tc.cond)
			c, err := e.svc.AssumeRole(ctx, tc.caller, tc.reqCtx, adminARN, "chain", 0, sts.SessionPolicies{}, sts.MFA{},
				sts.SourceIdentity(tc.param))
			if !errors.Is(err, tc.want) {
				t.Fatalf("AssumeRole: %v, want %v", err, tc.want)
			}
			if err != nil {
				return
			}
			if si := sourceIdentityOf(ctx, t, e.svc, c); si != tc.wantSI {
				t.Fatalf("source identity %q, want %q", si, tc.wantSI)
			}
		})
	}

	// A second hop, on a restarted service, keeps it too.
	trust(both, `{"aws:SourceIdentity":"alice"}`)
	first, err := e.svc.AssumeRole(ctx, samlCaller, nil, adminARN, "hop1", 0, sts.SessionPolicies{}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	hop1, err := restarted.Validate(ctx, first.AccessKeyID, first.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	second, err := restarted.AssumeRole(ctx, hop1.Caller(), nil, adminARN, "hop2", 0, sts.SessionPolicies{}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	if si := sourceIdentityOf(ctx, t, restarted, second); si != "alice" {
		t.Fatalf("second hop source identity %q", si)
	}

	// The caller's permissions must allow sts:SetSourceIdentity too.
	inline("saml-dev", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`)
	_, err = e.svc.AssumeRole(ctx, samlCaller, nil, adminARN, "chain", 0, sts.SessionPolicies{}, sts.MFA{})
	if !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("chained without sts:SetSourceIdentity permission: %v", err)
	}
}

// TestSourceIdentityParameter: AssumeRole takes 2 to 64 characters of
// [\w+=,.@-] as AWS does, before any read; the other calls that issue a
// session refuse the parameter.
func TestSourceIdentityParameter(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	if _, err := store.Mutate(ctx, e.b, "admin", func(r *iam.Role) error {
		r.AssumeRolePolicy = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"` + acct +
			`"},"Action":["sts:AssumeRole","sts:SetSourceIdentity"]}}`
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Mutate(ctx, e.b, "broker", func(u *iam.User) error {
		u.InlinePolicies["sts"] = assumeAndSI
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	broker := e.caller(t, "broker")
	assume := func(si string) error {
		_, err := e.svc.AssumeRole(ctx, broker, nil, adminARN, "si-session", 0, sts.SessionPolicies{}, sts.MFA{},
			sts.SourceIdentity(si))
		return err
	}
	for _, si := range []string{"a", strings.Repeat("x", 65), "aws:alice", "has space", "tab\t", "ünicode"} {
		if err := assume(si); !errors.Is(err, sts.ErrInvalidRequest) {
			t.Errorf("SourceIdentity %q: %v, want ValidationError", si, err)
		}
	}
	for _, si := range []string{"ab", strings.Repeat("x", 64), "a_b+c=d,e.f@g-h"} {
		if err := assume(si); err != nil {
			t.Errorf("SourceIdentity %q: %v", si, err)
		}
	}
	_, err := e.svc.GetSessionToken(ctx, broker, 0, sts.MFA{}, sts.SourceIdentity("alice"))
	if !errors.Is(err, sts.ErrInvalidRequest) {
		t.Errorf("GetSessionToken with SourceIdentity: %v", err)
	}
	if _, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)),
		sts.SourceIdentity("alice")); !errors.Is(err, sts.ErrInvalidRequest) {
		t.Errorf("AssumeRoleWithSAML with SourceIdentity: %v", err)
	}
}

// TestAuthorizeSeesSourceIdentity: a permission policy conditioned on
// aws:SourceIdentity applies to a session that holds it and not to one
// without it (#359).
func TestAuthorizeSeesSourceIdentity(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	if _, err := store.Mutate(ctx, e.b, "saml-dev", func(r *iam.Role) error {
		r.InlinePolicies["deny"] = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject",
			"Resource":"*","Condition":{"StringEquals":{"aws:SourceIdentity":"alice"}}}}`
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		si      string
		allowed bool
	}{{"alice", false}, {"bob", true}, {"", true}} {
		a := e.claims()
		a.SourceIdentity = tc.si
		got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
		if err != nil {
			t.Fatal(err)
		}
		sess, err := e.svc.Validate(ctx, got.Credentials.AccessKeyID, got.Credentials.SessionToken)
		if err != nil {
			t.Fatal(err)
		}
		d, err := e.az.Authorize(ctx, sess.Principal, "s3:GetObject", "arn:vws:s3:::b/k", sess.Context())
		if err != nil || d.Allowed != tc.allowed {
			t.Errorf("source identity %q: allowed %v (%v), want %v", tc.si, d.Allowed, err, tc.allowed)
		}
	}
}

// TestSAMLSourceIdentityWithSourceIP: a session issued with the transport
// source address (#432) keeps the assertion's source identity, and the
// address is not carried into the session (#359).
func TestSAMLSourceIdentityWithSourceIP(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	req := samlReq(e.response(t, e.claims(), samltest.SignAssertion))
	req.SourceIP = "192.0.2.9"
	got, err := e.svc.AssumeRoleWithSAML(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if si := sourceIdentityOf(ctx, t, e.svc, got.Credentials); si != "alice" {
		t.Fatalf("source identity %q, want alice", si)
	}
	sess, err := e.svc.Validate(ctx, got.Credentials.AccessKeyID, got.Credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if v := sess.Context()["aws:SourceIp"]; v != nil {
		t.Fatalf("session carries aws:SourceIp %v", v)
	}
}
