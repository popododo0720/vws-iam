package sts_test

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

func samlContext(t *testing.T, svc *sts.Service, c sts.Credentials) map[string][]string {
	t.Helper()
	ref, err := svc.MintSessionRef(c.AccessKeyID, c.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.CheckSessionRef(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string][]string{}
	got.AddSAMLContext(m)
	return m
}

// TestSessionRefCarriesSAMLIdentity: the reference of a SAML session, and
// of a role session chained from it, carries saml:sub, saml:sub_type and
// saml:namequalifier through a restart; a plain session's carries none (#202).
func TestSessionRefCarriesSAMLIdentity(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	for _, mutate := range []func() error{
		func() error {
			_, err := store.Mutate(ctx, e.b, "saml-dev", func(r *iam.Role) error {
				r.InlinePolicies["sts"] = assumeAny
				return nil
			})
			return err
		},
		func() error {
			_, err := store.Mutate(ctx, e.b, "broker", func(u *iam.User) error {
				u.InlinePolicies["sts"] = assumeAny
				return nil
			})
			return err
		},
	} {
		if err := mutate(); err != nil {
			t.Fatal(err)
		}
	}
	saml, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
	if err != nil {
		t.Fatal(err)
	}
	sess, err := e.svc.Validate(ctx, saml.Credentials.AccessKeyID, saml.Credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	chained, err := e.svc.AssumeRole(ctx, sess.Caller(), nil, adminARN, "chain", 0, sts.SessionPolicies{}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := e.svc.AssumeRole(ctx, e.caller(t, "broker"), nil, adminARN, "plain", 0, sts.SessionPolicies{}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string][]string{
		"saml:sub": {"alice@corp.test"}, "saml:sub_type": {"persistent"}, "saml:namequalifier": {saml.NameQualifier},
	}
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	for name, c := range map[string]sts.Credentials{"SAML session": saml.Credentials, "chained session": chained} {
		for _, svc := range []*sts.Service{e.svc, restarted} {
			got := samlContext(t, svc, c)
			if len(got) != len(want) {
				t.Errorf("%s: context %v, want %v", name, got, want)
			}
			for k, v := range want {
				if len(got[k]) != 1 || got[k][0] != v[0] {
					t.Errorf("%s: %s = %v, want %v", name, k, got[k], v)
				}
			}
		}
	}
	if got := samlContext(t, e.svc, plain); len(got) != 0 {
		t.Errorf("plain session context %v, want none", got)
	}
}

// TestSessionRefOfLongestSAMLSubject: a session whose NameID is as long as
// the assertion limit lets it be is still checked by its reference.
func TestSessionRefOfLongestSAMLSubject(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	var cred sts.Credentials
	var subject string
	for n := 20000; n > 0 && cred.AccessKeyID == ""; n -= 500 {
		subject = strings.Repeat("<", n)
		a := e.claims()
		a.NameID = subject
		got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
		switch {
		case err == nil:
			cred = got.Credentials
		case !errors.Is(err, sts.ErrInvalidRequest):
			t.Fatal(err)
		}
	}
	if cred.AccessKeyID == "" || len(subject) < 10000 {
		t.Fatalf("no long subject was accepted (%d characters)", len(subject))
	}
	ref, err := e.svc.MintSessionRef(cred.AccessKeyID, cred.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(ref) <= 4096 {
		t.Fatalf("reference is %d characters, want more than the old bound", len(ref))
	}
	got := samlContext(t, e.svc, cred)
	if v := got["saml:sub"]; len(v) != 1 || v[0] != subject {
		t.Fatalf("saml:sub has %d values, want the %d-character subject", len(v), len(subject))
	}
}

// TestSessionRefSAMLSurvivesRestartAndKEKRotation: the SAML identity in a
// reference opens on a restarted service and after a KEK rotation while the
// sealing KEK is in the ring, and not once it is retired.
func TestSessionRefSAMLSurvivesRestartAndKEKRotation(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	k1, k2 := make([]byte, 32), make([]byte, 32)
	for _, k := range [][]byte{k1, k2} {
		if _, err := rand.Read(k); err != nil {
			t.Fatal(err)
		}
	}
	ring := func(active string, keys map[string][]byte) *secret.Keyring {
		t.Helper()
		r, err := secret.NewKeyring(active, keys)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	provs := sts.WithSAML(samltest.Providers{samlIdpARN: e.idp.Provider(samlIdpARN)}, samlSP)
	oldRing := ring("kek-1", map[string][]byte{"kek-1": k1})
	old := sts.New(e.b, oldRing, e.az, acct, e.clk.now, provs)
	got, err := old.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := old.MintSessionRef(got.Credentials.AccessKeyID, got.Credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	sub := func(svc *sts.Service) (string, error) {
		r, err := svc.CheckSessionRef(ctx, ref)
		m := map[string][]string{}
		r.AddSAMLContext(m)
		return strings.Join(m["saml:sub"], ","), err
	}
	both := ring("kek-2", map[string][]byte{"kek-1": k1, "kek-2": k2})
	for name, svc := range map[string]*sts.Service{
		"same ring": old,
		"restart":   sts.New(e.b, oldRing, e.az, acct, e.clk.now),
		"rotated":   sts.New(e.b, both, e.az, acct, e.clk.now),
	} {
		if s, err := sub(svc); err != nil || s != "alice@corp.test" {
			t.Errorf("%s: saml:sub %q, %v", name, s, err)
		}
	}
	retired := sts.New(e.b, ring("kek-2", map[string][]byte{"kek-2": k2}), e.az, acct, e.clk.now)
	if s, err := sub(retired); !errors.Is(err, sts.ErrInvalidToken) || s != "" {
		t.Errorf("retired KEK: saml:sub %q, %v", s, err)
	}
}
