package sts_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // NameQualifier is SHA-1 by the AWS definition.
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

const (
	samlAud     = "https://signin.vws.test/saml"
	samlIdpARN  = "arn:vws:iam::" + acct + ":saml-provider/corp"
	samlRoleARN = "arn:vws:iam::" + acct + ":role/saml-dev"
	samlIssuer  = "https://idp.corp.test/saml"
	samlTrust   = `{"Version":"2012-10-17","Statement":{"Effect":"Allow",
		"Principal":{"Federated":"` + samlIdpARN + `"},"Action":"sts:AssumeRoleWithSAML",
		"Condition":{"StringEquals":{"SAML:aud":"` + samlAud + `"}}}}`
)

type samlEnv struct {
	fedEnv
	idp *samltest.IdP
	svc *sts.Service
}

func samlSetup(t *testing.T) samlEnv {
	t.Helper()
	e := fedSetup(t)
	idp, err := samltest.New(samlIssuer, e.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	put(t, e.b, iam.Role{
		Name: "saml-dev", ID: "AROASAMLDEV", MaxSessionDuration: 4 * time.Hour, AssumeRolePolicy: samlTrust,
		InlinePolicies: map[string]string{"s3": `{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`},
	})
	provs := samltest.Providers{samlIdpARN: idp.Provider(samlIdpARN)}
	return samlEnv{fedEnv: e, idp: idp, svc: sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithSAML(provs, samlAud))}
}

// claims is a valid assertion for saml-dev, as an IdP issues it now.
func (e samlEnv) claims() samltest.Assertion {
	now := e.clk.now()
	return samltest.Assertion{
		Issuer: samlIssuer, Audience: samlAud, Recipient: samlAud, Destination: samlAud,
		NameID: "alice@corp.test", NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		Roles:       []string{samlIdpARN + "," + samlRoleARN},
		SessionName: "alice@corp.test", SourceIdentity: "alice",
		NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
		ConfirmNotOnOrAfter: now.Add(5 * time.Minute),
	}
}

func (e samlEnv) response(t *testing.T, a samltest.Assertion, sign samltest.Sign) string {
	t.Helper()
	r, err := e.idp.Response(a, sign)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func samlReq(assertion string) sts.SAMLRequest {
	return sts.SAMLRequest{RoleARN: samlRoleARN, PrincipalARN: samlIdpARN, Assertion: assertion}
}

// TestAssumeRoleWithSAML: a response signed by the provider's IdP (the
// assertion, the response, or both) gets role credentials with the AWS
// response fields; the session is the role narrowed by the session
// policy, survives a restart, ends on role revocation, and every call
// issues new credentials.
func TestAssumeRoleWithSAML(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	for _, sign := range []samltest.Sign{samltest.SignAssertion, samltest.SignResponse, samltest.SignBoth} {
		if _, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), sign))); err != nil {
			t.Fatalf("sign mode %d: %v", sign, err)
		}
	}
	req := samlReq(e.response(t, e.claims(), samltest.SignAssertion))
	req.Policy = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`
	got, err := e.svc.AssumeRoleWithSAML(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	h := sha1.Sum([]byte(samlIssuer + acct + "/corp")) //nolint:gosec // see import
	c := got.Credentials
	if !strings.HasPrefix(c.AccessKeyID, "ASIA") || c.Secret == "" || c.SessionToken == "" ||
		c.AssumedRoleARN != "arn:vws:sts::"+acct+":assumed-role/saml-dev/alice@corp.test" ||
		got.AssumedRoleID != "AROASAMLDEV:alice@corp.test" || got.Audience != samlAud || got.Issuer != samlIssuer ||
		got.Subject != "alice@corp.test" || got.SubjectType != "persistent" || got.SourceIdentity != "alice" ||
		got.NameQualifier != base64.StdEncoding.EncodeToString(h[:]) || got.PackedPolicySize != 5 ||
		!c.Expiration.Equal(e.clk.now().Add(time.Hour)) {
		t.Fatalf("got %+v expires %v", got, c.Expiration)
	}
	if s := got.String(); strings.Contains(s, c.Secret) || strings.Contains(s, c.SessionToken) {
		t.Fatalf("String leaks credentials: %s", s)
	}
	if s := req.String(); strings.Contains(s, req.Assertion[:16]) {
		t.Fatalf("String leaks the assertion: %s", s)
	}
	// The same assertion again issues new credentials, as in AWS.
	again, err := e.svc.AssumeRoleWithSAML(ctx, req)
	if err != nil || again.Credentials.AccessKeyID == c.AccessKeyID {
		t.Fatalf("second call: %v, %v", again, err)
	}
	// A restarted service (nothing stored) accepts the token; the
	// session is the role narrowed by the session policy.
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	sess, err := restarted.Validate(ctx, c.AccessKeyID, c.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Principal.Kind != authz.Role || sess.Principal.Name != "saml-dev" || sess.SessionName != "alice@corp.test" {
		t.Fatalf("session %+v", sess)
	}
	for action, want := range map[string]bool{"s3:GetObject": true, "s3:PutObject": false} {
		d, err := e.az.Authorize(ctx, sess.Principal, action, "arn:vws:s3:::b/k", nil)
		if err != nil || d.Allowed != want {
			t.Errorf("%s: %+v, %v; want allowed=%v", action, d, err, want)
		}
	}
	if err := e.svc.RevokeSessions(ctx, authz.Role, "saml-dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Validate(ctx, c.AccessKeyID, c.SessionToken); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("revoked SAML session: %v", err)
	}
}

// TestAssumeRoleWithSAMLRejectsForgedResponses: an unsigned, tampered,
// foreign-signed or wrapped response, one with a DTD, or one that is not
// a SAML response is InvalidIdentityToken.
func TestAssumeRoleWithSAMLRejectsForgedResponses(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	other, err := samltest.New(samlIssuer, e.clk.now())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := e.idp.ResponseXML(e.claims(), samltest.SignAssertion)
	if err != nil {
		t.Fatal(err)
	}
	respSigned, err := e.idp.ResponseXML(e.claims(), samltest.SignResponse)
	if err != nil {
		t.Fatal(err)
	}
	edit := func(xml, old, repl string) string {
		out, err := samltest.Replace(xml, old, repl)
		if err != nil {
			t.Fatal(err)
		}
		return samltest.Encode(out)
	}
	evil := e.claims()
	evil.SessionName = "mallory"
	evilXML, err := e.idp.ResponseXML(evil, samltest.SignNone)
	if err != nil {
		t.Fatal(err)
	}
	evilAssertion := evilXML[strings.Index(evilXML, "<saml:Assertion"):strings.Index(evilXML, "</samlp:Response>")]
	foreign, err := other.Response(e.claims(), samltest.SignAssertion)
	if err != nil {
		t.Fatal(err)
	}
	for name, assertion := range map[string]string{
		"unsigned":           e.response(t, e.claims(), samltest.SignNone),
		"signed by another":  foreign,
		"tampered assertion": edit(signed, ">alice@corp.test</saml:AttributeValue>", ">root</saml:AttributeValue>"),
		"tampered response":  edit(respSigned, ">alice@corp.test</saml:AttributeValue>", ">root</saml:AttributeValue>"),
		"wrapped assertion":  edit(signed, "<saml:Assertion", evilAssertion+"<saml:Assertion"),
		"wrapped response":   edit(respSigned, "</samlp:Response>", evilAssertion+"</samlp:Response>"),
		"DTD":                samltest.Encode(`<!DOCTYPE x [<!ENTITY a "b">]>` + signed),
		"not base64":         "%%%%not-base64%%%%",
		"not XML":            base64.StdEncoding.EncodeToString([]byte("not xml at all")),
		"not a response": base64.StdEncoding.EncodeToString(
			[]byte(`<x:Response xmlns:x="urn:other"><x:Status/></x:Response>`)),
	} {
		_, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(assertion))
		if !errors.Is(err, sts.ErrInvalidIdentityToken) {
			t.Errorf("%s: %v, want InvalidIdentityToken", name, err)
		}
	}
}

// TestAssumeRoleWithSAMLClaims: expiry, audience, recipient, issuer,
// status, attributes and the role pair are checked with AWS error codes.
func TestAssumeRoleWithSAMLClaims(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	now := e.clk.now()
	invalid, expired := sts.ErrInvalidIdentityToken, sts.ErrExpired
	evil := "https://evil.test/saml"
	cases := []struct {
		name string
		edit func(*samltest.Assertion)
		want error
	}{
		{"expired conditions", func(a *samltest.Assertion) { a.NotOnOrAfter = now }, expired},
		{"expired confirmation", func(a *samltest.Assertion) { a.ConfirmNotOnOrAfter = now.Add(-time.Second) }, expired},
		{"session over", func(a *samltest.Assertion) { a.SessionNotOnOrAfter = now }, expired},
		{"not yet valid", func(a *samltest.Assertion) { a.NotBefore = now.Add(10 * time.Minute) }, invalid},
		{"other audience", func(a *samltest.Assertion) { a.Audience = evil }, invalid},
		{"other recipient", func(a *samltest.Assertion) { a.Recipient = evil }, invalid},
		{"other destination", func(a *samltest.Assertion) { a.Destination = evil }, invalid},
		{"no confirmation expiry", func(a *samltest.Assertion) { a.ConfirmNotOnOrAfter = time.Time{} }, invalid},
		{"other issuer", func(a *samltest.Assertion) { a.Issuer = "https://idp.evil.test" }, invalid},
		{"empty NameID", func(a *samltest.Assertion) { a.NameID = "" }, invalid},
		{"no Role", func(a *samltest.Assertion) { a.Roles = nil }, invalid},
		{"no session name", func(a *samltest.Assertion) { a.SessionName = "" }, invalid},
		{"bad session name", func(a *samltest.Assertion) { a.SessionName = "a b" }, invalid},
		{"bad SessionDuration", func(a *samltest.Assertion) { a.SessionDuration = "899" }, invalid},
		{"bad SourceIdentity", func(a *samltest.Assertion) { a.SourceIdentity = "x" }, invalid},
		{"IdP failure", func(a *samltest.Assertion) {
			a.Status = "urn:oasis:names:tc:SAML:2.0:status:Responder"
		}, sts.ErrIDPRejectedClaim},
		{"role not granted", func(a *samltest.Assertion) {
			a.Roles = []string{samlIdpARN + ",arn:vws:iam::" + acct + ":role/admin"}
		}, sts.ErrAccessDenied},
	}
	for _, tc := range cases {
		a := e.claims()
		tc.edit(&a)
		_, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// The Role attribute may list the pair in either order; SessionDuration
	// and SessionNotOnOrAfter shorten the session.
	a := e.claims()
	a.Roles = []string{samlRoleARN + "," + samlIdpARN}
	a.SessionDuration = "1800"
	got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
	if err != nil || !got.Credentials.Expiration.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("SessionDuration: %v, %v", got.Credentials.Expiration, err)
	}
	a.SessionNotOnOrAfter = now.Add(20 * time.Minute)
	got, err = e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
	if err != nil || !got.Credentials.Expiration.Equal(now.Add(20*time.Minute)) {
		t.Fatalf("SessionNotOnOrAfter: %v, %v", got.Credentials.Expiration, err)
	}
}

// TestAssumeRoleWithSAMLTrust: the role's trust policy decides, with the
// provider as Federated principal and SAML:* keys from the assertion;
// an unknown provider, or none configured, fails closed.
func TestAssumeRoleWithSAMLTrust(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	assertion := e.response(t, e.claims(), samltest.SignAssertion)
	trust := func(doc string) {
		t.Helper()
		_, err := store.Mutate(ctx, e.b, "saml-dev", func(r *iam.Role) error {
			r.AssumeRolePolicy = doc
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, doc := range map[string]string{
		"other provider":  strings.ReplaceAll(samlTrust, "saml-provider/corp", "saml-provider/other"),
		"other audience":  strings.ReplaceAll(samlTrust, `"SAML:aud":"`+samlAud, `"SAML:aud":"https://x.test`),
		"AssumeRole only": strings.ReplaceAll(samlTrust, "sts:AssumeRoleWithSAML", "sts:AssumeRole"),
		"explicit deny": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"` +
			samlIdpARN + `"},"Action":"sts:AssumeRoleWithSAML"},{"Effect":"Deny","Principal":"*",
			"Action":"sts:AssumeRoleWithSAML","Condition":{"StringEquals":{"SAML:sub":"alice@corp.test"}}}]}`,
		"account principal": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"` + acct +
			`"},"Action":"sts:AssumeRoleWithSAML"}}`,
	} {
		trust(doc)
		if _, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(assertion)); !errors.Is(err, sts.ErrAccessDenied) {
			t.Errorf("%s: %v, want AccessDenied", name, err)
		}
	}
	trust(strings.ReplaceAll(samlTrust, `"SAML:aud"`, `"SAML:iss":"`+samlIssuer+`","SAML:aud"`))
	if _, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(assertion)); err != nil {
		t.Fatalf("trusted with SAML:iss: %v", err)
	}
	unknown := samlReq(assertion)
	unknown.PrincipalARN = "arn:vws:iam::" + acct + ":saml-provider/nope"
	foreignAcct := samlReq(assertion)
	foreignAcct.PrincipalARN = "arn:vws:iam::999988887777:saml-provider/corp"
	for name, req := range map[string]sts.SAMLRequest{"unknown provider": unknown, "other account": foreignAcct} {
		if _, err := e.svc.AssumeRoleWithSAML(ctx, req); !errors.Is(err, sts.ErrInvalidIdentityToken) {
			t.Errorf("%s: %v, want InvalidIdentityToken", name, err)
		}
	}
	// Without WithSAML (no SAML provider store yet, #106) every call fails closed.
	if _, err := e.fedEnv.svc.AssumeRoleWithSAML(ctx, samlReq(assertion)); !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("no providers: %v", err)
	}
	// Expired metadata, or an expired signing certificate, fails closed.
	p := e.idp.Provider(samlIdpARN)
	p.ValidUntil = e.clk.now()
	svc := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithSAML(samltest.Providers{samlIdpARN: p}, samlAud))
	if _, err := svc.AssumeRoleWithSAML(ctx, samlReq(assertion)); !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("expired metadata: %v", err)
	}
	e.clk.t = e.clk.t.Add(48 * time.Hour)
	a := e.claims()
	_, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
	if !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("expired certificate: %v", err)
	}
}

// TestAssumeRoleWithSAMLValidation: request parameters are checked as
// AWS documents them, before the assertion is read.
func TestAssumeRoleWithSAMLValidation(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	good := e.response(t, e.claims(), samltest.SignAssertion)
	tooMany := make([]string, 11)
	for i := range tooMany {
		tooMany[i] = s3ReadARN
	}
	cases := []struct {
		name string
		edit func(*sts.SAMLRequest)
		want error
	}{
		{"short role", func(r *sts.SAMLRequest) { r.RoleARN = "arn:vws:iam::1:r" }, sts.ErrInvalidRequest},
		{"short principal", func(r *sts.SAMLRequest) { r.PrincipalARN = "arn" }, sts.ErrInvalidRequest},
		{"control char", func(r *sts.SAMLRequest) { r.RoleARN = samlRoleARN + "\x00" }, sts.ErrInvalidRequest},
		{"short assertion", func(r *sts.SAMLRequest) { r.Assertion = "abc" }, sts.ErrInvalidRequest},
		{"long assertion", func(r *sts.SAMLRequest) { r.Assertion = strings.Repeat("A", 100001) }, sts.ErrInvalidRequest},
		{"duration low", func(r *sts.SAMLRequest) { r.Duration = 899 * time.Second }, sts.ErrInvalidRequest},
		{"duration high", func(r *sts.SAMLRequest) { r.Duration = 43201 * time.Second }, sts.ErrInvalidRequest},
		{"over role max", func(r *sts.SAMLRequest) { r.Duration = 5 * time.Hour }, sts.ErrInvalidRequest},
		{"bad policy", func(r *sts.SAMLRequest) { r.Policy = `{"Version":"2012-10-17"}` }, policy.ErrMalformed},
		{"policy chars", func(r *sts.SAMLRequest) { r.Policy = "\x01" }, sts.ErrInvalidRequest},
		{"too many arns", func(r *sts.SAMLRequest) { r.PolicyARNs = tooMany }, sts.ErrInvalidRequest},
		{"unknown arn", func(r *sts.SAMLRequest) {
			r.PolicyARNs = []string{"arn:vws:iam::" + acct + ":policy/Nope"}
		}, policy.ErrMalformed},
		{"packed too large", func(r *sts.SAMLRequest) {
			long := "arn:vws:iam::" + acct + ":policy/" + strings.Repeat("p", 1100)
			r.PolicyARNs = []string{long, long}
		}, sts.ErrPackedPolicyTooLarge},
		{"unknown role", func(r *sts.SAMLRequest) { r.RoleARN = "arn:vws:iam::" + acct + ":role/nope" }, sts.ErrAccessDenied},
		{"other path", func(r *sts.SAMLRequest) {
			r.RoleARN = "arn:vws:iam::" + acct + ":role/x/saml-dev"
		}, sts.ErrAccessDenied},
	}
	for _, tc := range cases {
		r := samlReq(good)
		tc.edit(&r)
		if _, err := e.svc.AssumeRoleWithSAML(ctx, r); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	r := samlReq(good)
	r.Duration = 4 * time.Hour
	r.PolicyARNs = []string{s3ReadARN}
	got, err := e.svc.AssumeRoleWithSAML(ctx, r)
	if err != nil || !got.Credentials.Expiration.Equal(e.clk.now().Add(4*time.Hour)) {
		t.Fatalf("role max duration with managed session policy: %v, %v", got, err)
	}
}

// TestAssumeRoleWithSAMLEveryAudienceRestriction: each AudienceRestriction
// must name this service (SAML 2.0 core 2.5.1.4: OR within one
// restriction, AND across restrictions), so an assertion that a second
// restriction limits to another service is InvalidIdentityToken.
func TestAssumeRoleWithSAMLEveryAudienceRestriction(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	evil := "https://evil.test/saml"
	for name, tc := range map[string]struct {
		more [][]string
		ok   bool
	}{
		"second restriction names another": {[][]string{{evil}}, false},
		"second restriction is empty":      {[][]string{{}}, false},
		"second restriction names us too":  {[][]string{{evil, samlAud}}, true},
	} {
		a := e.claims()
		a.MoreAudienceRestrictions = tc.more
		_, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
		if tc.ok && err != nil {
			t.Errorf("%s: %v, want credentials", name, err)
		}
		if !tc.ok && !errors.Is(err, sts.ErrInvalidIdentityToken) {
			t.Errorf("%s: %v, want InvalidIdentityToken", name, err)
		}
	}
}
