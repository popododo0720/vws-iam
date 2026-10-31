package sts_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // NameQualifier is SHA-1 by the AWS definition.
	"encoding/base64"
	"errors"
	"strconv"
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
	// samlAud is the sign-in URL (Recipient, Destination, SAML:aud) and
	// samlSPID the service provider entity id (Audience), as in AWS.
	samlAud     = "https://signin.vws.test/saml"
	samlSPID    = "urn:amazon:webservices"
	samlIdpARN  = "arn:vws:iam::" + acct + ":saml-provider/corp"
	samlRoleARN = "arn:vws:iam::" + acct + ":role/saml-dev"
	samlIssuer  = "https://idp.corp.test/saml"
	samlTrust   = `{"Version":"2012-10-17","Statement":{"Effect":"Allow",
		"Principal":{"Federated":"` + samlIdpARN + `"},
		"Action":["sts:AssumeRoleWithSAML","sts:SetSourceIdentity"],
		"Condition":{"StringEquals":{"SAML:aud":"` + samlAud + `"}}}}`
)

var samlSP = sts.SAMLServiceProvider{Audience: samlSPID, SignInURL: samlAud}

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
	return samlEnv{fedEnv: e, idp: idp, svc: sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithSAML(provs, samlSP))}
}

// claims is a valid assertion for saml-dev, as an IdP issues it now.
func (e samlEnv) claims() samltest.Assertion {
	now := e.clk.now()
	return samltest.Assertion{
		Issuer: samlIssuer, Audience: samlSPID, Recipient: samlAud, Destination: samlAud,
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
		{"long SourceIdentity", func(a *samltest.Assertion) { a.SourceIdentity = strings.Repeat("a", 257) }, invalid},
		{"no SubjectConfirmation", func(a *samltest.Assertion) { a.NoSubjectConfirmation = true }, invalid},
		{"two SubjectConfirmations", func(a *samltest.Assertion) { a.ExtraSubjectConfirmations = 1 }, invalid},
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

// TestAssumeRoleWithSAMLSourceIdentityLength: the SourceIdentity attribute
// takes 2 to 256 characters, as AWS documents it (IAM User Guide,
// Configure SAML assertions for the authentication response).
func TestAssumeRoleWithSAMLSourceIdentityLength(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	for _, n := range []int{2, 256} {
		a := e.claims()
		a.SourceIdentity = strings.Repeat("a", n)
		got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
		if err != nil || got.SourceIdentity != a.SourceIdentity {
			t.Errorf("length %d: %v, SourceIdentity %q", n, err, got.SourceIdentity)
		}
	}
	for _, n := range []int{1, 257} {
		a := e.claims()
		a.SourceIdentity = strings.Repeat("a", n)
		_, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
		if !errors.Is(err, sts.ErrInvalidIdentityToken) {
			t.Errorf("length %d: %v, want InvalidIdentityToken", n, err)
		}
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
	svc := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithSAML(samltest.Providers{samlIdpARN: p}, samlSP))
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
		"second restriction names us too":  {[][]string{{evil, samlSPID}}, true},
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

// TestAssumeRoleWithSAMLSetSourceIdentity: an assertion with the
// SourceIdentity attribute also needs sts:SetSourceIdentity in the role's
// trust policy (IAM User Guide, SourceIdentity SAML attribute); without
// it, or with it denied, the call is AccessDenied.
func TestAssumeRoleWithSAMLSetSourceIdentity(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	stmt := func(effect, actions, cond string) string {
		return `{"Effect":"` + effect + `","Principal":{"Federated":"` + samlIdpARN + `"},"Action":` + actions + cond + `}`
	}
	only := stmt("Allow", `"sts:AssumeRoleWithSAML"`, "")
	both := stmt("Allow", `["sts:AssumeRoleWithSAML","sts:SetSourceIdentity"]`, "")
	denyAlice := stmt("Deny", `"sts:SetSourceIdentity"`, `,"Condition":{"StringEquals":{"sts:SourceIdentity":"alice"}}`)
	withID := e.response(t, e.claims(), samltest.SignAssertion)
	noIDClaims := e.claims()
	noIDClaims.SourceIdentity = ""
	noID := e.response(t, noIDClaims, samltest.SignAssertion)
	for _, tc := range []struct {
		name, trust, assertion string
		ok                     bool
	}{
		{"SourceIdentity without SetSourceIdentity", only, withID, false},
		{"SourceIdentity with SetSourceIdentity", both, withID, true},
		{"SetSourceIdentity denied", "[" + both + "," + denyAlice + "]", withID, false},
		{"no SourceIdentity needs no SetSourceIdentity", only, noID, true},
	} {
		if _, err := store.Mutate(ctx, e.b, "saml-dev", func(r *iam.Role) error {
			r.AssumeRolePolicy = `{"Version":"2012-10-17","Statement":` + tc.trust + `}`
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(tc.assertion))
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: %v, want credentials", tc.name, err)
		case !tc.ok && !errors.Is(err, sts.ErrAccessDenied):
			t.Errorf("%s: %v, want AccessDenied", tc.name, err)
		case tc.ok && tc.assertion == withID && got.SourceIdentity != "alice":
			t.Errorf("%s: SourceIdentity %q", tc.name, got.SourceIdentity)
		}
	}
}

// TestAssumeRoleWithSAMLAttributeContext: the signed eduPerson, eduOrg,
// Active Directory and X.500 attributes AWS maps to trust-policy keys
// ("Mapping SAML attributes to AWS trust policy context keys") reach the
// trust policy as SAML:<key>, so an Allow or a Deny on one decides; a
// string-typed key with conflicting values fails closed.
func TestAssumeRoleWithSAMLAttributeContext(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	const (
		eppn        = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
		affiliation = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
		adMail      = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
		x500Mail    = "0.9.2342.19200300.100.1.3"
	)
	allow := `{"Effect":"Allow","Principal":{"Federated":"` + samlIdpARN +
		`"},"Action":["sts:AssumeRoleWithSAML","sts:SetSourceIdentity"]`
	deny := func(key, value string) string {
		return `,{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML",` +
			`"Condition":{"StringEquals":{"` + key + `":"` + value + `"}}}`
	}
	allowIf := allow + `,"Condition":{"StringEquals":{"SAML:eduPersonPrincipalName":"alice@corp.test"}}}`
	denyMail := allow + "}" + deny("saml:mail", "mallory@corp.test")
	denyStudent := allow + "}" + deny("SAML:eduPersonAffiliation", "student")
	for _, tc := range []struct {
		name, trust string
		attrs       map[string][]string
		want        error
	}{
		{"allow condition met", allowIf, map[string][]string{eppn: {"alice@corp.test"}}, nil},
		{"allow condition other value", allowIf, map[string][]string{eppn: {"bob@corp.test"}}, sts.ErrAccessDenied},
		{"allow condition key absent", allowIf, nil, sts.ErrAccessDenied},
		{"deny AD mail", denyMail, map[string][]string{adMail: {"mallory@corp.test"}}, sts.ErrAccessDenied},
		{"deny X.500 mail", denyMail, map[string][]string{x500Mail: {"mallory@corp.test"}}, sts.ErrAccessDenied},
		{"deny not matched", denyMail, map[string][]string{adMail: {"alice@corp.test"}}, nil},
		{"deny one of a list", denyStudent, map[string][]string{affiliation: {"staff", "student"}}, sts.ErrAccessDenied},
		{"list without the denied value", denyStudent, map[string][]string{affiliation: {"staff"}}, nil},
		{"string key with two values", denyMail, map[string][]string{
			adMail: {"alice@corp.test", "mallory@corp.test"},
		}, sts.ErrInvalidIdentityToken},
		{"two claims of one string key disagree", denyMail, map[string][]string{
			adMail: {"alice@corp.test"}, x500Mail: {"mallory@corp.test"},
		}, sts.ErrInvalidIdentityToken},
	} {
		if _, err := store.Mutate(ctx, e.b, "saml-dev", func(r *iam.Role) error {
			r.AssumeRolePolicy = `{"Version":"2012-10-17","Statement":[` + tc.trust + `]}`
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		a := e.claims()
		a.Attributes = tc.attrs
		_, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
		if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestAssumeRoleWithSAMLAudienceAndSignInURL: as in AWS, the assertion's
// Audience is the service provider entity id (urn:amazon:webservices)
// while its bearer Recipient and the response Destination are the
// sign-in URL, which is also SAML:aud. Each is checked against its own
// configured value, and a service missing either fails closed.
func TestAssumeRoleWithSAMLAudienceAndSignInURL(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	const entityID = samlSPID
	provs := samltest.Providers{samlIdpARN: e.idp.Provider(samlIdpARN)}
	svc := e.svc
	awsStyle := e.claims()
	if awsStyle.Audience != entityID || awsStyle.Recipient != samlAud || awsStyle.Destination != samlAud {
		t.Fatalf("fixture %+v is not AWS-style", awsStyle)
	}
	got, err := svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, awsStyle, samltest.SignAssertion)))
	if err != nil || got.Audience != samlAud {
		t.Fatalf("AWS-style assertion: %+v, %v; want credentials with Audience %s", got, err, samlAud)
	}
	for name, edit := range map[string]func(*samltest.Assertion){
		"audience is the sign-in URL":    func(a *samltest.Assertion) { a.Audience = samlAud },
		"recipient is the entity id":     func(a *samltest.Assertion) { a.Recipient = entityID },
		"destination is the entity id":   func(a *samltest.Assertion) { a.Destination = entityID },
		"audience names another service": func(a *samltest.Assertion) { a.Audience = "urn:other" },
	} {
		a := awsStyle
		edit(&a)
		_, err := svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
		if !errors.Is(err, sts.ErrInvalidIdentityToken) {
			t.Errorf("%s: %v, want InvalidIdentityToken", name, err)
		}
	}
	good := samlReq(e.response(t, awsStyle, samltest.SignAssertion))
	for name, sp := range map[string]sts.SAMLServiceProvider{
		"no audience":    {SignInURL: samlAud},
		"no sign-in URL": {Audience: entityID},
	} {
		svc := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithSAML(provs, sp))
		if _, err := svc.AssumeRoleWithSAML(ctx, good); !errors.Is(err, sts.ErrInvalidIdentityToken) {
			t.Errorf("%s: %v, want InvalidIdentityToken", name, err)
		}
	}
}

// TestAssumeRoleWithSAMLTrustTime: aws:CurrentTime and aws:EpochTime are
// always in the request context, as in AWS, so an Allow plus a Deny
// conditioned on the time denies after the cutoff and allows before it.
func TestAssumeRoleWithSAMLTrustTime(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	now := e.clk.now().UTC()
	allow := `{"Effect":"Allow","Principal":{"Federated":"` + samlIdpARN +
		`"},"Action":["sts:AssumeRoleWithSAML","sts:SetSourceIdentity"]}`
	deny := func(op, key, value string) string {
		return `,{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML",` +
			`"Condition":{"` + op + `":{"` + key + `":"` + value + `"}}}`
	}
	before := now.Add(-time.Hour).Format(time.RFC3339)
	after := now.Add(time.Hour).Format(time.RFC3339)
	epochBefore := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	epochAfter := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	for _, tc := range []struct {
		name, trust string
		want        error
	}{
		{"CurrentTime past cutoff", allow + deny("DateGreaterThan", "aws:CurrentTime", before), sts.ErrAccessDenied},
		{"CurrentTime before cutoff", allow + deny("DateGreaterThan", "aws:CurrentTime", after), nil},
		{"CurrentTime lower-case key", allow + deny("DateGreaterThan", "aws:currenttime", before), sts.ErrAccessDenied},
		{"EpochTime past cutoff", allow + deny("NumericGreaterThan", "aws:EpochTime", epochBefore), sts.ErrAccessDenied},
		{"EpochTime before cutoff", allow + deny("NumericGreaterThan", "aws:EpochTime", epochAfter), nil},
		{"EpochTime as a date", allow + deny("DateGreaterThan", "aws:EpochTime", before), sts.ErrAccessDenied},
	} {
		if _, err := store.Mutate(ctx, e.b, "saml-dev", func(r *iam.Role) error {
			r.AssumeRolePolicy = `{"Version":"2012-10-17","Statement":[` + tc.trust + `]}`
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		_, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
		if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestAssumeRoleWithSAMLTrustPrincipalAccount: aws:PrincipalAccount is
// in every request context, as in AWS, and is "anonymous" for this
// unsigned request, so a trust-policy Deny conditioned on the key
// matches instead of failing open.
func TestAssumeRoleWithSAMLTrustPrincipalAccount(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	allow := `{"Effect":"Allow","Principal":{"Federated":"` + samlIdpARN +
		`"},"Action":["sts:AssumeRoleWithSAML","sts:SetSourceIdentity"]}`
	deny := func(op, key, value string) string {
		return `,{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRoleWithSAML",` +
			`"Condition":{"` + op + `":{"` + key + `":"` + value + `"}}}`
	}
	for _, tc := range []struct {
		name, trust string
		want        error
	}{
		{"Null false denies", allow + deny("Null", "aws:PrincipalAccount", "false"), sts.ErrAccessDenied},
		{"Null true allows", allow + deny("Null", "aws:PrincipalAccount", "true"), nil},
		{"anonymous denied", allow + deny("StringEquals", "aws:PrincipalAccount", "anonymous"), sts.ErrAccessDenied},
		{"lower-case key", allow + deny("StringEquals", "aws:principalaccount", "anonymous"), sts.ErrAccessDenied},
		{"not the account id", allow + deny("StringNotEquals", "aws:PrincipalAccount", acct), sts.ErrAccessDenied},
		{"account id deny not matched", allow + deny("StringEquals", "aws:PrincipalAccount", acct), nil},
	} {
		if _, err := store.Mutate(ctx, e.b, "saml-dev", func(r *iam.Role) error {
			r.AssumeRolePolicy = `{"Version":"2012-10-17","Statement":[` + tc.trust + `]}`
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		_, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
		if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestAssumeRoleWithSAMLChainedIdentity: as in AWS, saml:sub,
// saml:sub_type and saml:namequalifier stay in the request context of a
// SAML role session, so the trust policy of a role it assumes next can
// deny on them; no other SAML key carries over, a client cannot set
// them, and a chained session keeps them.
func TestAssumeRoleWithSAMLChainedIdentity(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	if _, err := store.Mutate(ctx, e.b, "saml-dev", func(r *iam.Role) error {
		r.InlinePolicies["sts"] = `{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Mutate(ctx, e.b, "broker", func(u *iam.User) error {
		u.InlinePolicies["sts"] = `{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
	if err != nil {
		t.Fatal(err)
	}
	// A restarted service reads the identity from the sealed token.
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	sess, err := restarted.Validate(ctx, got.Credentials.AccessKeyID, got.Credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if sess.SAML == nil || sess.SAML.Subject != "alice@corp.test" || sess.SAML.SubjectType != "persistent" ||
		sess.SAML.NameQualifier != got.NameQualifier {
		t.Fatalf("session SAML identity %+v", sess.SAML)
	}
	samlCaller := sess.Caller()
	const adminARN = "arn:vws:iam::" + acct + ":role/admin"
	allow := `{"Effect":"Allow","Principal":{"AWS":"` + acct + `"},"Action":"sts:AssumeRole"`
	cond := func(op, key, value string) string {
		return `,"Condition":{"` + op + `":{"` + key + `":"` + value + `"}}`
	}
	deny := func(key, value string) string {
		return `,{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"` + cond("StringEquals", key, value) + `}`
	}
	trust := func(doc string) {
		t.Helper()
		if _, err := store.Mutate(ctx, e.b, "admin", func(r *iam.Role) error {
			r.AssumeRolePolicy = `{"Version":"2012-10-17","Statement":[` + doc + `]}`
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	broker := e.caller(t, "broker")
	for _, tc := range []struct {
		name, trust string
		caller      sts.Caller
		reqCtx      map[string][]string
		want        error
	}{
		{"deny saml:sub", allow + "}" + deny("saml:sub", "alice@corp.test"), samlCaller, nil, sts.ErrAccessDenied},
		{"deny SAML:sub any case", allow + "}" + deny("SAML:Sub", "alice@corp.test"), samlCaller, nil, sts.ErrAccessDenied},
		{"deny other subject", allow + "}" + deny("saml:sub", "bob@corp.test"), samlCaller, nil, nil},
		{"deny saml:sub_type", allow + "}" + deny("saml:sub_type", "persistent"), samlCaller, nil, sts.ErrAccessDenied},
		{
			"deny saml:namequalifier", allow + "}" + deny("saml:namequalifier", got.NameQualifier), samlCaller, nil,
			sts.ErrAccessDenied,
		},
		{
			"client cannot replace saml:sub", allow + "}" + deny("saml:sub", "alice@corp.test"), samlCaller,
			map[string][]string{"saml:sub": {"bob@corp.test"}, "SAML:SUB": {"bob@corp.test"}},
			sts.ErrAccessDenied,
		},
		{"allow on saml:sub", allow + cond("StringEquals", "saml:sub", "alice@corp.test") + "}", samlCaller, nil, nil},
		{
			"saml:iss does not carry over", allow + cond("StringEquals", "saml:iss", samlIssuer) + "}", samlCaller, nil,
			sts.ErrAccessDenied,
		},
		{
			"saml:aud does not carry over", allow + cond("StringEquals", "saml:aud", samlAud) + "}", samlCaller, nil,
			sts.ErrAccessDenied,
		},
		{
			"client cannot claim saml:sub", allow + cond("StringEquals", "saml:sub", "alice@corp.test") + "}", broker,
			map[string][]string{"saml:sub": {"alice@corp.test"}},
			sts.ErrAccessDenied,
		},
	} {
		trust(tc.trust)
		_, err := e.svc.AssumeRole(ctx, tc.caller, tc.reqCtx, adminARN, "chain", 0, "", sts.MFA{})
		if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// The chained session keeps the SAML identity for the next hop.
	trust(allow + "}")
	chained, err := e.svc.AssumeRole(ctx, samlCaller, nil, adminARN, "chain", 0, "", sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.svc.Validate(ctx, chained.AccessKeyID, chained.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if next.SAML == nil || *next.SAML != *sess.SAML {
		t.Fatalf("chained session SAML identity %+v, want %+v", next.SAML, sess.SAML)
	}
	if _, err := store.Mutate(ctx, e.b, "admin", func(r *iam.Role) error {
		r.InlinePolicies["sts"] = `{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	trust(allow + "}" + deny("saml:sub", "alice@corp.test"))
	_, err = e.svc.AssumeRole(ctx, next.Caller(), nil, adminARN, "again", 0, "", sts.MFA{})
	if !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("second hop with Deny on saml:sub: %v, want AccessDenied", err)
	}
	// A caller without SAML identity does not match the Deny, and its
	// session has none.
	plain, err := e.svc.AssumeRole(ctx, broker, nil, adminARN, "plain", 0, "", sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	if ps, err := e.svc.Validate(ctx, plain.AccessKeyID, plain.SessionToken); err != nil || ps.SAML != nil {
		t.Fatalf("plain session SAML identity %+v, %v", ps.SAML, err)
	}
}

// TestAssumeRoleWithSAMLSessionNotOnOrAfterAbsolute: SessionNotOnOrAfter
// caps the expiry as an absolute time, so time spent between reading the
// assertion and sealing the session does not push the expiry past it.
func TestAssumeRoleWithSAMLSessionNotOnOrAfterAbsolute(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	start := e.clk.now()
	// Every clock read moves 10 seconds on, as a slow request would.
	tick := start
	slow := func() time.Time {
		now := tick
		tick = tick.Add(10 * time.Second)
		return now
	}
	provs := samltest.Providers{samlIdpARN: e.idp.Provider(samlIdpARN)}
	svc := sts.New(e.b, e.keys, e.az, acct, slow, sts.WithSAML(provs, samlSP))
	a := e.claims()
	a.SessionNotOnOrAfter = start.Add(20 * time.Minute)
	got, err := svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, a, samltest.SignAssertion)))
	if err != nil {
		t.Fatal(err)
	}
	if exp := got.Credentials.Expiration; exp.After(a.SessionNotOnOrAfter) {
		t.Fatalf("expires %v, after SessionNotOnOrAfter %v", exp, a.SessionNotOnOrAfter)
	}
	if !got.Credentials.Expiration.Equal(a.SessionNotOnOrAfter) {
		t.Fatalf("expires %v, want SessionNotOnOrAfter %v", got.Credentials.Expiration, a.SessionNotOnOrAfter)
	}
}
