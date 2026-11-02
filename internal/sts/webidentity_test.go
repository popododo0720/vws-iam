package sts_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/oidctest"
)

const (
	wiIssuer   = "https://oidc.ci.test/org/1"
	wiName     = "oidc.ci.test/org/1"
	wiProvARN  = "arn:vws:iam::" + acct + ":oidc-provider/" + wiName
	wiRoleARN  = "arn:vws:iam::" + acct + ":role/ci-deploy"
	wiClientID = "sts.vws.test"
	wiTrust    = `{"Version":"2012-10-17","Statement":{"Effect":"Allow",
		"Principal":{"Federated":"` + wiProvARN + `"},
		"Action":["sts:AssumeRoleWithWebIdentity","sts:SetSourceIdentity"],
		"Condition":{"StringEquals":{"` + wiName + `:aud":"` + wiClientID + `"}}}}`
)

type wiEnv struct {
	fedEnv
	idp *oidctest.IdP
	svc *sts.Service
}

func wiSetup(t *testing.T) wiEnv {
	t.Helper()
	e := fedSetup(t)
	idp, err := oidctest.New(wiIssuer)
	if err != nil {
		t.Fatal(err)
	}
	put(t, e.b, iam.Role{
		Name: "ci-deploy", ID: "AROACIDEPLOY", MaxSessionDuration: 4 * time.Hour, AssumeRolePolicy: wiTrust,
		InlinePolicies: map[string]string{"s3": `{"Version":"2012-10-17","Statement":
			{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`},
	})
	provs := oidctest.Providers{ByARN: map[string]sts.OIDCProvider{
		wiProvARN: idp.Provider(wiProvARN, "other-client", wiClientID),
	}}
	return wiEnv{fedEnv: e, idp: idp, svc: sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithOIDC(provs))}
}

// claims are valid ID token claims for ci-deploy, issued now.
func (e wiEnv) claims() map[string]any {
	now := e.clk.now().Unix()
	return map[string]any{
		"iss": wiIssuer, "sub": "repo:org/app:ref:refs/heads/main", "aud": wiClientID,
		"iat": now - 10, "nbf": now - 10, "exp": now + 300, "amr": []string{"authenticated", "ci"},
	}
}

func (e wiEnv) token(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	tok, err := e.idp.Token(alg, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func wiReq(token string) sts.WebIdentityRequest {
	return sts.WebIdentityRequest{RoleARN: wiRoleARN, RoleSessionName: "deploy-1", Token: token}
}

// with returns c with the given claims set; a nil value removes one.
func with(c map[string]any, kv ...any) map[string]any {
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			panic("claim name must be a string")
		}
		if kv[i+1] == nil {
			delete(c, k)
		} else {
			c[k] = kv[i+1]
		}
	}
	return c
}

// TestAssumeRoleWithWebIdentity: an ID token signed by a key of the
// provider (every algorithm AWS accepts) gets role credentials with the
// AWS response fields; the session is the role narrowed by the session
// policy, keeps the session keys of the token, survives a restart, ends
// on role revocation, and every call issues new credentials.
func TestAssumeRoleWithWebIdentity(t *testing.T) {
	e := wiSetup(t)
	ctx := context.Background()
	for _, alg := range []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"} {
		if _, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(e.token(t, alg, e.claims()))); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
	}
	req := wiReq(e.token(t, "RS256", e.claims()))
	req.Policy = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`
	got, err := e.svc.AssumeRoleWithWebIdentity(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	c := got.Credentials
	if !strings.HasPrefix(c.AccessKeyID, "ASIA") || c.Secret == "" || c.SessionToken == "" ||
		c.AssumedRoleARN != "arn:vws:sts::"+acct+":assumed-role/ci-deploy/deploy-1" ||
		got.AssumedRoleID != "AROACIDEPLOY:deploy-1" || got.Audience != wiClientID || got.Provider != wiIssuer ||
		got.SubjectFromWebIdentityToken != "repo:org/app:ref:refs/heads/main" || got.SourceIdentity != "" ||
		got.PackedPolicySize != 5 || !c.Expiration.Equal(e.clk.now().Add(time.Hour)) {
		t.Fatalf("got %+v expires %v", got, c.Expiration)
	}
	if s := got.String(); strings.Contains(s, c.Secret) || strings.Contains(s, c.SessionToken) {
		t.Fatalf("String leaks credentials: %s", s)
	}
	if s := req.String(); strings.Contains(s, req.Token[:16]) {
		t.Fatalf("String leaks the token: %s", s)
	}
	again, err := e.svc.AssumeRoleWithWebIdentity(ctx, req)
	if err != nil || again.Credentials.AccessKeyID == c.AccessKeyID {
		t.Fatalf("second call: %v, %v", again, err)
	}
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	sess, err := restarted.Validate(ctx, c.AccessKeyID, c.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	wi := sess.WebIdentity
	if sess.Principal.Kind != authz.Role || sess.Principal.Name != "ci-deploy" || sess.SessionName != "deploy-1" ||
		wi == nil || wi.Provider != wiName || wi.ProviderARN != wiProvARN ||
		wi.Subject != "repo:org/app:ref:refs/heads/main" || fmt.Sprint(wi.Audience) != "["+wiClientID+"]" ||
		fmt.Sprint(wi.AMR) != "[authenticated ci]" {
		t.Fatalf("session %+v web identity %+v", sess, wi)
	}
	ctxKeys := sess.Context()
	if fmt.Sprint(ctxKeys[wiName+":sub"]) != "[repo:org/app:ref:refs/heads/main]" ||
		fmt.Sprint(ctxKeys["aws:FederatedProvider"]) != "["+wiProvARN+"]" || ctxKeys[wiName+":oaud"] != nil {
		t.Fatalf("session context %v", ctxKeys)
	}
	for action, want := range map[string]bool{"s3:GetObject": true, "s3:PutObject": false} {
		d, err := e.az.Authorize(ctx, sess.Principal, action, "arn:vws:s3:::b/k", nil)
		if err != nil || d.Allowed != want {
			t.Errorf("%s: %+v, %v; want allowed=%v", action, d, err, want)
		}
	}
	if err := e.svc.RevokeSessions(ctx, authz.Role, "ci-deploy"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Validate(ctx, c.AccessKeyID, c.SessionToken); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("after revocation: %v", err)
	}
}

// TestAssumeRoleWithWebIdentityRejectsForgedTokens: only a compact JWS
// signed (RS256-RS512, ES256-ES512) by a key the provider lists, with the
// key its kid names, is accepted; claims cannot be changed after signing.
func TestAssumeRoleWithWebIdentityRejectsForgedTokens(t *testing.T) {
	e := wiSetup(t)
	ctx := context.Background()
	good := e.token(t, "RS256", e.claims())
	parts := strings.Split(good, ".")
	b64 := base64.RawURLEncoding.EncodeToString
	evilClaims := b64([]byte(`{"iss":"` + wiIssuer + `","sub":"admin","aud":"` + wiClientID +
		`","iat":1793404790,"exp":1793405100}`))
	other, err := oidctest.New(wiIssuer)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.Token("RS256", e.claims())
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreignEC, err := oidctest.Sign("ES256", ecKey, map[string]any{"alg": "ES256", "kid": "ES256"}, e.claims())
	if err != nil {
		t.Fatal(err)
	}
	hdr := func(h map[string]any) string {
		t.Helper()
		tok, err := e.idp.TokenWithHeader(h, e.claims())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	raw := func(header, claims string) string {
		t.Helper()
		tok, err := e.idp.SignRaw("RS256", []byte(header), []byte(claims))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	now := e.clk.now().Unix()
	cases := map[string]string{
		"alg none":        b64([]byte(`{"alg":"none"}`)) + "." + parts[1] + ".",
		"alg none sig":    b64([]byte(`{"alg":"none"}`)) + "." + parts[1] + "." + parts[2],
		"alg HS256":       b64([]byte(`{"alg":"HS256","kid":"rsa"}`)) + "." + parts[1] + "." + parts[2],
		"alg PS256":       hdrAlgSwap(parts, "PS256"),
		"empty signature": parts[0] + "." + parts[1] + ".",
		"tampered claims": parts[0] + "." + evilClaims + "." + parts[2],
		"other key":       foreign,
		"other EC key":    foreignEC,
		"unknown kid":     hdr(map[string]any{"alg": "RS256", "kid": "nope"}),
		"kid of EC key":   hdr(map[string]any{"alg": "RS256", "kid": "ES256"}),
		"ES256 as RS256":  hdrAlgSwap(strings.Split(e.token(t, "ES256", e.claims()), "."), "RS256"),
		"crit header":     hdr(map[string]any{"alg": "RS256", "kid": "rsa", "crit": []string{"exp"}}),
		"JWE":             "eyJhbGciOiJSU0EtT0FFUCJ9.a.b.c.d",
		"two parts":       parts[0] + "." + parts[1],
		"padded":          parts[0] + "=." + parts[1] + "." + parts[2],
		"not base64":      parts[0] + ".%%%%." + parts[2],
		"duplicate claim": raw(`{"alg":"RS256","kid":"rsa"}`, fmt.Sprintf(
			`{"iss":%q,"sub":"a","sub":"admin","aud":%q,"iat":%d,"exp":%d}`, wiIssuer, wiClientID, now, now+60)),
		"duplicate alg": raw(`{"alg":"RS256","alg":"none","kid":"rsa"}`, fmt.Sprintf(
			`{"iss":%q,"sub":"a","aud":%q,"iat":%d,"exp":%d}`, wiIssuer, wiClientID, now, now+60)),
		"trailing data": raw(`{"alg":"RS256","kid":"rsa"}`, fmt.Sprintf(
			`{"iss":%q,"sub":"a","aud":%q,"iat":%d,"exp":%d}{}`, wiIssuer, wiClientID, now, now+60)),
		"claims array": raw(`{"alg":"RS256","kid":"rsa"}`, `[1]`),
	}
	for name, tok := range cases {
		if _, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(tok)); !errors.Is(err, sts.ErrInvalidIdentityToken) {
			t.Errorf("%s: %v, want InvalidIdentityToken", name, err)
		}
	}
	// A token without kid is checked against every key of its type.
	if _, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(hdr(map[string]any{"alg": "ES384"}))); err != nil {
		t.Fatalf("no kid: %v", err)
	}
	// An RSA key under 2048 bits never verifies, even when listed.
	weak, err := oidctest.NewWithRSABits(wiIssuer, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakTok, err := weak.Token("RS256", e.claims())
	if err != nil {
		t.Fatal(err)
	}
	svc := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithOIDC(oidctest.Providers{ByARN: map[string]sts.OIDCProvider{
		wiProvARN: weak.Provider(wiProvARN, wiClientID),
	}}))
	if _, err := svc.AssumeRoleWithWebIdentity(ctx, wiReq(weakTok)); !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("1024-bit key: %v, want InvalidIdentityToken", err)
	}
}

// hdrAlgSwap re-encodes the header of parts with another alg, keeping
// the signature.
func hdrAlgSwap(parts []string, alg string) string {
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		panic(err)
	}
	h := strings.Replace(string(b), `"alg":"`+algOf(string(b))+`"`, `"alg":"`+alg+`"`, 1)
	return base64.RawURLEncoding.EncodeToString([]byte(h)) + "." + parts[1] + "." + parts[2]
}

func algOf(header string) string {
	_, rest, _ := strings.Cut(header, `"alg":"`)
	alg, _, _ := strings.Cut(rest, `"`)
	return alg
}

// TestAssumeRoleWithWebIdentityClaims: the issuer selects the provider,
// aud must name one of its client ids, exp, iat and nbf are integers
// checked at the service clock (expired is ExpiredToken), and claims AWS
// constrains are checked; every other fault is InvalidIdentityToken.
func TestAssumeRoleWithWebIdentityClaims(t *testing.T) {
	e := wiSetup(t)
	ctx := context.Background()
	now := e.clk.now().Unix()
	skew := int64(sts.WebIdentityClockSkew / time.Second)
	cases := []struct {
		name string
		kv   []any
		want error
	}{
		{"expired", []any{"exp", now}, sts.ErrExpired},
		{"no exp", []any{"exp", nil}, sts.ErrInvalidIdentityToken},
		{"float exp", []any{"exp", float64(now) + 0.5}, sts.ErrInvalidIdentityToken},
		{"string exp", []any{"exp", fmt.Sprint(now + 60)}, sts.ErrInvalidIdentityToken},
		{"no iat", []any{"iat", nil}, sts.ErrInvalidIdentityToken},
		{"future iat", []any{"iat", now + skew + 1}, sts.ErrInvalidIdentityToken},
		{"future nbf", []any{"nbf", now + skew + 1}, sts.ErrInvalidIdentityToken},
		{"iat and nbf within skew", []any{"iat", now + skew, "nbf", now + skew}, nil},
		{"no nbf", []any{"nbf", nil}, nil},
		{"no sub", []any{"sub", nil}, sts.ErrInvalidIdentityToken},
		{"empty sub", []any{"sub", ""}, sts.ErrInvalidIdentityToken},
		{"numeric sub", []any{"sub", 7}, sts.ErrInvalidIdentityToken},
		{"no aud", []any{"aud", nil}, sts.ErrInvalidIdentityToken},
		{"other aud", []any{"aud", "someone-else"}, sts.ErrInvalidIdentityToken},
		{"aud list with client", []any{"aud", []string{"x", wiClientID}}, nil},
		{"aud list without client", []any{"aud", []string{"x", "y"}}, sts.ErrInvalidIdentityToken},
		{"azp alone is not aud", []any{"aud", "x", "azp", wiClientID}, sts.ErrInvalidIdentityToken},
		{"http issuer", []any{"iss", "http://oidc.ci.test/org/1"}, sts.ErrInvalidIdentityToken},
		{"issuer with port", []any{"iss", "https://oidc.ci.test:8443/org/1"}, sts.ErrInvalidIdentityToken},
		{"issuer with query", []any{"iss", wiIssuer + "?x=1"}, sts.ErrInvalidIdentityToken},
		{"unknown issuer", []any{"iss", "https://other.test"}, sts.ErrInvalidIdentityToken},
		{"issuer trailing slash", []any{"iss", wiIssuer + "/"}, sts.ErrInvalidIdentityToken},
		{"no issuer", []any{"iss", nil}, sts.ErrInvalidIdentityToken},
		{
			"session tags",
			[]any{"https://aws.amazon.com/tags", map[string]any{"principal_tags": map[string]any{}}},
			sts.ErrInvalidIdentityToken,
		},
		{"short source identity", []any{"https://aws.amazon.com/source_identity", "a"}, sts.ErrInvalidIdentityToken},
		{
			"long source identity",
			[]any{"https://aws.amazon.com/source_identity", strings.Repeat("a", 257)},
			sts.ErrInvalidIdentityToken,
		},
		{"longest source identity", []any{"https://aws.amazon.com/source_identity", strings.Repeat("a", 256)}, nil},
		{"source identity charset", []any{"https://aws.amazon.com/source_identity", "a_b+c=d,e.f@g-h"}, nil},
		{"source identity colon", []any{"https://aws.amazon.com/source_identity", "aws:x"}, sts.ErrInvalidIdentityToken},
		{"bad amr", []any{"amr", 3}, sts.ErrInvalidIdentityToken},
	}
	for _, tc := range cases {
		tok := e.token(t, "ES256", with(e.claims(), tc.kv...))
		_, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(tok))
		if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// azp, when present, is the audience AWS reports and the aud key.
	tok := e.token(t, "RS256", with(e.claims(), "azp", "android-app",
		"https://aws.amazon.com/source_identity", "alice@corp"))
	got, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(tok))
	if !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("azp with trust on aud=%s: %v, want AccessDenied", wiClientID, err)
	}
	trustDoc(t, e.b, strings.ReplaceAll(wiTrust, `"`+wiClientID+`"`, `"android-app"`))
	if got, err = e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(tok)); err != nil {
		t.Fatal(err)
	}
	if got.Audience != "android-app" || got.SourceIdentity != "alice@corp" {
		t.Fatalf("azp session %+v", got)
	}
}

// trustDoc replaces the trust policy of ci-deploy.
func trustDoc(t *testing.T, b store.Backend, doc string) {
	t.Helper()
	if _, err := store.Mutate(context.Background(), b, "ci-deploy", func(r *iam.Role) error {
		r.AssumeRolePolicy = doc
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAssumeRoleWithWebIdentityTrust: the trust policy must allow
// sts:AssumeRoleWithWebIdentity (and sts:SetSourceIdentity with a source
// identity claim) for the Federated provider, evaluated with the token's
// keys and the server's time keys, aws:PrincipalAccount anonymous; the
// call fails closed without providers and passes IDPCommunicationError on.
func TestAssumeRoleWithWebIdentityTrust(t *testing.T) {
	e := wiSetup(t)
	ctx := context.Background()
	tok := e.token(t, "RS256", e.claims())
	allow := func(cond string) string {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"` + wiProvARN +
			`"},"Action":"sts:AssumeRoleWithWebIdentity"` + cond + `}]}`
	}
	cond := func(op, key, value string) string {
		return `,"Condition":{"` + op + `":{"` + key + `":"` + value + `"}}`
	}
	deny := func(op, key, value string) string {
		return strings.TrimSuffix(allow(""), "]}") + `,{"Effect":"Deny","Principal":"*",
			"Action":"sts:AssumeRoleWithWebIdentity"` + cond(op, key, value) + `}]}`
	}
	cutoff := e.clk.now().Add(-time.Minute)
	for _, tc := range []struct {
		name, doc string
		ok        bool
	}{
		{"other provider", strings.ReplaceAll(wiTrust, "org/1", "org/2"), false},
		{"AssumeRole only", strings.ReplaceAll(wiTrust, "sts:AssumeRoleWithWebIdentity", "sts:AssumeRole"), false},
		{"account principal", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"` + acct +
			`"},"Action":"sts:AssumeRoleWithWebIdentity"}}`, false},
		{"sub matches", allow(cond("StringLike", wiName+":sub", "repo:org/app:*")), true},
		{"sub differs", allow(cond("StringLike", wiName+":sub", "repo:org/other:*")), false},
		{"oaud", allow(cond("StringEquals", wiName+":oaud", wiClientID)), true},
		{"amr", allow(cond("StringEquals", wiName+":amr", "ci")), true},
		{"federated provider", allow(cond("StringEquals", "aws:FederatedProvider", wiProvARN)), true},
		{"session name", allow(cond("StringEquals", "sts:RoleSessionName", "deploy-2")), false},
		{"principal account", allow(cond("StringEquals", "aws:PrincipalAccount", "anonymous")), true},
		{"deny sub", deny("StringEquals", wiName+":sub", "repo:org/app:ref:refs/heads/main"), false},
		{"deny after cutoff", deny("DateGreaterThan", "aws:CurrentTime", cutoff.Format(time.RFC3339)), false},
		{"deny epoch", deny("NumericGreaterThan", "aws:EpochTime", fmt.Sprint(cutoff.Unix())), false},
		{"deny own account", deny("StringEquals", "aws:PrincipalAccount", acct), true},
	} {
		trustDoc(t, e.b, tc.doc)
		_, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(tok))
		if (tc.ok && err != nil) || (!tc.ok && !errors.Is(err, sts.ErrAccessDenied)) {
			t.Errorf("%s: %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
	// A source identity claim needs sts:SetSourceIdentity too.
	srcTok := e.token(t, "RS256", with(e.claims(), "https://aws.amazon.com/source_identity", "alice"))
	trustDoc(t, e.b, allow(""))
	if _, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(srcTok)); !errors.Is(err, sts.ErrAccessDenied) {
		t.Errorf("source identity without sts:SetSourceIdentity: %v, want AccessDenied", err)
	}
	trustDoc(t, e.b, strings.ReplaceAll(allow(cond("StringEquals", "sts:SourceIdentity", "alice")),
		`"sts:AssumeRoleWithWebIdentity"`, `["sts:AssumeRoleWithWebIdentity","sts:SetSourceIdentity"]`))
	if _, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(srcTok)); err != nil {
		t.Errorf("source identity allowed: %v", err)
	}
	// Without WithOIDC (no OIDC provider store yet, #208) every call
	// fails closed; so does a ProviderId (OAuth 2.0 access token).
	if _, err := e.fedEnv.svc.AssumeRoleWithWebIdentity(ctx, wiReq(tok)); !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Errorf("no providers: %v", err)
	}
	r := wiReq(tok)
	r.ProviderID = "www.amazon.com"
	if _, err := e.svc.AssumeRoleWithWebIdentity(ctx, r); !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Errorf("ProviderId: %v", err)
	}
	for name, p := range map[string]oidctest.Providers{
		"unreachable": {Err: fmt.Errorf("jwks: %w", sts.ErrIDPCommunication)},
		"other url": {ByARN: map[string]sts.OIDCProvider{wiProvARN: {
			ARN: wiProvARN, URL: "https://elsewhere.test", ClientIDs: []string{wiClientID}, Keys: e.idp.Keys(),
		}}},
		"no keys": {ByARN: map[string]sts.OIDCProvider{wiProvARN: {
			ARN: wiProvARN, URL: wiIssuer, ClientIDs: []string{wiClientID},
		}}},
	} {
		svc := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithOIDC(p))
		_, err := svc.AssumeRoleWithWebIdentity(ctx, wiReq(tok))
		want := sts.ErrInvalidIdentityToken
		if name == "unreachable" {
			want = sts.ErrIDPCommunication
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
}

// TestAssumeRoleWithWebIdentityValidation: request parameters are checked
// as AWS documents them, before the token is read.
func TestAssumeRoleWithWebIdentityValidation(t *testing.T) {
	e := wiSetup(t)
	ctx := context.Background()
	good := e.token(t, "RS256", e.claims())
	tooMany := make([]string, 11)
	for i := range tooMany {
		tooMany[i] = s3ReadARN
	}
	cases := []struct {
		name string
		edit func(*sts.WebIdentityRequest)
		want error
	}{
		{"short role", func(r *sts.WebIdentityRequest) { r.RoleARN = "arn:vws:iam::1:r" }, sts.ErrInvalidRequest},
		{"short session", func(r *sts.WebIdentityRequest) { r.RoleSessionName = "a" }, sts.ErrInvalidRequest},
		{
			"long session", func(r *sts.WebIdentityRequest) { r.RoleSessionName = strings.Repeat("a", 65) },
			sts.ErrInvalidRequest,
		},
		{"session chars", func(r *sts.WebIdentityRequest) { r.RoleSessionName = "a b" }, sts.ErrInvalidRequest},
		{"short token", func(r *sts.WebIdentityRequest) { r.Token = "abc" }, sts.ErrInvalidRequest},
		{"long token", func(r *sts.WebIdentityRequest) { r.Token = strings.Repeat("A", 20001) }, sts.ErrInvalidRequest},
		{"short provider id", func(r *sts.WebIdentityRequest) { r.ProviderID = "a.b" }, sts.ErrInvalidRequest},
		{"duration low", func(r *sts.WebIdentityRequest) { r.Duration = 899 * time.Second }, sts.ErrInvalidRequest},
		{"duration high", func(r *sts.WebIdentityRequest) { r.Duration = 43201 * time.Second }, sts.ErrInvalidRequest},
		{"over role max", func(r *sts.WebIdentityRequest) { r.Duration = 5 * time.Hour }, sts.ErrInvalidRequest},
		{"bad policy", func(r *sts.WebIdentityRequest) { r.Policy = `{"Version":"2012-10-17"}` }, policy.ErrMalformed},
		{"too many arns", func(r *sts.WebIdentityRequest) { r.PolicyARNs = tooMany }, sts.ErrInvalidRequest},
		{"unknown arn", func(r *sts.WebIdentityRequest) {
			r.PolicyARNs = []string{"arn:vws:iam::" + acct + ":policy/Nope"}
		}, policy.ErrMalformed},
		{"packed too large", func(r *sts.WebIdentityRequest) {
			long := "arn:vws:iam::" + acct + ":policy/" + strings.Repeat("p", 1100)
			r.PolicyARNs = []string{long, long}
		}, sts.ErrPackedPolicyTooLarge},
		{"unknown role", func(r *sts.WebIdentityRequest) {
			r.RoleARN = "arn:vws:iam::" + acct + ":role/nope"
		}, sts.ErrAccessDenied},
		{"other path", func(r *sts.WebIdentityRequest) {
			r.RoleARN = "arn:vws:iam::" + acct + ":role/x/ci-deploy"
		}, sts.ErrAccessDenied},
	}
	for _, tc := range cases {
		r := wiReq(good)
		tc.edit(&r)
		if _, err := e.svc.AssumeRoleWithWebIdentity(ctx, r); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	r := wiReq(good)
	r.Duration = 4 * time.Hour
	r.PolicyARNs = []string{s3ReadARN}
	got, err := e.svc.AssumeRoleWithWebIdentity(ctx, r)
	if err != nil || !got.Credentials.Expiration.Equal(e.clk.now().Add(4*time.Hour)) {
		t.Fatalf("role max duration with managed session policy: %v, %v", got, err)
	}
}

// TestAssumeRoleWithWebIdentityChainedIdentity: the session keeps the
// OIDC keys AWS makes available in session (<provider>:sub, :aud, :amr,
// aws:FederatedProvider) and no other; they apply in a chained
// AssumeRole trust policy, carry into the chained session, and a client
// can neither replace nor claim them.
func TestAssumeRoleWithWebIdentityChainedIdentity(t *testing.T) {
	e := wiSetup(t)
	ctx := context.Background()
	stsAll := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`
	for _, name := range []string{"ci-deploy", "admin"} {
		if _, err := store.Mutate(ctx, e.b, name, func(r *iam.Role) error {
			r.InlinePolicies["sts"] = stsAll
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Mutate(ctx, e.b, "broker", func(u *iam.User) error {
		u.InlinePolicies["sts"] = stsAll
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.AssumeRoleWithWebIdentity(ctx, wiReq(e.token(t, "RS256", with(e.claims(),
		"email", "alice@corp.test"))))
	if err != nil {
		t.Fatal(err)
	}
	wiCaller := e.session(t, got.Credentials).Caller()
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
	sub := "repo:org/app:ref:refs/heads/main"
	broker := e.caller(t, "broker")
	for _, tc := range []struct {
		name, trust string
		caller      sts.Caller
		reqCtx      map[string][]string
		want        error
	}{
		{"deny sub", allow + "}" + deny(wiName+":sub", sub), wiCaller, nil, sts.ErrAccessDenied},
		{"deny aud", allow + "}" + deny(wiName+":aud", wiClientID), wiCaller, nil, sts.ErrAccessDenied},
		{"deny provider", allow + "}" + deny("aws:FederatedProvider", wiProvARN), wiCaller, nil, sts.ErrAccessDenied},
		{"deny other sub", allow + "}" + deny(wiName+":sub", "repo:x"), wiCaller, nil, nil},
		{
			"client cannot replace sub", allow + "}" + deny(wiName+":sub", sub), wiCaller,
			map[string][]string{wiName + ":sub": {"repo:x"}, strings.ToUpper(wiName) + ":SUB": {"repo:x"}},
			sts.ErrAccessDenied,
		},
		{"allow on sub", allow + cond("StringEquals", wiName+":sub", sub) + "}", wiCaller, nil, nil},
		{
			"email does not carry over", allow + cond("StringEquals", wiName+":email", "alice@corp.test") + "}",
			wiCaller, nil, sts.ErrAccessDenied,
		},
		{
			"oaud does not carry over", allow + cond("StringEquals", wiName+":oaud", wiClientID) + "}",
			wiCaller, nil, sts.ErrAccessDenied,
		},
		{
			"client cannot claim sub", allow + cond("StringEquals", wiName+":sub", sub) + "}", broker,
			map[string][]string{wiName + ":sub": {sub}},
			sts.ErrAccessDenied,
		},
		{
			"client cannot claim provider", allow + cond("StringEquals", "aws:FederatedProvider", wiProvARN) + "}",
			broker,
			map[string][]string{"aws:federatedprovider": {wiProvARN}},
			sts.ErrAccessDenied,
		},
	} {
		trust(tc.trust)
		_, err := e.svc.AssumeRole(ctx, tc.caller, tc.reqCtx, adminARN, "chain", 0, "", sts.MFA{})
		if (tc.want == nil && err != nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	trust(allow + "}")
	chained, err := e.svc.AssumeRole(ctx, wiCaller, nil, adminARN, "chain", 0, "", sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	next := e.session(t, chained)
	if next.WebIdentity == nil || fmt.Sprint(*next.WebIdentity) != fmt.Sprint(*e.session(t, got.Credentials).WebIdentity) {
		t.Fatalf("chained web identity %+v", next.WebIdentity)
	}
	trust(allow + "}" + deny(wiName+":sub", sub))
	_, err = e.svc.AssumeRole(ctx, next.Caller(), nil, adminARN, "again", 0, "", sts.MFA{})
	if !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("second hop with Deny on sub: %v, want AccessDenied", err)
	}
	plain, err := e.svc.AssumeRole(ctx, broker, nil, adminARN, "plain", 0, "", sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	if ps := e.session(t, plain); ps.WebIdentity != nil {
		t.Fatalf("plain session web identity %+v", ps.WebIdentity)
	}
}

// TestClientKey: a client may send service keys but not saml:*,
// aws:FederatedProvider or OIDC provider keys, in any letter case.
func TestClientKey(t *testing.T) {
	for k, want := range map[string]bool{
		"aws:SourceIp": true, "sts:ExternalId": true, "s3:prefix": true, "aws:RequestTag/team": true,
		"saml:sub": false, "SAML:aud": false, "aws:FederatedProvider": false, "AWS:FEDERATEDPROVIDER": false,
		"accounts.google.com:sub": false, "oidc.ci.test/org/1:aud": false, "Token.Actions.Example:SUB": false,
	} {
		if got := sts.ClientKey(k); got != want {
			t.Errorf("ClientKey(%q) = %v, want %v", k, got, want)
		}
	}
}

// TestAssumeRoleWithWebIdentityJWKSKeys: keys read by ParseJWKS from the
// IdP's JWKS document verify its tokens of every algorithm.
func TestAssumeRoleWithWebIdentityJWKSKeys(t *testing.T) {
	e := wiSetup(t)
	doc, err := e.idp.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := sts.ParseJWKS(doc)
	if err != nil {
		t.Fatal(err)
	}
	svc := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithOIDC(oidctest.Providers{ByARN: map[string]sts.OIDCProvider{
		wiProvARN: {ARN: wiProvARN, URL: wiIssuer, ClientIDs: []string{wiClientID}, Keys: keys},
	}}))
	for _, alg := range []string{"RS256", "RS512", "ES256", "ES384", "ES512"} {
		if _, err := svc.AssumeRoleWithWebIdentity(context.Background(), wiReq(e.token(t, alg, e.claims()))); err != nil {
			t.Errorf("%s: %v", alg, err)
		}
	}
}
