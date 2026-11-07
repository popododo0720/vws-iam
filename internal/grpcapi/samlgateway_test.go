package grpcapi_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

const (
	samlSub   = "alice@corp.test"
	assumeAny = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}}`
)

// samlGateway is a deployment where a SAML session, a role session chained
// from it and a plain session of the same role reach the gateway. The role
// policy allows s3:* and denies GetObject on saml:sub, PutObject on
// saml:sub_type, DeleteObject on saml:namequalifier and CopyObject on
// another subject (#202).
type samlGateway struct {
	e     *env
	b     store.Backend
	saml  sts.Credentials
	chain *iamv1.AssumeRoleResponse
	plain *iamv1.AssumeRoleResponse
	// The principals Authenticate returns for the three sessions.
	samlP, chainP, plainP *iamv1.Principal
}

func newSAMLGateway(t *testing.T, b store.Backend) *samlGateway {
	t.Helper()
	now := time.Now().UTC()
	idp, err := samltest.New(samlIssuer, now)
	if err != nil {
		t.Fatal(err)
	}
	sp := sts.SAMLServiceProvider{Audience: samlSPID, SignInURL: samlAud}
	e := newEnvOn(t, b, &now, grpcapi.WithSAML(samltest.Providers{samlIdpARN: idp.Provider(samlIdpARN)}, sp))
	ctx := t.Context()
	role := func(id, trust, s3 string) {
		t.Helper()
		inline := map[string]string{"sts": assumeAny}
		if s3 != "" {
			inline["s3"] = s3
		}
		if _, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
			Parent: parentName, RoleId: id,
			Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust, InlinePolicies: inline}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	samlTrust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"` +
		samlIdpARN + `"},"Action":"sts:AssumeRoleWithSAML"}]}`
	session := func(roleID string) sts.SAMLRoleSession {
		t.Helper()
		r, err := idp.Response(samltest.Assertion{
			Issuer: samlIssuer, Audience: samlSPID, Recipient: samlAud, Destination: samlAud,
			NameID: samlSub, NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			Roles:       []string{"arn:vws:iam::" + proj + ":role/" + roleID + "," + samlIdpARN},
			SessionName: "alice", NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute),
			ConfirmNotOnOrAfter: now.Add(5 * time.Minute),
		}, samltest.SignAssertion)
		if err != nil {
			t.Fatal(err)
		}
		out, err := e.api.AssumeSAMLRole(ctx, sts.SAMLRequest{
			RoleARN: "arn:vws:iam::" + proj + ":role/" + roleID, PrincipalARN: samlIdpARN, Assertion: r,
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	role("probe", samlTrust, "")
	nq := session("probe").NameQualifier
	deny := func(action, key, value string) string {
		return `{"Effect":"Deny","Action":"` + action + `","Resource":"*","Condition":{"StringEquals":{"saml:` +
			key + `":"` + value + `"}}}`
	}
	s3 := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"},` +
		deny("s3:GetObject", "sub", samlSub) + `,` + deny("s3:PutObject", "sub_type", "persistent") + `,` +
		deny("s3:DeleteObject", "namequalifier", nq) + `,` + deny("s3:CopyObject", "sub", "bob@corp.test") + `]}`
	role("saml-dev", samlTrust, s3)
	chainTrust := func(sub string) string {
		return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"` + proj +
			`"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",` +
			`"Condition":{"StringEquals":{"saml:sub":"` + sub + `"}}}]}`
	}
	role("deny-alice", chainTrust(samlSub), s3)
	role("deny-bob", chainTrust("bob@corp.test"), s3)

	g := &samlGateway{e: e, b: b, saml: session("saml-dev").Credentials}
	c := g.saml
	_, err = g.assume(ctx, e.stsSign(c.AccessKeyID, c.Secret, c.SessionToken, "AssumeRole"), "deny-alice", "chain")
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	samlSig := e.stsSign(c.AccessKeyID, c.Secret, c.SessionToken, "AssumeRole")
	if g.chain, err = g.assume(ctx, samlSig, "deny-bob", "chain"); err != nil {
		t.Fatal(err)
	}
	broker := e.keyedUser(t, "broker", assumeAny)
	brokerSig := e.stsSign(broker.id, broker.secretKey, "", "AssumeRole")
	if g.plain, err = g.assume(ctx, brokerSig, "deny-bob", "plain"); err != nil {
		t.Fatal(err)
	}
	cc, pc := g.chain.GetCredentials(), g.plain.GetCredentials()
	g.samlP = g.authenticate(t, c.AccessKeyID, c.Secret, c.SessionToken)
	g.chainP = g.authenticate(t, cc.GetAccessKeyId(), cc.GetSecretAccessKey(), cc.GetSessionToken())
	g.plainP = g.authenticate(t, pc.GetAccessKeyId(), pc.GetSecretAccessKey(), pc.GetSessionToken())
	return g
}

func (g *samlGateway) assume(
	ctx context.Context, sig *iamv1.AuthenticateRequest, roleID, sessionName string,
) (*iamv1.AssumeRoleResponse, error) {
	return g.e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
		Authentication: arSig(sig), Role: parentName + "/roles/" + roleID, RoleSessionName: sessionName,
	})
}

func (g *samlGateway) authenticate(t *testing.T, id, secret, token string) *iamv1.Principal {
	t.Helper()
	resp, err := g.e.auth.Authenticate(t.Context(), g.e.sign(id, secret, token))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return resp.GetPrincipal()
}

// decide is the gateway's Authorize call; kv are request context pairs.
func decide(t *testing.T, e *env, p *iamv1.Principal, action string, kv ...string) *iamv1.AuthorizeResponse {
	t.Helper()
	req := &iamv1.AuthorizeRequest{Principal: p, Action: action}
	for i := 0; i < len(kv); i += 2 {
		if req.Context == nil {
			req.Context = map[string]*iamv1.ContextValues{}
		}
		req.Context[kv[i]] = &iamv1.ContextValues{Values: []string{kv[i+1]}}
	}
	resp, err := e.auth.Authorize(t.Context(), req)
	if err != nil {
		t.Fatalf("Authorize %s: %v", action, err)
	}
	return resp
}

func expect(t *testing.T, what string, got *iamv1.AuthorizeResponse, want iamv1.Decision) {
	t.Helper()
	if got.GetDecision() != want {
		t.Errorf("%s: %v (%s), want %v", what, got.GetDecision(), got.GetReason(), want)
	}
}

const (
	allow    = iamv1.Decision_DECISION_ALLOW
	explicit = iamv1.Decision_DECISION_DENY_EXPLICIT
	implicit = iamv1.Decision_DECISION_DENY_IMPLICIT
)

// expectSAMLDecisions: the role policy denies each saml:* key of a SAML
// identity (and not another subject's), so a session with the identity is
// denied by the keys it holds; a session without one is allowed throughout.
func expectSAMLDecisions(t *testing.T, e *env, name string, p *iamv1.Principal, hasIdentity bool) {
	t.Helper()
	deniedWith := allow
	if hasIdentity {
		deniedWith = explicit
	}
	for action, want := range map[string]iamv1.Decision{
		"s3:GetObject": deniedWith, "s3:PutObject": deniedWith, "s3:DeleteObject": deniedWith,
		"s3:CopyObject": allow, "s3:ListBucket": allow,
	} {
		expect(t, name+" "+action, decide(t, e, p, action), want)
	}
}

// TestAssumeRoleWithSAMLSessionIdentity: on both store backends, a SAML
// session signs a further STS AssumeRole with its saml:sub restored as a
// trusted key, so the next role's trust policy can deny on it; the SAML
// session and a role session chained from it authenticate at the gateway,
// and the Principal Authenticate (and AssumeRole) returns, passed unchanged
// to Authorize, makes a Deny on saml:sub, saml:sub_type or
// saml:namequalifier explicit, while a plain session of the same role is
// allowed (#202).
func TestAssumeRoleWithSAMLSessionIdentity(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			g := newSAMLGateway(t, bk.open())
			e := g.e
			for name, p := range map[string]*iamv1.Principal{"SAML session": g.samlP, "chained session": g.chainP} {
				if p.GetType() != iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE || p.GetSessionContext() == "" {
					t.Fatalf("%s principal %v has no session context", name, p)
				}
				expectSAMLDecisions(t, e, name, p, true)
			}
			expectSAMLDecisions(t, e, "plain session", g.plainP, false)

			// The AssumeRole response's principal authorizes alike.
			expect(t, "AssumeRole chained", decide(t, e, g.chain.GetAssumedRoleUser(), "s3:GetObject"), explicit)
			expect(t, "AssumeRole plain", decide(t, e, g.plain.GetAssumedRoleUser(), "s3:GetObject"), allow)
		})
	}
}

// TestSAMLSessionContextIsRequired: an assumed-role principal is refused
// without its session context, with another session's, or with one the
// service did not seal, so a gateway that drops or swaps the field cannot
// skip a Deny on saml:sub; and a client's saml:* keys neither give a plain
// session an identity nor replace a SAML session's.
func TestSAMLSessionContextIsRequired(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			g := newSAMLGateway(t, bk.open())
			e := g.e
			with := func(p *iamv1.Principal, ctx string) *iamv1.Principal {
				out, ok := proto.Clone(p).(*iamv1.Principal)
				if !ok {
					t.Fatal("clone is not a Principal")
				}
				out.SessionContext = ctx
				return out
			}
			for name, p := range map[string]*iamv1.Principal{
				"SAML cleared":      with(g.samlP, ""),
				"plain cleared":     with(g.plainP, ""),
				"SAML with plain":   with(g.samlP, g.plainP.GetSessionContext()),
				"plain with SAML":   with(g.plainP, g.samlP.GetSessionContext()),
				"chained with SAML": with(g.chainP, g.samlP.GetSessionContext()),
				"garbage":           with(g.samlP, "kek.AAAA"),
				"not a reference":   with(g.samlP, g.saml.SessionToken),
				"flipped":           with(g.samlP, flip(g.samlP.GetSessionContext())),
			} {
				d := decide(t, e, p, "s3:GetObject")
				expect(t, name, d, implicit)
				if d.GetEncodedMessage() != "" {
					t.Errorf("%s: a refused principal carries an authorization message", name)
				}
			}
			cleared := decide(t, e, with(g.samlP, ""), "s3:ListBucket")
			if !strings.Contains(cleared.GetReason(), "session context required") {
				t.Errorf("cleared context reason %q", cleared.GetReason())
			}

			// A client claim of saml:* is dropped, in any letter case.
			for _, key := range []string{"saml:sub", "SAML:Sub", "saml:SUB"} {
				expect(t, "plain claiming alice via "+key, decide(t, e, g.plainP, "s3:GetObject", key, samlSub), allow)
				expect(t, "plain claiming bob via "+key, decide(t, e, g.plainP, "s3:CopyObject", key, "bob@corp.test"), allow)
				expect(t, "SAML replaced by bob via "+key, decide(t, e, g.samlP, "s3:CopyObject", key, "bob@corp.test"), allow)
				expect(t, "SAML hiding via "+key, decide(t, e, g.samlP, "s3:GetObject", key, "bob@corp.test"), explicit)
				expect(t, "chained hiding via "+key, decide(t, e, g.chainP, "s3:GetObject", key, "bob@corp.test"), explicit)
			}
		})
	}
}

// flip changes one character of a reference's ciphertext.
func flip(ref string) string {
	b := []byte(ref)
	i := len(b) - 3
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// TestSAMLSessionAuthorizesAfterRestartAndReplay: the same principal gives
// the same decision again, on a second server over the same store, and
// whichever order the calls come in.
func TestSAMLSessionAuthorizesAfterRestartAndReplay(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			g := newSAMLGateway(t, bk.open())
			restarted := newEnvOn(t, g.b, g.e.now)
			for round := 0; round < 2; round++ {
				for _, e := range []*env{g.e, restarted} {
					expectSAMLDecisions(t, e, "SAML session", g.samlP, true)
					expectSAMLDecisions(t, e, "chained session", g.chainP, true)
					expectSAMLDecisions(t, e, "plain session", g.plainP, false)
				}
			}
			// The restarted server also authenticates the sessions itself.
			c := g.saml
			resp, err := restarted.auth.Authenticate(t.Context(), restarted.sign(c.AccessKeyID, c.Secret, c.SessionToken))
			if err != nil {
				t.Fatal(err)
			}
			expect(t, "restarted Authenticate", decide(t, restarted, resp.GetPrincipal(), "s3:GetObject"), explicit)
		})
	}
}

// TestSAMLSessionRevoked: RevokeRoleSessions ends the sessions of the role
// at Authorize on every server, SAML identity or not, and leaves the
// sessions of another role alone.
func TestSAMLSessionRevoked(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			g := newSAMLGateway(t, bk.open())
			e := g.e
			other := newEnvOn(t, g.b, e.now)
			*e.now = e.now.Add(time.Second)
			revoke := func(role string) {
				t.Helper()
				if _, err := e.roles.RevokeRoleSessions(t.Context(), &iamv1.RevokeRoleSessionsRequest{
					Name: parentName + "/roles/" + role,
				}); err != nil {
					t.Fatal(err)
				}
			}
			revoke("saml-dev")
			for _, srv := range []*env{e, other} {
				expect(t, "revoked SAML session", decide(t, srv, g.samlP, "s3:GetObject"), implicit)
				expect(t, "other role's chained session", decide(t, srv, g.chainP, "s3:GetObject"), explicit)
				expect(t, "other role's plain session", decide(t, srv, g.plainP, "s3:GetObject"), allow)
			}
			revoke("deny-bob")
			for _, srv := range []*env{e, other} {
				for name, p := range map[string]*iamv1.Principal{"chained": g.chainP, "plain": g.plainP} {
					d := decide(t, srv, p, "s3:GetObject")
					expect(t, "revoked "+name+" session", d, implicit)
					if !strings.Contains(d.GetReason(), "revoked") {
						t.Errorf("%s reason %q", name, d.GetReason())
					}
				}
			}
			c := g.saml
			_, err := e.auth.Authenticate(t.Context(), e.sign(c.AccessKeyID, c.Secret, c.SessionToken))
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidToken")
		})
	}
}

// TestClientKeysFoldedByUnicodeAreIgnored: a client key that only Unicode
// simple folding equates with a server key ("ſaml:sub", U+017F) is not a
// copy the filter drops, so policy evaluation must not read it as that key:
// it neither replaces a SAML session's saml:sub, nor gives a user a
// saml:sub, nor claims aws:MultiFactorAuthPresent. Map order is random, so
// each request repeats.
func TestClientKeysFoldedByUnicodeAreIgnored(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			g := newSAMLGateway(t, bk.open())
			e := g.e
			user := func(name, cond string) *iamv1.Principal {
				u := e.keyedUser(t, name, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject",`+
					`"Resource":"*","Condition":`+cond+`}}`)
				return g.authenticate(t, u.id, u.secretKey, "")
			}
			subUser := user("sub-user", `{"StringEquals":{"saml:sub":"`+samlSub+`"}}`)
			mfaUser := user("mfa-user", `{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`)
			for range 20 {
				expect(t, "SAML session, client ſaml:sub", decide(t, e, g.samlP, "s3:GetObject", "ſaml:sub", "bob@corp.test"),
					iamv1.Decision_DECISION_DENY_EXPLICIT)
				expect(t, "plain session, client ſaml:sub", decide(t, e, g.plainP, "s3:CopyObject", "ſaml:sub", "bob@corp.test"),
					iamv1.Decision_DECISION_ALLOW)
				expect(t, "user, client ſaml:sub", decide(t, e, subUser, "s3:GetObject", "ſaml:sub", samlSub),
					iamv1.Decision_DECISION_DENY_IMPLICIT)
				expect(t, "user without MFA, client aws:MultiFactorAuthPreſent", decide(t, e, mfaUser, "s3:GetObject",
					"aws:MultiFactorAuthPreſent", "true"), iamv1.Decision_DECISION_DENY_IMPLICIT)
			}
		})
	}
}
