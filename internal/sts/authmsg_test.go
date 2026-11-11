package sts_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/sts"
)

const (
	decodeAny = `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
		`"Action":"sts:DecodeAuthorizationMessage","Resource":"*"}}`
	denyDecode = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},` +
		`{"Sid":"NoDecode","Effect":"Deny","Action":"sts:DecodeAuthorizationMessage","Resource":"*"}]}`
)

// msgEnv adds a user allowed to decode ("auditor") and one denied
// explicitly ("blocked") to the sts test env.
func msgEnv(t *testing.T) env {
	t.Helper()
	e := setup(t)
	put(t, e.b, iam.User{Name: "auditor", ID: "6", InlinePolicies: map[string]string{"decode": decodeAny}})
	put(t, e.b, iam.User{Name: "blocked", ID: "7", InlinePolicies: map[string]string{"all": denyDecode}})
	return e
}

func sampleMessage() sts.AuthorizationMessage {
	return sts.NewAuthorizationMessage(
		sts.MessagePrincipal{ID: "3", Name: "bob", ARN: "arn:vws:iam::" + acct + ":user/bob"},
		"ec2:StopInstances", "arn:vws:ec2:kr-1:"+acct+":instance/i-1",
		policy.Decision{
			Explicit: true, Policy: "guard", Statement: "NoStop",
			Context: map[string][]string{"ec2:Tenancy": {"default"}, "aws:MultiFactorAuthPresent": {"false"}},
		},
	)
}

func TestDecodeAuthorizationMessageRoundTrip(t *testing.T) {
	e := msgEnv(t)
	ctx := context.Background()
	enc, err := e.svc.EncodeAuthorizationMessage(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) > sts.MaxEncodedMessageLen || strings.ContainsAny(enc, "\n\r =") {
		t.Fatalf("encoded message %d chars: %q", len(enc), enc)
	}
	// Long plaintext markers only: a short one can occur in random base64.
	if strings.Contains(enc, "StopInstances") || strings.Contains(enc, "arn:vws:iam::") {
		t.Fatal("encoded message is not opaque")
	}
	got, err := e.svc.DecodeAuthorizationMessage(ctx, e.caller(t, "auditor"), nil, enc)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"allowed":false,"explicitDeny":true,` +
		`"matchedStatements":{"items":[{"statementId":"NoStop","effect":"DENY","sourcePolicyName":"guard",` +
		`"principals":{"items":[]},"principalGroups":{"items":[]},"actions":{"items":[]},` +
		`"resources":{"items":[]},"conditions":{"items":[]}}]},` +
		`"failures":{"items":[]},` +
		`"context":{"principal":{"id":"3","name":"bob","arn":"arn:vws:iam::` + acct + `:user/bob"},` +
		`"action":"ec2:StopInstances","resource":"arn:vws:ec2:kr-1:` + acct + `:instance/i-1",` +
		`"conditions":{"items":[{"key":"aws:MultiFactorAuthPresent","values":{"items":[{"value":"false"}]}},` +
		`{"key":"ec2:Tenancy","values":{"items":[{"value":"default"}]}}]}}}`
	if got != want {
		t.Fatalf("decoded\n%s\nwant\n%s", got, want)
	}
	// Read only: a repeat, and the root user, read the same JSON.
	again, err := e.svc.DecodeAuthorizationMessage(ctx, sts.RootCaller(false, time.Time{}), nil, enc)
	if err != nil || again != want {
		t.Fatalf("repeat by root: %v %s", err, again)
	}
	// An implicit deny with no matching statement has empty lists, not null.
	implicit := sts.NewAuthorizationMessage(sts.MessagePrincipal{ID: "3"}, "s3:GetObject", "*", policy.Decision{})
	enc, err = e.svc.EncodeAuthorizationMessage(implicit)
	if err != nil {
		t.Fatal(err)
	}
	got, err = e.svc.DecodeAuthorizationMessage(ctx, e.caller(t, "auditor"), nil, enc)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	if m["allowed"] != false || m["explicitDeny"] != false ||
		!strings.Contains(got, `"matchedStatements":{"items":[]}`) || !strings.Contains(got, `"conditions":{"items":[]}`) {
		t.Fatalf("implicit deny: %s", got)
	}
}

func TestDecodeAuthorizationMessageTampered(t *testing.T) {
	e := msgEnv(t)
	ctx := context.Background()
	enc, err := e.svc.EncodeAuthorizationMessage(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	kid, body, _ := strings.Cut(enc, ".")
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) string {
		b := append([]byte(nil), raw...)
		b[i] ^= 1
		return kid + "." + base64.RawURLEncoding.EncodeToString(b)
	}
	cases := map[string]string{
		"flipped nonce":      flip(0),
		"flipped ciphertext": flip(len(raw) / 2),
		"flipped tag":        flip(len(raw) - 1),
		"truncated":          enc[:len(enc)-8],
		"unknown KEK":        "kek-9." + body,
		"no KEK":             body,
		"empty KEK":          "." + body,
		"not base64":         kid + ".!!!" + body[3:],
		"line break":         enc[:20] + "\n" + enc[20:],
		"short":              kid + ".AAAA",
		"garbage":            strings.Repeat("A", sts.MaxEncodedMessageLen),
	}
	// The last character of unpadded base64 carries unused low bits when
	// the length is not a multiple of 4; a changed one must not decode to
	// the same ciphertext. Grow the message until it has such bits.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for pad := ""; ; pad += "x" {
		m := sampleMessage()
		m.Context.Resource += pad
		odd, err := e.svc.EncodeAuthorizationMessage(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, b, _ := strings.Cut(odd, "."); len(b)%4 != 0 {
			last := strings.IndexByte(alphabet, odd[len(odd)-1])
			cases["non-canonical last character"] = odd[:len(odd)-1] + string(alphabet[last^1])
			break
		}
	}
	auditor := e.caller(t, "auditor")
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.svc.DecodeAuthorizationMessage(ctx, auditor, nil, msg)
			if !errors.Is(err, sts.ErrInvalidAuthorizationMessage) {
				t.Fatalf("err %v, want InvalidAuthorizationMessageException", err)
			}
		})
	}
}

func TestDecodeAuthorizationMessageUnauthorized(t *testing.T) {
	e := msgEnv(t)
	ctx := context.Background()
	enc, err := e.svc.EncodeAuthorizationMessage(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"bob", "alice", "blocked"} {
		for _, msg := range []string{enc, "not-a-message"} {
			got, err := e.svc.DecodeAuthorizationMessage(ctx, e.caller(t, user), nil, msg)
			// The permission is checked first: an unauthorized caller
			// cannot tell a valid message from an invalid one.
			if !errors.Is(err, sts.ErrAccessDenied) || got != "" {
				t.Fatalf("%s: %q %v, want AccessDenied", user, got, err)
			}
		}
	}
	if _, err := e.svc.DecodeAuthorizationMessage(ctx, sts.Caller{}, nil, enc); !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("unresolved caller: %v", err)
	}
	// A session policy narrows the permission away.
	put(t, e.b, iam.Role{
		Name: "decoder", ID: "8",
		AssumeRolePolicy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Principal":{"AWS":"arn:vws:iam::` + acct + `:user/alice"},"Action":"sts:AssumeRole"}}`,
		InlinePolicies: map[string]string{"decode": decodeAny},
	})
	narrow := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`
	for _, tc := range []struct {
		session string
		allowed bool
	}{{"", true}, {narrow, false}} {
		role := "arn:vws:iam::" + acct + ":role/decoder"
		creds, err := e.svc.AssumeRole(ctx, e.caller(t, "alice"), nil, role, "audit", 0,
			sts.SessionPolicies{Policy: tc.session}, sts.MFA{})
		if err != nil {
			t.Fatal(err)
		}
		c, err := e.svc.Resolve(ctx, sts.Credential{AccessKeyID: creds.AccessKeyID, SessionToken: creds.SessionToken})
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.svc.DecodeAuthorizationMessage(ctx, c, nil, enc)
		if (err == nil) != tc.allowed || (!tc.allowed && !errors.Is(err, sts.ErrAccessDenied)) {
			t.Fatalf("role session (policy %q): %v", tc.session, err)
		}
	}
}

func TestDecodeAuthorizationMessageLengthBounds(t *testing.T) {
	e := msgEnv(t)
	ctx := context.Background()
	for _, n := range []int{0, sts.MaxEncodedMessageLen + 1, 1 << 20} {
		_, err := e.svc.DecodeAuthorizationMessage(ctx, e.caller(t, "auditor"), nil, strings.Repeat("A", n))
		if !errors.Is(err, sts.ErrInvalidRequest) {
			t.Fatalf("length %d: %v, want ValidationError", n, err)
		}
	}
	for _, n := range []int{1, sts.MaxEncodedMessageLen} {
		_, err := e.svc.DecodeAuthorizationMessage(ctx, e.caller(t, "auditor"), nil, strings.Repeat("A", n))
		if !errors.Is(err, sts.ErrInvalidAuthorizationMessage) {
			t.Fatalf("length %d: %v, want InvalidAuthorizationMessageException", n, err)
		}
	}
	// A context too large for the limit loses condition keys from the end
	// until the encoded message fits, and stays decodable.
	big := map[string][]string{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		big["vws:"+k] = []string{strings.Repeat(k, 1500)}
	}
	m := sts.NewAuthorizationMessage(sts.MessagePrincipal{ID: "3"}, "s3:PutObject", "*", policy.Decision{Context: big})
	enc, err := e.svc.EncodeAuthorizationMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(enc) > sts.MaxEncodedMessageLen {
		t.Fatalf("encoded %d chars", len(enc))
	}
	got, err := e.svc.DecodeAuthorizationMessage(ctx, e.caller(t, "auditor"), nil, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"key":"vws:a"`) || strings.Contains(got, `"key":"vws:h"`) {
		t.Fatalf("trim keeps the first keys: %.200s", got)
	}
	if len(m.Context.Conditions.Items) != len(big) {
		t.Fatal("encoding changed the caller's message")
	}
	// With a matched statement too, context keys go first, and the
	// statement keeps every field until they are gone.
	var res []string
	for _, k := range []string{"a", "b", "c", "d", "e", "f"} {
		res = append(res, "arn:vws:s3:::"+strings.Repeat(k, 1200))
	}
	withStmt := func(ctx map[string][]string, res []string) sts.AuthorizationMessage {
		st := policy.Statement{
			Sid: "NoPut", Effect: policy.Deny, Actions: []string{"s3:PutObject"}, Resources: res,
			Conditions: []policy.Condition{{Op: "StringEquals", Key: "s3:x-amz-acl", Values: []string{"public-read"}}},
		}
		return sts.NewAuthorizationMessage(sts.MessagePrincipal{ID: "3"}, "s3:PutObject", "*", policy.Decision{
			Explicit: true, Policy: "guard", Statement: "NoPut", Context: ctx,
			Matched: &policy.Matched{Statement: st, Holder: policy.Holder{ID: "3"}},
		})
	}
	reader := e.caller(t, "auditor")
	decoded := func(m sts.AuthorizationMessage) sts.AuthorizationMessage {
		t.Helper()
		enc, err := e.svc.EncodeAuthorizationMessage(m)
		if err != nil {
			t.Fatal(err)
		}
		if len(enc) > sts.MaxEncodedMessageLen {
			t.Fatalf("encoded %d chars", len(enc))
		}
		got, err := e.svc.DecodeAuthorizationMessage(ctx, reader, nil, enc)
		if err != nil {
			t.Fatal(err)
		}
		var out sts.AuthorizationMessage
		if err := json.Unmarshal([]byte(got), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	small := map[string][]string{"vws:a": {strings.Repeat("a", 1500)}}
	fits := decoded(withStmt(small, res[:2]))
	if s := fits.MatchedStatements.Items[0]; len(fits.Context.Conditions.Items) != 1 || len(s.Resources.Items) != 2 ||
		len(s.Conditions.Items) != 1 || len(s.Actions.Items) != 1 || len(s.Principals.Items) != 1 {
		t.Fatalf("a message that fits lost items: %d context keys, %d resources, %d conditions",
			len(fits.Context.Conditions.Items), len(s.Resources.Items), len(s.Conditions.Items))
	}
	m = withStmt(big, res)
	trimmed := decoded(m)
	s := trimmed.MatchedStatements.Items[0]
	if len(trimmed.Context.Conditions.Items) != 0 || len(s.Conditions.Items) != 0 ||
		len(s.Resources.Items) == 0 || len(s.Resources.Items) == len(res) ||
		s.Resources.Items[0].Value != res[0] || len(s.Actions.Items) != 1 || len(s.Principals.Items) != 1 ||
		s.StatementID != "NoPut" || s.Effect != "DENY" {
		t.Fatalf("trim order: %d context keys, %d conditions, %d of %d resources, %d actions, %d principals",
			len(trimmed.Context.Conditions.Items), len(s.Conditions.Items), len(s.Resources.Items), len(res),
			len(s.Actions.Items), len(s.Principals.Items))
	}
	if ms := m.MatchedStatements.Items[0]; len(m.Context.Conditions.Items) != len(big) ||
		len(ms.Resources.Items) != len(res) || len(ms.Conditions.Items) != 1 {
		t.Fatal("encoding changed the caller's message")
	}
	// A message that cannot fit even with no conditions is refused.
	long := strings.Repeat("r", sts.MaxEncodedMessageLen)
	huge := sts.NewAuthorizationMessage(sts.MessagePrincipal{ID: "3"}, "s3:PutObject", long, policy.Decision{})
	if _, err := e.svc.EncodeAuthorizationMessage(huge); !errors.Is(err, sts.ErrInvalidRequest) {
		t.Fatalf("oversized message: %v", err)
	}
}

func TestDecodeAuthorizationMessageExpiresAndStaysInProject(t *testing.T) {
	e := msgEnv(t)
	ctx := context.Background()
	enc, err := e.svc.EncodeAuthorizationMessage(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	// Another project with the same KEK cannot read it: the project is in
	// the associated data and in the sealed envelope.
	other := sts.New(e.b, e.keys, authz.New(e.b, "111111111111", e.clk.now), "111111111111", e.clk.now)
	root := sts.RootCaller(false, time.Time{})
	_, err = other.DecodeAuthorizationMessage(ctx, root, nil, enc)
	if !errors.Is(err, sts.ErrInvalidAuthorizationMessage) {
		t.Fatalf("other project: %v", err)
	}
	start := e.clk.t
	e.clk.t = start.Add(sts.AuthorizationMessageTTL - time.Second)
	if _, err := e.svc.DecodeAuthorizationMessage(ctx, e.caller(t, "auditor"), nil, enc); err != nil {
		t.Fatalf("before expiry: %v", err)
	}
	e.clk.t = start.Add(sts.AuthorizationMessageTTL)
	_, err = e.svc.DecodeAuthorizationMessage(ctx, e.caller(t, "auditor"), nil, enc)
	if !errors.Is(err, sts.ErrInvalidAuthorizationMessage) {
		t.Fatalf("expired: %v", err)
	}
}

func TestDecodeAuthorizationMessageAcrossKEKRotation(t *testing.T) {
	e := msgEnv(t)
	ctx := context.Background()
	rng := rand.NewChaCha8([32]byte{1})
	kek := func() []byte {
		k := make([]byte, 32)
		if _, err := rng.Read(k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	ring := func(active string, keys map[string][]byte) *sts.Service {
		r, err := secret.NewKeyring(active, keys)
		if err != nil {
			t.Fatal(err)
		}
		return sts.New(e.b, r, e.az, acct, e.clk.now)
	}
	a, b := kek(), kek()
	enc, err := ring("kek-a", map[string][]byte{"kek-a": a}).EncodeAuthorizationMessage(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	c := e.caller(t, "auditor")
	// A restart with a new active KEK that keeps the old one still decodes
	// an earlier message; once the old KEK is gone it does not.
	rotated := ring("kek-b", map[string][]byte{"kek-a": a, "kek-b": b})
	if _, err := rotated.DecodeAuthorizationMessage(ctx, c, nil, enc); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	dropped := ring("kek-b", map[string][]byte{"kek-b": b})
	_, err = dropped.DecodeAuthorizationMessage(ctx, c, nil, enc)
	if !errors.Is(err, sts.ErrInvalidAuthorizationMessage) {
		t.Fatalf("old KEK removed: %v", err)
	}
}

// TestAuthorizationMessageNegatedElements: AWS has no field for
// NotAction, NotResource or NotPrincipal, so a statement using them lists
// no actions, resources or statement principals rather than the patterns
// it excludes; the holder's id is still listed.
func TestAuthorizationMessageNegatedElements(t *testing.T) {
	st := policy.Statement{
		Sid: "OnlyS3", Effect: policy.Deny, Actions: []string{"s3:*"}, NotAction: true,
		Resources: []string{"arn:vws:s3:::pub/*"}, NotRes: true,
		Principals: map[string][]string{"AWS": {"arn:vws:iam::" + acct + ":root"}}, NotPrincipal: true,
	}
	m := sts.NewAuthorizationMessage(sts.MessagePrincipal{ID: "3"}, "ec2:RunInstances", "*", policy.Decision{
		Explicit: true, Policy: "guard", Statement: "OnlyS3",
		Matched: &policy.Matched{Statement: st, Holder: policy.Holder{ID: "AIDA3"}},
	})
	b, err := json.Marshal(m.MatchedStatements)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"items":[{"statementId":"OnlyS3","effect":"DENY","sourcePolicyName":"guard",` +
		`"principals":{"items":[{"value":"AIDA3"}]},"principalGroups":{"items":[]},` +
		`"actions":{"items":[]},"resources":{"items":[]},"conditions":{"items":[]}}]}`
	if string(b) != want {
		t.Fatalf("got\n%s\nwant\n%s", b, want)
	}
}

// TestAuthorizationMessageFromEarlierRelease: a message sealed before
// matched statements had their lists decodes them as empty lists, not
// null.
func TestAuthorizationMessageFromEarlierRelease(t *testing.T) {
	e := msgEnv(t)
	old := sts.AuthorizationMessage{MatchedStatements: sts.Items[sts.MatchedStatement]{
		Items: []sts.MatchedStatement{{StatementID: "NoStop", Effect: "DENY", SourcePolicyName: "guard"}},
	}}
	enc, err := e.svc.EncodeAuthorizationMessage(old)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.DecodeAuthorizationMessage(context.Background(), e.caller(t, "auditor"), nil, enc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "null") || !strings.Contains(got, `"principals":{"items":[]}`) {
		t.Fatalf("decoded %s", got)
	}
}
