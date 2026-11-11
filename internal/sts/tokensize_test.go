package sts_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

// issuer is one STS call that issues a session, with the given options.
type issuer struct {
	name  string
	issue func(t *testing.T, opts ...sts.IssueOption) (sts.Credentials, error)
}

// issuers are the four STS calls that issue a session (#199), all from one
// environment, so their tokens open with one keyring.
func issuers(t *testing.T, e samlEnv) []issuer {
	ctx := context.Background()
	adminRole := "arn:vws:iam::" + acct + ":role/admin"
	broker := e.caller(t, "broker")
	return []issuer{
		{"AssumeRole", func(t *testing.T, opts ...sts.IssueOption) (sts.Credentials, error) {
			return e.svc.AssumeRole(ctx, broker, nil, adminRole, "s1", time.Hour,
				sts.SessionPolicies{}, sts.MFA{}, opts...)
		}},
		{"GetSessionToken", func(t *testing.T, opts ...sts.IssueOption) (sts.Credentials, error) {
			return e.svc.GetSessionToken(ctx, broker, time.Hour, sts.MFA{}, opts...)
		}},
		{"GetFederationToken", func(t *testing.T, opts ...sts.IssueOption) (sts.Credentials, error) {
			tok, err := e.svc.GetFederationToken(ctx, broker, nil,
				sts.FederationRequest{Name: "bob", Policy: s3PutOnly}, opts...)
			return tok.Credentials, err
		}},
		{"AssumeRoleWithSAML", func(t *testing.T, opts ...sts.IssueOption) (sts.Credentials, error) {
			got, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)), opts...)
			return got.Credentials, err
		}},
	}
}

// padOverhead is the token bytes of an empty pad field: `,"z":""` is 7
// plaintext bytes, at most 10 base64 bytes.
const padOverhead = 10

func checkSizeFields(t *testing.T, c sts.Credentials) {
	t.Helper()
	want := (len(c.SessionToken)*100 + sts.MaxSessionTokenSize - 1) / sts.MaxSessionTokenSize
	if c.SessionTokenSize != len(c.SessionToken) || c.SessionTokenUtilization != want {
		t.Fatalf("SessionTokenSize %d, SessionTokenUtilization %d; token %d bytes, want %d%%",
			c.SessionTokenSize, c.SessionTokenUtilization, len(c.SessionToken), want)
	}
}

// TestSessionTokenSizeFields: every STS call that issues a session reports
// the AWS SessionTokenSize (bytes of the token returned) and
// SessionTokenUtilization (its share of MaxSessionTokenSize, rounded up).
func TestSessionTokenSizeFields(t *testing.T) {
	e := samlSetup(t)
	for _, is := range issuers(t, e) {
		t.Run(is.name, func(t *testing.T) {
			c, err := is.issue(t)
			if err != nil {
				t.Fatal(err)
			}
			checkSizeFields(t, c)
			if c.SessionTokenSize == 0 || c.SessionTokenUtilization == 0 {
				t.Fatalf("empty size fields %d %d", c.SessionTokenSize, c.SessionTokenUtilization)
			}
		})
	}
}

// TestMinimumSessionTokenSize: MinimumSessionTokenSize grows the token to
// at least the size asked for, from one byte to MaxSessionTokenSize, and
// leaves a token already that long unchanged in size; the padded token
// opens and works as any other, also on a restarted service, and every
// call issues new credentials padded alike.
func TestMinimumSessionTokenSize(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	for _, is := range issuers(t, e) {
		t.Run(is.name, func(t *testing.T) {
			base, err := is.issue(t, sts.MinimumSessionTokenSize(0))
			if err != nil {
				t.Fatal(err)
			}
			plain := len(base.SessionToken)
			sizes := []int{
				1, plain - 1, plain, plain + 1, plain + 2, plain + 3, 2000,
				sts.MaxSessionTokenSize - 1, sts.MaxSessionTokenSize,
			}
			for _, n := range sizes {
				c, err := is.issue(t, sts.MinimumSessionTokenSize(n))
				if err != nil {
					t.Fatalf("minimum %d: %v", n, err)
				}
				got := len(c.SessionToken)
				// The smallest pad adds its JSON field, padOverhead bytes;
				// past that a token ends within 3 bytes of n.
				if got < n || got > max(n, plain+padOverhead)+3 {
					t.Fatalf("minimum %d: token %d bytes (unpadded %d)", n, got, plain)
				}
				checkSizeFields(t, c)
				for _, svc := range []*sts.Service{e.svc, restarted} {
					sess, err := svc.Validate(ctx, c.AccessKeyID, c.SessionToken)
					if err != nil || sess.Secret != c.Secret {
						t.Fatalf("minimum %d: padded token does not open: %v", n, err)
					}
				}
				if c.AccessKeyID == base.AccessKeyID {
					t.Fatalf("minimum %d: credentials reused", n)
				}
			}
		})
	}
}

// TestMinimumSessionTokenSizeValidation: a MinimumSessionTokenSize outside
// 0 to 4096 is ValidationError before the permission check, so a caller
// without any permission gets the same answer and nothing is issued.
func TestMinimumSessionTokenSizeValidation(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	all := issuers(t, e)
	nobody := e.caller(t, "nobody")
	for _, n := range []int{-1, sts.MaxSessionTokenSize + 1, 1 << 30} {
		for _, is := range all {
			c, err := is.issue(t, sts.MinimumSessionTokenSize(n))
			if !errors.Is(err, sts.ErrInvalidRequest) || c.SessionToken != "" {
				t.Fatalf("%s minimum %d: %v", is.name, n, err)
			}
		}
		_, err := e.svc.GetFederationToken(ctx, nobody, nil,
			sts.FederationRequest{Name: "bob"}, sts.MinimumSessionTokenSize(n))
		if !errors.Is(err, sts.ErrInvalidRequest) {
			t.Fatalf("unauthorized caller, minimum %d: %v", n, err)
		}
	}
	// The last option given wins, as for any repeated parameter.
	c, err := all[0].issue(t, sts.MinimumSessionTokenSize(-1), sts.MinimumSessionTokenSize(3000))
	if err != nil || len(c.SessionToken) < 3000 {
		t.Fatalf("last option: %d bytes, %v", len(c.SessionToken), err)
	}
	if s := fmt.Sprint(c); len(s) > 200 {
		t.Fatalf("String carries the padded token: %d bytes", len(s))
	}
}

// TestSessionTokenOverMaxIsAccepted pins the #364 decision: VWS never
// refuses a request AWS accepts, so a valid 2,048-character session policy
// whose JSON escapes ("&" seals as \u0026) make the token pass
// MaxSessionTokenSize is issued, SessionTokenUtilization passes 100, and
// PackedPolicySize stays the plaintext share (#192). The token opens on a
// restarted service, and a repeated call issues new credentials alike.
func TestSessionTokenOverMaxIsAccepted(t *testing.T) {
	e := samlSetup(t)
	ctx := context.Background()
	broker := e.caller(t, "broker")
	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	policy := func(n int) string {
		head := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:vws:s3:::`
		tail := `"}}`
		return head + strings.Repeat("&", n-len(head)-len(tail)) + tail
	}
	req := sts.FederationRequest{Name: "bob", Policy: policy(sts.MaxPackedPolicyChars)}
	var keys []string
	for range 2 {
		tok, err := e.svc.GetFederationToken(ctx, broker, nil, req)
		if err != nil {
			t.Fatalf("token over %d bytes refused: %v", sts.MaxSessionTokenSize, err)
		}
		c := tok.Credentials
		checkSizeFields(t, c)
		if c.SessionTokenSize <= sts.MaxSessionTokenSize || c.SessionTokenUtilization <= 100 {
			t.Fatalf("token %d bytes, utilization %d: not over the limit", c.SessionTokenSize, c.SessionTokenUtilization)
		}
		if tok.PackedPolicySize != 100 {
			t.Fatalf("PackedPolicySize %d, want 100", tok.PackedPolicySize)
		}
		for _, svc := range []*sts.Service{e.svc, restarted} {
			if sess, err := svc.Validate(ctx, c.AccessKeyID, c.SessionToken); err != nil || sess.Secret != c.Secret {
				t.Fatalf("token over the limit does not open: %v", err)
			}
		}
		keys = append(keys, c.AccessKeyID)
	}
	if keys[0] == keys[1] {
		t.Fatal("credentials reused on a repeated call")
	}
}
