package grpcapi_test

import (
	"strconv"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// TestAuthorizeTimeKeysAreServerOnly: gateway Authorize evaluates
// aws:CurrentTime and aws:EpochTime from the service clock (#203). An
// Allow plus a Deny after a cutoff allows before it and denies after it,
// and a copy of either key in the request context, in any letter case,
// can neither escape the Deny nor trigger it early, on both backends and
// on a second server over the same store.
func TestAuthorizeTimeKeysAreServerOnly(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC().Truncate(time.Second)
			e := newEnvOn(t, b, &now)
			other := newEnvOn(t, b, &now)
			ctx := t.Context()
			cutoff := now.Add(time.Hour)
			epoch := strconv.FormatInt(cutoff.Unix(), 10)
			u := e.keyedUser(t, "carol", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"s3:*","Resource":"*"},
				{"Sid":"AfterDate","Effect":"Deny","Action":"s3:GetObject","Resource":"*",
				 "Condition":{"DateGreaterThan":{"aws:CurrentTime":"`+cutoff.Format(time.RFC3339)+`"}}},
				{"Sid":"AfterEpoch","Effect":"Deny","Action":"s3:PutObject","Resource":"*",
				 "Condition":{"NumericGreaterThan":{"aws:EpochTime":"`+epoch+`"}}}]}`)
			a, err := e.auth.Authenticate(ctx, e.sign(u.id, u.secretKey, ""))
			if err != nil {
				t.Fatal(err)
			}
			pr := a.GetPrincipal()
			check := func(name string, rc map[string][]string, want iamv1.Decision) {
				t.Helper()
				c := map[string]*iamv1.ContextValues{}
				for k, v := range rc {
					c[k] = &iamv1.ContextValues{Values: v}
				}
				for _, srv := range []*env{e, other} {
					for _, action := range []string{"s3:GetObject", "s3:PutObject"} {
						r, err := srv.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: pr, Action: action, Context: c})
						if err != nil || r.GetDecision() != want {
							t.Fatalf("%s %s: %v %v, want %v", name, action, r, err, want)
						}
					}
				}
			}
			check("before the cutoff", nil, iamv1.Decision_DECISION_ALLOW)
			check("client copy before the cutoff", map[string][]string{
				"aws:CurrentTime": {"2100-01-01T00:00:00Z"}, "aws:EpochTime": {"4102444800"},
			}, iamv1.Decision_DECISION_ALLOW)
			check("client copy in another case before the cutoff", map[string][]string{
				"AWS:CURRENTTIME": {"2100-01-01T00:00:00Z"}, "Aws:EpochTime": {"4102444800"},
			}, iamv1.Decision_DECISION_ALLOW)
			*e.now = now.Add(2 * time.Hour)
			check("after the cutoff", nil, iamv1.Decision_DECISION_DENY_EXPLICIT)
			check("client copy after the cutoff", map[string][]string{
				"aws:currenttime": {"2000-01-01T00:00:00Z"}, "aws:epochtime": {"946684800"},
			}, iamv1.Decision_DECISION_DENY_EXPLICIT)
			check("unparsable client copy after the cutoff", map[string][]string{
				"aws:CurrentTime": {"never"}, "AWS:EPOCHTIME": {"not a number"},
			}, iamv1.Decision_DECISION_DENY_EXPLICIT)
		})
	}
}

// TestAuthorizeServerKeysFoldLikePolicyLookup: a request key that a
// policy lookup matches to a server key only under Unicode case folding
// ("awſ:", U+017F; "ſaml:") is dropped, so it never takes the server
// value's place. A policy lookup picks one of two matching keys at random,
// so each case runs many times.
func TestAuthorizeServerKeysFoldLikePolicyLookup(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.keyedUser(t, "dave", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}},
		{"Effect":"Allow","Action":"s3:PutObject","Resource":"*","Condition":{"StringEquals":{"saml:sub":"dave"}}},
		{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*",
		 "Condition":{"NumericLessThan":{"aws:EpochTime":"946684801"}}}]}`)
	a, err := e.auth.Authenticate(ctx, e.sign(u.id, u.secretKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	for action, key := range map[string]string{
		"s3:GetObject":  "awſ:MultiFactorAuthPresent",
		"s3:PutObject":  "ſaml:sub",
		"s3:ListBucket": "awſ:EpochTime",
	} {
		value := map[string]string{"s3:GetObject": "true", "s3:PutObject": "dave", "s3:ListBucket": "946684800"}[action]
		c := map[string]*iamv1.ContextValues{key: {Values: []string{value}}}
		for range 32 {
			r, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{Principal: a.GetPrincipal(), Action: action, Context: c})
			if err != nil || r.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT {
				t.Fatalf("%s with %q: %v %v, want DENY_IMPLICIT", action, key, r, err)
			}
		}
	}
}
