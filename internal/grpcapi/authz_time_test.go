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
