package authz_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestAuthorizeTimeKeys: identity policies see aws:CurrentTime and
// aws:EpochTime from the service clock (#203), so an Allow plus a Deny
// after a cutoff allows before it and denies after it, and a client copy
// of either key, in any letter case, can neither escape the Deny nor
// trigger it early.
func TestAuthorizeTimeKeys(t *testing.T) {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	cutoff := now.Add(time.Hour)
	for _, tc := range []struct{ name, cond string }{
		{"CurrentTime", `{"DateGreaterThan":{"aws:CurrentTime":"` + cutoff.Format(time.RFC3339) + `"}}`},
		{"EpochTime", `{"NumericGreaterThan":{"aws:EpochTime":"` + strconv.FormatInt(cutoff.Unix(), 10) + `"}}`},
		{"EpochTime as a date", `{"DateGreaterThan":{"aws:EpochTime":"` + cutoff.Format(time.RFC3339) + `"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := memstore.New()
			doc := `{"Version":"2012-10-17","Statement":[` +
				`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},` +
				`{"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":` + tc.cond + `}]}`
			put(t, b, iam.User{Name: "alice", ID: "1", InlinePolicies: map[string]string{"s3": doc}})
			clk := now
			a := authz.New(b, acct, func() time.Time { return clk })
			alice := authz.Principal{Kind: authz.User, Name: "alice", ID: "1"}
			check := func(name string, rc map[string][]string, want bool) {
				t.Helper()
				for range 2 {
					d, err := a.Authorize(context.Background(), alice, "s3:GetObject", "*", rc)
					if err != nil || d.Allowed != want {
						t.Fatalf("%s: %+v %v, want allowed %v", name, d, err, want)
					}
				}
			}
			check("before the cutoff", nil, true)
			check("client copy before the cutoff", map[string][]string{
				"aws:CurrentTime": {"2100-01-01T00:00:00Z"}, "AWS:EPOCHTIME": {"4102444800"},
			}, true)
			clk = now.Add(2 * time.Hour)
			check("after the cutoff", nil, false)
			check("client copy after the cutoff", map[string][]string{
				"aws:currenttime": {"2000-01-01T00:00:00Z"}, "aws:epochtime": {"946684800"},
			}, false)
			check("unparsable client copy after the cutoff", map[string][]string{
				"aws:EpochTime": {"not a number"}, "Aws:CurrentTime": {""},
			}, false)
		})
	}
}
