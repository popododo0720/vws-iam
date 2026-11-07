package sts_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
)

const timeTrustAllow = `{"Effect":"Allow","Principal":{"AWS":"arn:vws:iam::` + acct +
	`:user/alice"},"Action":"sts:AssumeRole"}`

func timeTrustDeny(op, key, value string) string {
	return `,{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole",` +
		`"Condition":{"` + op + `":{"` + key + `":"` + value + `"}}}`
}

func setAdminTrust(t *testing.T, e env, statements string) {
	t.Helper()
	if _, err := store.Mutate(context.Background(), e.b, "admin", func(r *iam.Role) error {
		r.AssumeRolePolicy = `{"Version":"2012-10-17","Statement":[` + statements + `]}`
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func checkAssume(t *testing.T, e env, name string, reqCtx map[string][]string, want error) {
	t.Helper()
	// Twice: the answer is the same on a repeat.
	for range 2 {
		_, err := e.svc.AssumeRole(context.Background(), e.caller(t, "alice"), reqCtx, adminARN, "t1", 0,
			sts.SessionPolicies{}, sts.MFA{})
		if (want == nil && err != nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("%s: %v, want %v", name, err, want)
			return
		}
	}
}

// TestAssumeRoleTrustTime: the trust policy of AssumeRole sees
// aws:CurrentTime and aws:EpochTime from the service clock, as in AWS, so
// an Allow plus a Deny conditioned on the time denies when the time
// matches and allows when it does not.
func TestAssumeRoleTrustTime(t *testing.T) {
	e := setup(t)
	now := e.clk.now().UTC()
	before := now.Add(-time.Hour).Format(time.RFC3339)
	after := now.Add(time.Hour).Format(time.RFC3339)
	epochBefore := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	epochAfter := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	for _, tc := range []struct {
		name, deny string
		want       error
	}{
		{"DateGreaterThan matches", timeTrustDeny("DateGreaterThan", "aws:CurrentTime", before), sts.ErrAccessDenied},
		{"DateGreaterThan does not match", timeTrustDeny("DateGreaterThan", "aws:CurrentTime", after), nil},
		{"DateLessThan matches", timeTrustDeny("DateLessThan", "aws:CurrentTime", after), sts.ErrAccessDenied},
		{"DateLessThan does not match", timeTrustDeny("DateLessThan", "aws:CurrentTime", before), nil},
		{"lower-case key", timeTrustDeny("DateGreaterThan", "aws:currenttime", before), sts.ErrAccessDenied},
		{"EpochTime matches", timeTrustDeny("NumericGreaterThan", "aws:EpochTime", epochBefore), sts.ErrAccessDenied},
		{"EpochTime does not match", timeTrustDeny("NumericGreaterThan", "aws:EpochTime", epochAfter), nil},
		{"EpochTime as a date", timeTrustDeny("DateLessThan", "aws:EpochTime", after), sts.ErrAccessDenied},
	} {
		setAdminTrust(t, e, timeTrustAllow+tc.deny)
		checkAssume(t, e, tc.name, nil, tc.want)
	}
	// The clock moves on: a Deny after a cutoff starts to match.
	setAdminTrust(t, e, timeTrustAllow+timeTrustDeny("DateGreaterThan", "aws:CurrentTime", after))
	checkAssume(t, e, "before the cutoff", nil, nil)
	e.clk.t = e.clk.t.Add(2 * time.Hour)
	checkAssume(t, e, "after the cutoff", nil, sts.ErrAccessDenied)
}

// TestAssumeRoleTrustTimeIgnoresClient: a client copy of aws:CurrentTime
// or aws:EpochTime, in any letter case, never reaches the trust policy, so
// it can neither escape a time Deny nor trigger one.
func TestAssumeRoleTrustTimeIgnoresClient(t *testing.T) {
	e := setup(t)
	now := e.clk.now().UTC()
	before := now.Add(-time.Hour).Format(time.RFC3339)
	after := now.Add(time.Hour).Format(time.RFC3339)
	epochBefore := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	epochAfter := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	escape := []map[string][]string{
		{"aws:CurrentTime": {"2000-01-01T00:00:00Z"}, "aws:EpochTime": {"946684800"}},
		{"AWS:CURRENTTIME": {"2000-01-01T00:00:00Z"}, "aws:epochtime": {"946684800"}},
		{"aws:CurrentTime": {"2000-01-01T00:00:00Z", "2001-01-01T00:00:00Z"}},
		{"aws:EpochTime": {"not a number"}, "aws:currentTime": {""}},
	}
	setAdminTrust(t, e, timeTrustAllow+timeTrustDeny("DateGreaterThan", "aws:CurrentTime", before))
	for i, reqCtx := range escape {
		checkAssume(t, e, "escape CurrentTime deny "+strconv.Itoa(i), reqCtx, sts.ErrAccessDenied)
	}
	setAdminTrust(t, e, timeTrustAllow+timeTrustDeny("NumericGreaterThan", "aws:EpochTime", epochBefore))
	for i, reqCtx := range escape {
		checkAssume(t, e, "escape EpochTime deny "+strconv.Itoa(i), reqCtx, sts.ErrAccessDenied)
	}
	trigger := []map[string][]string{
		{"aws:CurrentTime": {"2100-01-01T00:00:00Z"}, "aws:EpochTime": {"4102444800"}},
		{"Aws:CurrentTime": {"2100-01-01T00:00:00Z"}, "AWS:EPOCHTIME": {"4102444800"}},
	}
	setAdminTrust(t, e, timeTrustAllow+timeTrustDeny("DateGreaterThan", "aws:CurrentTime", after))
	for i, reqCtx := range trigger {
		checkAssume(t, e, "trigger CurrentTime deny "+strconv.Itoa(i), reqCtx, nil)
	}
	setAdminTrust(t, e, timeTrustAllow+timeTrustDeny("NumericGreaterThan", "aws:EpochTime", epochAfter))
	for i, reqCtx := range trigger {
		checkAssume(t, e, "trigger EpochTime deny "+strconv.Itoa(i), reqCtx, nil)
	}
}
