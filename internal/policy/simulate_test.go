package policy_test

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/policy"
)

func named(t *testing.T, id, doc string) policy.Named {
	t.Helper()
	n := must(t, doc)
	n.ID = id
	return n
}

// doc wraps statements in a policy document.
func doc(statements ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`
}

// matched returns "id#index" for each matched statement.
func matched(s policy.Simulation) []string {
	var out []string
	for _, m := range s.Matched {
		out = append(out, m.Policy.ID+"#"+strconv.Itoa(m.Index))
	}
	return out
}

// TestSimulate: every deciding statement is reported, an explicit deny
// lists only the denies, a boundary only narrows, and condition keys the
// request lacks are reported once.
func TestSimulate(t *testing.T) {
	s3 := named(t, "s3", doc(`{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}`,
		`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:vws:s3:::b/*"}`))
	all := named(t, "all", doc(`{"Effect":"Allow","Action":"*","Resource":"*"}`))
	deny := named(t, "deny", doc(`{"Effect":"Allow","Action":"ec2:*","Resource":"*"}`,
		`{"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}`))
	mfa := named(t, "mfa", doc(`{"Effect":"Allow","Action":"s3:PutObject","Resource":"*","Condition":{`+
		`"Bool":{"aws:MultiFactorAuthPresent":"true"},"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}}`))
	iamOnly := named(t, "boundary", doc(`{"Effect":"Allow","Action":"iam:*","Resource":"*"}`))
	denyIAM := named(t, "boundary", doc(`{"Effect":"Allow","Action":"*","Resource":"*"}`,
		`{"Effect":"Deny","Action":"iam:DeleteUser","Resource":"*"}`))
	insecure := map[string][]string{"aws:SecureTransport": {"false"}}
	prefix := named(t, "prefix", doc(`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*",`+
		`"Condition":{"StringLike":{"s3:prefix":["home/${aws:username}/*","${aws:PrincipalTag/team}/*","pub${*}"]}}}`))
	home := named(t, "home", doc(`{"Effect":"Allow","Action":"s3:GetObject",`+
		`"Resource":"arn:vws:s3:::home/${aws:username}/${aws:userid}/*"}`))
	literal := named(t, "literal", `{"Statement":{"Effect":"Allow","Action":"s3:GetObject",`+
		`"Resource":"arn:vws:s3:::home/${aws:username}/*"}}`)
	prefixCtx := map[string][]string{"s3:prefix": {"home/bob/k"}}
	userCtx := map[string][]string{"aws:username": {"bob"}}

	const (
		allowed  = policy.DecisionAllowed
		explicit = policy.DecisionExplicitDeny
		implicit = policy.DecisionImplicitDeny
	)
	ns := func(n ...policy.Named) []policy.Named { return n }
	strs := func(s ...string) []string { return s }
	get, put := req("s3:GetObject", "*", nil), req("s3:GetObject", "*", insecure)
	ipCtx := map[string][]string{"AWS:SOURCEIP": {"192.0.2.1"}}
	getUser, delUser := req("iam:GetUser", "*", nil), req("iam:DeleteUser", "*", nil)
	cases := []struct {
		name         string
		r            policy.Request
		ids, bound   []policy.Named
		decision     string
		matched      []string
		missing      []string
		boundary, by bool
	}{
		{"no policy", get, nil, nil, implicit, nil, nil, false, false},
		{
			"every allow", req("s3:GetObject", "arn:vws:s3:::b/k", nil), ns(s3, all), nil,
			allowed, strs("s3#0", "s3#1", "all#0"), nil, false, false,
		},
		{
			"resource narrows allows", req("s3:GetObject", "arn:vws:s3:::c/k", nil), ns(s3), nil,
			allowed, strs("s3#0"), nil, false, false,
		},
		{"deny lists only denies", put, ns(all, deny), nil, explicit, strs("deny#1"), nil, false, false},
		{
			"condition key missing", get, ns(all, deny), nil,
			allowed, strs("all#0"), strs("aws:SecureTransport"), false, false,
		},
		{
			"every missing key once", req("s3:PutObject", "*", ipCtx), ns(mfa, mfa), nil,
			implicit, nil, strs("aws:MultiFactorAuthPresent"), false, false,
		},
		{
			"missing keys sorted", req("s3:PutObject", "*", nil), ns(mfa), nil,
			implicit, nil, strs("aws:MultiFactorAuthPresent", "aws:SourceIp"), false, false,
		},
		{
			"unrelated action reports no key", req("ec2:RunInstances", "*", nil), ns(deny), nil,
			allowed, strs("deny#0"), nil, false, false,
		},
		{
			"condition variables missing", req("s3:ListBucket", "*", prefixCtx), ns(prefix), nil,
			implicit, nil, strs("aws:PrincipalTag/team", "aws:username"), false, false,
		},
		{
			"resource variables missing", req("s3:GetObject", "arn:vws:s3:::home/bob/AIDA1/k", nil), ns(home), nil,
			implicit, nil, strs("aws:userid", "aws:username"), false, false,
		},
		{
			"resource variable given", req("s3:GetObject", "arn:vws:s3:::home/bob/AIDA1/k", userCtx), ns(home), nil,
			implicit, nil, strs("aws:userid"), false, false,
		},
		{
			"resource variables of another resource", req("s3:GetObject", "arn:vws:s3:::logs/k", nil), ns(home), nil,
			implicit, nil, nil, false, false,
		},
		{
			"no variables before 2012-10-17", req("s3:GetObject", "arn:vws:s3:::home/x/k", nil), ns(literal), nil,
			implicit, nil, nil, false, false,
		},
		{"boundary narrows", get, ns(all), ns(iamOnly), implicit, nil, nil, true, false},
		{"boundary allows", getUser, ns(all), ns(iamOnly), allowed, strs("all#0"), nil, true, true},
		{"boundary alone allows nothing", getUser, nil, ns(iamOnly), implicit, nil, nil, true, true},
		{"boundary deny", delUser, ns(all), ns(denyIAM), explicit, strs("boundary#1"), nil, true, false},
		{"empty boundary set denies", getUser, ns(all), []policy.Named{}, implicit, nil, nil, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := policy.Simulate(c.r, c.ids, c.bound)
			if s.Decision != c.decision {
				t.Errorf("decision %s, want %s", s.Decision, c.decision)
			}
			if got := matched(s); !slices.Equal(got, c.matched) {
				t.Errorf("matched %q, want %q", got, c.matched)
			}
			if !slices.Equal(s.Missing, c.missing) {
				t.Errorf("missing %q, want %q", s.Missing, c.missing)
			}
			if s.Boundary != c.boundary || s.AllowedByBoundary != c.by {
				t.Errorf("boundary %v allowed %v, want %v %v",
					s.Boundary, s.AllowedByBoundary, c.boundary, c.by)
			}
			e := policy.Evaluate(c.r, c.ids, nil)
			if c.bound == nil && e.Allowed != (s.Decision == policy.DecisionAllowed) {
				t.Errorf("Evaluate allowed %v disagrees with %s", e.Allowed, s.Decision)
			}
		})
	}
}
