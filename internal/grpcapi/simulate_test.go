package grpcapi_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

const (
	simAllow = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":%q,"Resource":"*"}}`
	simARN   = "arn:vws:iam::" + proj + ":"
)

func simDoc(action string) string { return fmt.Sprintf(simAllow, action) }

// seedSim stores, in project proj: managed policy S3Read (s3:Get*), group
// devs (inline ec2 allow) with member alice, user alice (S3Read attached,
// inline deny of s3:DeleteObject) and role /svc/app (S3Read attached).
func seedSim(t *testing.T, b store.Backend, mutate func(u *iam.User)) {
	t.Helper()
	ctx, sb := t.Context(), store.Scoped(b, proj)
	now := time.Now().UTC()
	s3Read := []string{simARN + "policy/S3Read"}
	pol := iam.Policy{
		Meta: iam.Meta{UID: iam.NewUID()}, Name: "S3Read", ID: "ANPA1", Created: now, DefaultVersion: "v1",
		Versions: []iam.PolicyVersion{{ID: "v1", Document: simDoc("s3:Get*"), Created: now}},
	}
	noDelete := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}}`
	u := iam.User{
		Meta: iam.Meta{UID: iam.NewUID()}, Name: "alice", ID: "AIDA1", Created: now,
		AttachedPolicies: s3Read, InlinePolicies: map[string]string{"nodelete": noDelete},
	}
	g := iam.Group{
		Meta: iam.Meta{UID: iam.NewUID()}, Name: "devs", ID: "AGPA1", Created: now,
		Members: []string{"alice"}, InlinePolicies: map[string]string{"ec2": simDoc("ec2:*")},
	}
	role := iam.Role{
		Meta: iam.Meta{UID: iam.NewUID()}, Name: "app", Path: "/svc/", ID: "AROA1", Created: now,
		AssumeRolePolicy: slrTrust, AttachedPolicies: s3Read,
	}
	if mutate != nil {
		mutate(&u)
	}
	objs := []func() error{
		func() error { _, err := store.Create(ctx, sb, pol); return err },
		func() error { _, err := store.Create(ctx, sb, u); return err },
		func() error { _, err := store.Create(ctx, sb, g); return err },
		func() error { _, err := store.Create(ctx, sb, role); return err },
	}
	for _, f := range objs {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
}

// summary is "action resource decision [type:id ...]" for each result.
func summary(p grpcapi.SimulationPage) []string {
	var out []string
	for _, r := range p.Results {
		var ms []string
		for _, m := range r.MatchedStatements {
			ms = append(ms, m.SourcePolicyType+":"+m.SourcePolicyID)
		}
		out = append(out, fmt.Sprintf("%s %s %s %v", r.ActionName, r.ResourceName, r.Decision, ms))
	}
	return out
}

func simulate(t *testing.T, e *env, in grpcapi.SimulateInput) grpcapi.SimulationPage {
	t.Helper()
	p, err := e.api.SimulatePrincipalPolicy(t.Context(), proj, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSimulatePrincipalPolicy: a user's own, attached, group and input
// policies decide; a group and a role (with path) are sources too; on
// both store backends.
func TestSimulatePrincipalPolicy(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedSim(t, b, nil)
			got := summary(simulate(t, e, grpcapi.SimulateInput{
				PolicySourceARN: simARN + "user/alice",
				ActionNames: []string{
					"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "ec2:RunInstances", "iam:CreateUser",
				},
				PolicyInputList: []string{simDoc("s3:*")},
			}))
			want := []string{
				"s3:GetObject * allowed [user-managed:S3Read none:PolicyInputList.1]",
				"s3:PutObject * allowed [none:PolicyInputList.1]",
				"s3:DeleteObject * explicitDeny [user:user_alice_nodelete]",
				"ec2:RunInstances * allowed [group:group_devs_ec2]",
				"iam:CreateUser * implicitDeny []",
			}
			if !slices.Equal(got, want) {
				t.Fatalf("user results\n%q\nwant\n%q", got, want)
			}
			got = summary(simulate(t, e, grpcapi.SimulateInput{
				PolicySourceARN: simARN + "group/DEVS", ActionNames: []string{"ec2:RunInstances", "s3:GetObject"},
			}))
			want = []string{"ec2:RunInstances * allowed [group:group_devs_ec2]", "s3:GetObject * implicitDeny []"}
			if !slices.Equal(got, want) {
				t.Fatalf("group results %q, want %q", got, want)
			}
			got = summary(simulate(t, e, grpcapi.SimulateInput{
				PolicySourceARN: simARN + "role/svc/app", ActionNames: []string{"s3:GetObject", "ec2:RunInstances"},
			}))
			want = []string{"s3:GetObject * allowed [user-managed:S3Read]", "ec2:RunInstances * implicitDeny []"}
			if !slices.Equal(got, want) {
				t.Fatalf("role results %q, want %q", got, want)
			}
		})
	}
}

// TestSimulatePrincipalPolicyBoundary: the stored boundary of the source
// narrows it, and an input boundary replaces the stored one.
func TestSimulatePrincipalPolicyBoundary(t *testing.T) {
	b := fakeKube()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedSim(t, b, func(u *iam.User) { u.PermissionsBoundary = simARN + "policy/S3Read" })
	in := grpcapi.SimulateInput{
		PolicySourceARN: simARN + "user/alice", ActionNames: []string{"s3:GetObject", "ec2:RunInstances"},
	}
	p := simulate(t, e, in)
	want := []string{"s3:GetObject * allowed [user-managed:S3Read]", "ec2:RunInstances * implicitDeny []"}
	if got := summary(p); !slices.Equal(got, want) {
		t.Fatalf("stored boundary: %q, want %q", got, want)
	}
	for i, want := range []bool{true, false} {
		if a := p.Results[i].AllowedByPermissionsBoundary; a == nil || *a != want {
			t.Fatalf("result %d AllowedByPermissionsBoundary %v, want %v", i, a, want)
		}
	}
	in.PermissionsBoundaryInp = []string{simDoc("ec2:*")}
	p = simulate(t, e, in)
	want = []string{"s3:GetObject * implicitDeny []", "ec2:RunInstances * allowed [group:group_devs_ec2]"}
	if got := summary(p); !slices.Equal(got, want) {
		t.Fatalf("input boundary: %q, want %q", got, want)
	}
	in.PolicySourceARN = simARN + "group/devs"
	in.PermissionsBoundaryInp = nil
	if p := simulate(t, e, in); p.Results[0].AllowedByPermissionsBoundary != nil {
		t.Fatal("a group has no boundary, want AllowedByPermissionsBoundary unset")
	}
}

// TestSimulatePrincipalPolicyContext: condition keys come only from
// ContextEntries, a missing one is reported, and with ResourceArns the
// result for each resource is repeated as its resource-specific result.
func TestSimulatePrincipalPolicyContext(t *testing.T) {
	b := fakeKube()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ipOnly := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*",` +
		`"Condition":{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"},"Bool":{"aws:SecureTransport":"true"}}}}`
	seedSim(t, b, func(u *iam.User) { u.InlinePolicies["ip"] = ipOnly })
	in := grpcapi.SimulateInput{PolicySourceARN: simARN + "user/alice", ActionNames: []string{"sqs:SendMessage"}}
	p := simulate(t, e, in)
	r := p.Results[0]
	missing := []string{"aws:securetransport", "aws:sourceip"}
	if r.Decision != "implicitDeny" || !slices.Equal(r.MissingContextValues, missing) || r.ResourceSpecific != nil {
		t.Fatalf("no context: %+v", r)
	}
	in.ContextEntries = []grpcapi.ContextEntry{
		{Key: "aws:SourceIp", Type: "ip", Values: []string{"192.0.2.10"}},
		{Key: "aws:SecureTransport", Type: "boolean", Values: []string{"true"}},
	}
	in.ResourceARNs = []string{"arn:vws:sqs:kr-central-1:" + proj + ":q"}
	r = simulate(t, e, in).Results[0]
	if r.Decision != "allowed" || len(r.MissingContextValues) != 0 ||
		len(r.ResourceSpecific) != 1 || r.ResourceSpecific[0].Decision != "allowed" {
		t.Fatalf("with context: %+v", r)
	}
	in.ContextEntries = in.ContextEntries[:1]
	r = simulate(t, e, in).Results[0]
	if r.MissingContextValues != nil ||
		!slices.Equal(r.ResourceSpecific[0].MissingContextValues, []string{"aws:securetransport"}) {
		t.Fatalf("missing key of a listed resource: %+v, want it only in the resource-specific result", r)
	}
}

// TestSimulatePrincipalPolicyPages: every action is evaluated for every
// resource, in that order, and pages continue where the last ended.
func TestSimulatePrincipalPolicyPages(t *testing.T) {
	b := fakeKube()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedSim(t, b, nil)
	in := grpcapi.SimulateInput{
		PolicySourceARN: simARN + "user/alice",
		ActionNames:     []string{"s3:GetObject", "s3:DeleteObject", "iam:GetUser"},
		ResourceARNs:    []string{"arn:vws:s3:::a", "arn:vws:s3:::b"},
		MaxItems:        4,
	}
	var got []string
	pages := 0
	for {
		p := simulate(t, e, in)
		pages++
		for _, r := range p.Results {
			got = append(got, r.ActionName+" "+r.ResourceName)
		}
		if !p.IsTruncated {
			if p.Marker != "" {
				t.Fatal("marker on the last page")
			}
			break
		}
		in.Marker = p.Marker
	}
	want := []string{
		"s3:GetObject arn:vws:s3:::a", "s3:GetObject arn:vws:s3:::b",
		"s3:DeleteObject arn:vws:s3:::a", "s3:DeleteObject arn:vws:s3:::b",
		"iam:GetUser arn:vws:s3:::a", "iam:GetUser arn:vws:s3:::b",
	}
	if pages != 2 || !slices.Equal(got, want) {
		t.Fatalf("%d pages %q, want 2 pages %q", pages, got, want)
	}
	in.Marker, in.MaxItems = "", 0
	if p := simulate(t, e, in); len(p.Results) != 6 || p.IsTruncated {
		t.Fatalf("default page: %d results truncated %v, want all 6", len(p.Results), p.IsTruncated)
	}
}

// TestSimulatePrincipalPolicyErrors: every bad input is refused with the
// AWS error before any store access, an unknown entity is NoSuchEntity,
// and a stored policy that cannot be parsed is PolicyEvaluation.
func TestSimulatePrincipalPolicyErrors(t *testing.T) {
	b := fakeKube()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedSim(t, b, nil)
	type in = grpcapi.SimulateInput
	const (
		bad, missing = codes.InvalidArgument, codes.NotFound
		vErr, iErr   = "ValidationError", "InvalidInput"
	)
	ok := func(f func(*in)) in {
		i := in{PolicySourceARN: simARN + "user/alice", ActionNames: []string{"s3:GetObject"}}
		f(&i)
		return i
	}
	src := func(arn string) in { return ok(func(i *in) { i.PolicySourceARN = arn }) }
	acts := func(a ...string) in { return ok(func(i *in) { i.ActionNames = a }) }
	res := func(r ...string) in { return ok(func(i *in) { i.ResourceARNs = r }) }
	pols := func(p ...string) in { return ok(func(i *in) { i.PolicyInputList = p }) }
	bounds := func(p ...string) in { return ok(func(i *in) { i.PermissionsBoundaryInp = p }) }
	caller := func(arn string) in { return ok(func(i *in) { i.CallerARN = arn }) }
	maxItems := func(n int) in { return ok(func(i *in) { i.MaxItems = n }) }
	marker := func(m string) in { return ok(func(i *in) { i.Marker = m }) }
	ctxs := func(es ...grpcapi.ContextEntry) in { return ok(func(i *in) { i.ContextEntries = es }) }
	entry := func(k, typ string, v ...string) in { return ctxs(grpcapi.ContextEntry{Key: k, Type: typ, Values: v}) }
	long := strings.Repeat("a", 2048)
	principal := `{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`
	cases := []struct {
		name string
		pid  string
		in   in
		code codes.Code
		aws  string
	}{
		{"bad project", "Bad Project", ok(func(*in) {}), bad, vErr},
		{"short source", proj, src("arn:vws:iam::x:u"), bad, vErr},
		{"long source", proj, src(simARN + "user/" + long), bad, vErr},
		{"no actions", proj, acts(), bad, vErr},
		{"short action", proj, acts("s:"), bad, vErr},
		{"long action", proj, acts("s3:" + strings.Repeat("a", 126)), bad, vErr},
		{"action without service", proj, acts("GetObject"), bad, iErr},
		{"empty resource", proj, res(""), bad, vErr},
		{"long resource", proj, res(long + "r"), bad, vErr},
		{"malformed input policy", proj, pols("{"), bad, iErr},
		{"empty input policy", proj, pols(""), bad, vErr},
		{"input policy outside pattern", proj, pols(simDoc("s3:\u0100")), bad, vErr},
		{"input policy with principal", proj, pols(principal), bad, iErr},
		{"two boundaries", proj, bounds(simDoc("*"), simDoc("*")), bad, iErr},
		{"malformed boundary", proj, bounds("[]"), bad, iErr},
		{"caller is a session", proj, caller("arn:vws:sts::" + proj + ":assumed-role/app/s"), bad, iErr},
		{"caller too long", proj, caller(simARN + "user/" + long), bad, vErr},
		{"short context key", proj, entry("aws:", "string", "v"), bad, vErr},
		{"unknown context type", proj, entry("aws:SourceIp", "cidr", "192.0.2.1"), bad, vErr},
		{"two values for a single type", proj, entry("aws:username", "string", "a", "b"), bad, iErr},
		{"not an ip", proj, entry("aws:SourceIp", "ip", "192.0.2"), bad, iErr},
		{"not a number", proj, entry("s3:max-keys", "numericList", "1", "x"), bad, iErr},
		{"not a boolean", proj, entry("aws:SecureTransport", "boolean", "yes"), bad, iErr},
		{"not a date", proj, entry("aws:CurrentTime", "date", "tomorrow"), bad, iErr},
		{"not binary", proj, entry("aws:binaryKey", "binary", "!!"), bad, iErr},
		{"duplicate context key", proj, ctxs(
			grpcapi.ContextEntry{Key: "aws:username", Type: "string", Values: []string{"a"}},
			grpcapi.ContextEntry{Key: "AWS:UserName", Type: "string", Values: []string{"b"}},
		), bad, iErr},
		{"max items 0 is default, 1001 is not", proj, maxItems(1001), bad, vErr},
		{"negative max items", proj, maxItems(-1), bad, vErr},
		{"marker outside pattern", proj, marker("\x01"), bad, vErr},
		{"marker not issued", proj, marker("MQ"), bad, iErr}, // offset 1 of 1 result
		{"marker garbage", proj, marker("not a marker"), bad, iErr},
		{"source not an identity", proj, src(simARN + "policy/S3Read"), bad, iErr},
		{"source of another account", proj, src("arn:vws:iam::other:user/alice"), missing, "NoSuchEntity"},
		{"unknown user", proj, src(simARN + "user/bob"), missing, "NoSuchEntity"},
		{"unknown group", proj, src(simARN + "group/ops"), missing, "NoSuchEntity"},
		{"unknown role", proj, src(simARN + "role/app"), missing, "NoSuchEntity"}, // path is /svc/
		{"user path differs", proj, src(simARN + "user/x/alice"), missing, "NoSuchEntity"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.api.SimulatePrincipalPolicy(t.Context(), c.pid, c.in)
			wantAWS(t, err, c.code, c.aws)
		})
	}

	breakAlice := func(u *iam.User) error {
		u.InlinePolicies["broken"] = "{not json"
		return nil
	}
	if _, err := store.Mutate(t.Context(), store.Scoped(b, proj), "alice", breakAlice); err != nil {
		t.Fatal(err)
	}
	_, err := e.api.SimulatePrincipalPolicy(t.Context(), proj, ok(func(*in) {}))
	wantAWS(t, err, codes.Internal, "PolicyEvaluation")
	if strings.Contains(err.Error(), "not json") {
		t.Fatalf("PolicyEvaluation %q echoes the stored document", err)
	}
}
