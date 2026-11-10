package grpcapi_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
)

func simulateCustom(t *testing.T, e *env, in grpcapi.CustomSimulateInput) grpcapi.SimulationPage {
	t.Helper()
	p, err := e.api.SimulateCustomPolicy(t.Context(), proj, in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSimulateCustomPolicy: only the input policies decide, by
// PolicyInputList.N, even with CallerArn naming a stored user with its own
// policies; a deny wins; on both store backends.
func TestSimulateCustomPolicy(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedSim(t, b, nil) // alice: S3Read attached, s3:DeleteObject denied, group devs allows ec2:*
			noPut := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:PutObject","Resource":"*"}}`
			in := grpcapi.CustomSimulateInput{
				PolicyInputList: []string{simDoc("s3:*"), noPut},
				ActionNames:     []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "ec2:RunInstances"},
				CallerARN:       simARN + "user/alice",
			}
			want := []string{
				"s3:GetObject arn:vws:s3:::${BucketName}/${ObjectName} allowed [none:PolicyInputList.1]",
				"s3:PutObject arn:vws:s3:::${BucketName}/${ObjectName} explicitDeny [none:PolicyInputList.2]",
				"s3:DeleteObject arn:vws:s3:::${BucketName}/${ObjectName} allowed [none:PolicyInputList.1]",
				"ec2:RunInstances * implicitDeny []",
			}
			p := simulateCustom(t, e, in)
			if got := summary(p); !slices.Equal(got, want) || p.IsTruncated {
				t.Fatalf("results %q truncated %v, want %q", got, p.IsTruncated, want)
			}
			if p.Results[0].AllowedByPermissionsBoundary != nil || p.Results[0].ResourceSpecific != nil {
				t.Fatalf("no boundary and no ResourceArns: %+v", p.Results[0])
			}
			in.CallerARN = ""
			if got := summary(simulateCustom(t, e, in)); !slices.Equal(got, want) {
				t.Fatalf("without CallerArn %q, want %q", got, want)
			}
		})
	}
}

// TestSimulateCustomPolicyBoundaryAndResources: the boundary only narrows
// and is reported per resource and in the aggregate; condition keys come
// only from ContextEntries.
func TestSimulateCustomPolicyBoundaryAndResources(t *testing.T) {
	now := time.Now().UTC()
	e := newEnvOn(t, fakeKube(), &now)
	onlyA := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"arn:vws:s3:::a"}}`
	mfa := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*",` +
		`"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`
	in := grpcapi.CustomSimulateInput{
		PolicyInputList:        []string{simDoc("s3:GetObject"), mfa},
		PermissionsBoundaryInp: []string{onlyA},
		ActionNames:            []string{"s3:GetObject", "s3:ListBucket"},
		ResourceARNs:           []string{"arn:vws:s3:::a", "arn:vws:s3:::b"},
	}
	p := simulateCustom(t, e, in)
	want := []string{
		"s3:GetObject arn:vws:s3:::${BucketName}/${ObjectName} implicitDeny []",
		"s3:ListBucket arn:vws:s3:::${BucketName} implicitDeny []",
	}
	if got := summary(p); !slices.Equal(got, want) {
		t.Fatalf("results %q, want %q", got, want)
	}
	if got, want := resourceSummary(p.Results[0]), []string{
		"arn:vws:s3:::a allowed [none:PolicyInputList.1]", "arn:vws:s3:::b implicitDeny []",
	}; !slices.Equal(got, want) {
		t.Fatalf("resource-specific %q, want %q", got, want)
	}
	if a := p.Results[0].AllowedByPermissionsBoundary; a == nil || *a {
		t.Fatalf("aggregate AllowedByPermissionsBoundary %v, want false", a)
	}
	if a := p.Results[0].ResourceSpecific[0].AllowedByPermissionsBoundary; a == nil || !*a {
		t.Fatalf("resource a AllowedByPermissionsBoundary %v, want true", a)
	}
	if got := p.Results[1].MissingContextValues; !slices.Equal(got, []string{"aws:MultiFactorAuthPresent"}) {
		t.Fatalf("missing context %q, want aws:MultiFactorAuthPresent", got)
	}
	in.ContextEntries = []grpcapi.ContextEntry{
		{Key: "aws:MultiFactorAuthPresent", Type: "boolean", Values: []string{"true"}},
	}
	in.ResourceARNs = []string{"arn:vws:s3:::a"}
	r := simulateCustom(t, e, in).Results[1]
	if r.Decision != "allowed" || len(r.MissingContextValues) != 0 {
		t.Fatalf("with context: %+v, want allowed", r)
	}
}

// TestSimulateCustomPolicyPages: pages hold whole actions and a retried
// page gives the same results.
func TestSimulateCustomPolicyPages(t *testing.T) {
	now := time.Now().UTC()
	e := newEnvOn(t, fakeKube(), &now)
	in := grpcapi.CustomSimulateInput{
		PolicyInputList: []string{simDoc("s3:*")},
		ActionNames:     []string{"s3:GetObject", "iam:GetUser", "s3:PutObject"},
		MaxItems:        2,
	}
	first := simulateCustom(t, e, in)
	if again := simulateCustom(t, e, in); !slices.Equal(summary(first), summary(again)) || first.Marker != again.Marker {
		t.Fatal("a retried page differs")
	}
	in.Marker = first.Marker
	last := simulateCustom(t, e, in)
	got := append(summary(first), summary(last)...)
	want := []string{
		"s3:GetObject arn:vws:s3:::${BucketName}/${ObjectName} allowed [none:PolicyInputList.1]",
		"iam:GetUser arn:vws:iam::${Account}:user/${UserNameWithPath} implicitDeny []",
		"s3:PutObject arn:vws:s3:::${BucketName}/${ObjectName} allowed [none:PolicyInputList.1]",
	}
	if !first.IsTruncated || last.IsTruncated || last.Marker != "" || !slices.Equal(got, want) {
		t.Fatalf("pages %q (truncated %v, %v), want %q", got, first.IsTruncated, last.IsTruncated, want)
	}
}

// TestSimulateCustomPolicyErrors: every bad input is refused with the AWS
// error, and the resource inputs not simulated yet are InvalidInput,
// never ignored.
func TestSimulateCustomPolicyErrors(t *testing.T) {
	now := time.Now().UTC()
	e := newEnvOn(t, fakeKube(), &now)
	type in = grpcapi.CustomSimulateInput
	const vErr, iErr = "ValidationError", "InvalidInput"
	ok := func(f func(*in)) in {
		i := in{PolicyInputList: []string{simDoc("s3:*")}, ActionNames: []string{"s3:GetObject"}}
		f(&i)
		return i
	}
	long := strings.Repeat("a", 2048)
	principal := `{"Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`
	resPolicy := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"*"},` +
		`"Action":"s3:*","Resource":"*"}}`
	cases := []struct {
		name string
		pid  string
		in   in
		aws  string
	}{
		{"bad project", "Bad Project", ok(func(*in) {}), vErr},
		{"no input policy", proj, ok(func(i *in) { i.PolicyInputList = nil }), vErr},
		{"no actions", proj, ok(func(i *in) { i.ActionNames = nil }), vErr},
		{"long action", proj, ok(func(i *in) { i.ActionNames = []string{"s3:" + long[:126]} }), vErr},
		{"action without service", proj, ok(func(i *in) { i.ActionNames = []string{"GetObject"} }), iErr},
		{"empty resource", proj, ok(func(i *in) { i.ResourceARNs = []string{""} }), vErr},
		{"empty input policy", proj, ok(func(i *in) { i.PolicyInputList = []string{""} }), vErr},
		{"input policy outside pattern", proj, ok(func(i *in) { i.PolicyInputList = []string{simDoc("\u0100")} }), vErr},
		{"malformed input policy", proj, ok(func(i *in) { i.PolicyInputList = []string{"{"} }), iErr},
		{"input policy with principal", proj, ok(func(i *in) { i.PolicyInputList = []string{principal} }), iErr},
		{"two boundaries", proj, ok(func(i *in) { i.PermissionsBoundaryInp = []string{simDoc("*"), simDoc("*")} }), iErr},
		{"malformed boundary", proj, ok(func(i *in) { i.PermissionsBoundaryInp = []string{"[]"} }), iErr},
		{"caller is a session", proj, ok(func(i *in) { i.CallerARN = "arn:vws:sts::" + proj + ":assumed-role/a/s" }), iErr},
		{"caller too long", proj, ok(func(i *in) { i.CallerARN = simARN + "user/" + long }), vErr},
		{"context value not of its type", proj, ok(func(i *in) {
			i.ContextEntries = []grpcapi.ContextEntry{{Key: "aws:SourceIp", Type: "ip", Values: []string{"x"}}}
		}), iErr},
		{"max items 1001", proj, ok(func(i *in) { i.MaxItems = 1001 }), vErr},
		{"marker not issued", proj, ok(func(i *in) { i.Marker = "MQ" }), iErr},
		{"resource policy outside pattern", proj, ok(func(i *in) { i.ResourcePolicy = "\x01" }), vErr},
		{"resource policy without caller", proj, ok(func(i *in) { i.ResourcePolicy = resPolicy }), iErr},
		{"resource policy not simulated", proj, ok(func(i *in) {
			i.ResourcePolicy, i.CallerARN = resPolicy, simARN+"user/alice"
		}), iErr},
		{"resource owner too long", proj, ok(func(i *in) { i.ResourceOwner = long + "a" }), vErr},
		{"resource owner not an account", proj, ok(func(i *in) { i.ResourceOwner = simARN + "user/alice" }), iErr},
		{"resource owner of another partition", proj, ok(func(i *in) {
			i.ResourceOwner = "arn:aws:iam::" + proj + ":root"
		}), iErr},
		{"resource owner bad account", proj, ok(func(i *in) { i.ResourceOwner = "arn:vws:iam::Bad:root" }), iErr},
		{"handling option too long", proj, ok(func(i *in) { i.ResourceHandlingOption = long[:65] }), vErr},
		{"handling option not simulated", proj, ok(func(i *in) { i.ResourceHandlingOption = "EC2-VPC-EBS" }), iErr},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.api.SimulateCustomPolicy(t.Context(), c.pid, c.in)
			wantAWS(t, err, codes.InvalidArgument, c.aws)
		})
	}
	owner := ok(func(i *in) { i.ResourceOwner = "arn:vws:iam::" + proj + ":root" })
	if _, err := e.api.SimulateCustomPolicy(t.Context(), proj, owner); err != nil {
		t.Fatalf("an account ResourceOwner was refused: %v", err)
	}
}
