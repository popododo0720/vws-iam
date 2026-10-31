package authz_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const acct = "000000000000"

func put[T iam.Object](t *testing.T, b store.Backend, o T) {
	if _, err := store.Create(context.Background(), b, o); err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) store.Backend {
	b := memstore.New()
	put(t, b, iam.Policy{Name: "S3Read", ID: "1", DefaultVersion: "v2", Versions: []iam.PolicyVersion{
		{ID: "v1", Document: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`},
		{ID: "v2", Document: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":["s3:Get*","s3:List*"],"Resource":"*"}}`},
	}})
	put(t, b, iam.Group{Name: "devs", ID: "2", Members: []string{"Alice"}, InlinePolicies: map[string]string{"ec2": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*"}}`}})
	put(t, b, iam.Group{Name: "nofleet", ID: "3", Members: []string{"alice"}, InlinePolicies: map[string]string{"deny": `{"Version":"2012-10-17","Statement":{"Sid":"NoTerminate","Effect":"Deny","Action":"ec2:TerminateInstances","Resource":"*"}}`}})
	put(t, b, iam.User{Name: "alice", ID: "4", AttachedPolicies: []string{"arn:vws:iam::" + acct + ":policy/S3Read"}})
	put(t, b, iam.Role{Name: "reader", ID: "5", AssumeRolePolicy: `{}`, AttachedPolicies: []string{"arn:vws:iam::" + acct + ":policy/S3Read"}})
	return b
}

func TestAuthorizeCombinesUserAndGroups(t *testing.T) {
	a := authz.New(setup(t), acct, func() time.Time { return time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC) })
	ctx := context.Background()
	alice := authz.Principal{Kind: authz.User, Name: "alice"}
	for _, c := range []struct {
		action string
		ok     bool
	}{
		{"s3:GetObject", true},            // managed policy, default version only
		{"s3:PutObject", false},           // v1 allowed *, but v2 is default
		{"ec2:RunInstances", true},        // group inline
		{"ec2:TerminateInstances", false}, // other group's explicit deny
		{"iam:CreateUser", false},         // implicit deny
	} {
		d, err := a.Authorize(ctx, alice, c.action, "arn:vws:s3:::b/k", nil)
		if err != nil || d.Allowed != c.ok {
			t.Errorf("%s: %+v %v, want %v", c.action, d, err, c.ok)
		}
	}
	if d, err := a.Authorize(ctx, authz.Principal{Kind: authz.Root}, "iam:DeleteUser", "*", nil); err != nil || !d.Allowed {
		t.Fatalf("root: %+v %v", d, err)
	}
	d, err := a.Authorize(ctx, alice, "ec2:TerminateInstances", "*", nil)
	if err != nil || d.Reason != "explicit deny in arn:vws:iam::"+acct+":group/nofleet:inline/deny/NoTerminate" || d.Policy != "arn:vws:iam::"+acct+":group/nofleet:inline/deny" || d.Statement != "NoTerminate" || !d.Explicit {
		t.Fatalf("reason %q %v", d.Reason, err)
	}
}

func TestAuthorizeRoleAndSessionPolicy(t *testing.T) {
	a := authz.New(setup(t), acct, nil)
	ctx := context.Background()
	p := authz.Principal{Kind: authz.Role, Name: "reader", ARN: "arn:vws:sts::" + acct + ":assumed-role/reader/s1"}
	if d, err := a.Authorize(ctx, p, "s3:ListBucket", "arn:vws:s3:::b", nil); err != nil || !d.Allowed {
		t.Fatalf("%+v %v", d, err)
	}
	p.SessionPolicies = []string{`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`}
	if d, err := a.Authorize(ctx, p, "s3:ListBucket", "arn:vws:s3:::b", nil); err != nil || d.Allowed {
		t.Fatalf("session policy did not narrow: %+v %v", d, err)
	}
}

func TestAuthorizeFailsClosed(t *testing.T) {
	b := setup(t)
	a := authz.New(b, acct, nil)
	ctx := context.Background()
	if _, err := a.Authorize(ctx, authz.Principal{Kind: authz.User, Name: "nobody"}, "s3:GetObject", "*", nil); !errors.Is(err, authz.ErrNoSuchEntity) {
		t.Fatalf("unknown user: %v", err)
	}
	put(t, b, iam.User{Name: "mallory", ID: "9", InlinePolicies: map[string]string{"bad": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*"}}`}})
	if _, err := a.Authorize(ctx, authz.Principal{Kind: authz.User, Name: "mallory"}, "s3:GetObject", "*", nil); !errors.Is(err, policy.ErrMalformed) {
		t.Fatalf("malformed stored policy: %v", err)
	}
	put(t, b, iam.User{Name: "trent", ID: "10", AttachedPolicies: []string{"arn:vws:iam::999999999999:policy/S3Read"}})
	if _, err := a.Authorize(ctx, authz.Principal{Kind: authz.User, Name: "trent"}, "s3:GetObject", "*", nil); !errors.Is(err, authz.ErrNoSuchEntity) {
		t.Fatalf("foreign-account policy: %v", err)
	}
}

// TestAuthorizeInlineOverMaxSize checks that a stored inline policy over
// policy.MaxSize, which the write path accepts under the aggregate quota,
// still authorizes for a user, a group member and a role.
func TestAuthorizeInlineOverMaxSize(t *testing.T) {
	b := setup(t)
	a := authz.New(b, acct, nil)
	ctx := context.Background()
	big := strings.Replace(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*"}}`,
		"{", "{"+strings.Repeat(" \n\t", policy.MaxSize/3+1), 1)
	if len(big) <= policy.MaxSize {
		t.Fatalf("document is %d bytes, want over %d", len(big), policy.MaxSize)
	}
	inline := map[string]string{"big": big}
	put(t, b, iam.User{Name: "uma", ID: "20", InlinePolicies: inline})
	put(t, b, iam.User{Name: "gus", ID: "21"})
	put(t, b, iam.Group{Name: "queues", ID: "22", Members: []string{"gus"}, InlinePolicies: inline})
	put(t, b, iam.Role{Name: "worker", ID: "23", AssumeRolePolicy: `{}`, InlinePolicies: inline})
	for _, p := range []authz.Principal{
		{Kind: authz.User, Name: "uma"},
		{Kind: authz.User, Name: "gus"},
		{Kind: authz.Role, Name: "worker", ARN: "arn:vws:sts::" + acct + ":assumed-role/worker/s1"},
	} {
		if d, err := a.Authorize(ctx, p, "sqs:SendMessage", "*", nil); err != nil || !d.Allowed {
			t.Errorf("%s: %+v %v", p.Name, d, err)
		}
	}
}

// TestManagedPolicyARNIncludesPath checks that a managed policy is
// identified by its full ARN, path included, as in AWS (#191).
func TestManagedPolicyARNIncludesPath(t *testing.T) {
	b := setup(t)
	put(t, b, iam.Policy{Name: "TeamRead", ID: "30", Path: "/other/", DefaultVersion: "v1", Versions: []iam.PolicyVersion{
		{ID: "v1", Document: `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
			`"Action":"s3:GetObject","Resource":"*"}}`},
	}})
	a := authz.New(b, acct, nil)
	ctx := context.Background()
	for _, c := range []struct {
		arn  string
		want bool
	}{
		{"arn:vws:iam::" + acct + ":policy/S3Read", true},
		{"arn:vws:iam::" + acct + ":policy/other/S3Read", false},
		{"arn:vws:iam::" + acct + ":policy/other/TeamRead", true},
		{"arn:vws:iam::" + acct + ":policy/TeamRead", false},
	} {
		if got, err := a.ManagedPolicyExists(ctx, c.arn); err != nil || got != c.want {
			t.Errorf("ManagedPolicyExists(%s) = %v, %v; want %v", c.arn, got, err, c.want)
		}
	}
	put(t, b, iam.User{Name: "pat", ID: "31", AttachedPolicies: []string{"arn:vws:iam::" + acct + ":policy/other/S3Read"}})
	if _, err := a.Authorize(ctx, authz.Principal{Kind: authz.User, Name: "pat"},
		"s3:GetObject", "*", nil); !errors.Is(err, authz.ErrNoSuchEntity) {
		t.Errorf("attached policy with the wrong path: %v", err)
	}
}
