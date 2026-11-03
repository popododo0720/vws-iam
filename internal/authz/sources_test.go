package authz_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
)

func sources(ns []policy.Named) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Type+" "+n.ID)
	}
	return out
}

// TestPolicySources: every gathered policy names its simulator source
// (type and id), inline policies in name order, and a group's own
// policies can be read alone.
func TestPolicySources(t *testing.T) {
	b := setup(t)
	allow := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sqs:*","Resource":"*"}}`
	inline := map[string]string{"zeta": allow, "alpha": allow, "mid": allow}
	put(t, b, iam.User{Name: "bob", ID: "6", InlinePolicies: inline})
	a := authz.New(b, acct, nil)
	ctx := context.Background()

	ids, _, err := a.IdentityPolicies(ctx, authz.Principal{Kind: authz.User, Name: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"user-managed S3Read", "group group_devs_ec2", "group group_nofleet_deny"}
	if got := sources(ids); !slices.Equal(got, want) {
		t.Fatalf("alice sources %q, want %q", got, want)
	}
	for range 20 { // map order would show up within a few runs
		ids, _, err = a.IdentityPolicies(ctx, authz.Principal{Kind: authz.User, Name: "bob"})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"user user_bob_alpha", "user user_bob_mid", "user user_bob_zeta"}
		if got := sources(ids); !slices.Equal(got, want) {
			t.Fatalf("bob sources %q, want %q", got, want)
		}
	}
	ids, _, err = a.IdentityPolicies(ctx, authz.Principal{Kind: authz.Role, Name: "reader"})
	if err != nil || !slices.Equal(sources(ids), []string{"user-managed S3Read"}) {
		t.Fatalf("role sources %q %v", sources(ids), err)
	}

	ids, arn, err := a.GroupPolicies(ctx, "DEVS")
	wantARN := "arn:vws:iam::" + acct + ":group/devs"
	if err != nil || arn != wantARN || !slices.Equal(sources(ids), []string{"group group_devs_ec2"}) {
		t.Fatalf("group: %q %s %v", sources(ids), arn, err)
	}
	if _, _, err := a.GroupPolicies(ctx, "nobody"); !errors.Is(err, authz.ErrNoSuchEntity) {
		t.Fatalf("unknown group: %v, want ErrNoSuchEntity", err)
	}

	m, err := a.ManagedPolicy(ctx, "arn:vws:iam::"+acct+":policy/S3Read")
	if err != nil || m.ID != "S3Read" || m.Type != "user-managed" {
		t.Fatalf("managed: %+v %v", m, err)
	}
	if _, err := a.ManagedPolicy(ctx, "arn:vws:iam::other:policy/S3Read"); !errors.Is(err, authz.ErrNoSuchEntity) {
		t.Fatalf("other account's policy: %v, want ErrNoSuchEntity", err)
	}
}
