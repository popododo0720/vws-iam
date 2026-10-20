package grpcapi_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const tagPolicyDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`

func tagsOf(t *testing.T, ctx context.Context, e *env, policy string) map[string]string {
	t.Helper()
	out := map[string]string{}
	resp, err := e.policies.ListPolicyTags(ctx, &iamv1.ListPolicyTagsRequest{Name: policy})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range resp.GetTags() {
		out[tag.GetKey()] = tag.GetValue()
	}
	return out
}

func tag(key, value string) *iamv1.Tag { return &iamv1.Tag{Key: key, Value: value} }

func TestPolicyTags(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	pol := e.createPolicy(t, ctx, "tagged", tagPolicyDoc)
	if n := len(tagsOf(t, ctx, e, pol.GetName())); n != 0 {
		t.Fatalf("fresh policy has %d tags", n)
	}
	op, err := e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: pol.GetName(), Tags: []*iamv1.Tag{
		tag("Team", "platform"), tag("env", "prod"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	unpack(t, op, &iamv1.Policy{})
	if got := tagsOf(t, ctx, e, pol.GetName()); len(got) != 2 || got["Team"] != "platform" || got["env"] != "prod" {
		t.Fatalf("tags %v", got)
	}
	// TagPolicy overwrites a key it names and leaves other keys alone.
	if _, err := e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: pol.GetName(), Tags: []*iamv1.Tag{
		tag("env", "dev"), tag("Owner", "ops"),
	}}); err != nil {
		t.Fatal(err)
	}
	got := tagsOf(t, ctx, e, pol.GetName())
	if len(got) != 3 || got["Team"] != "platform" || got["env"] != "dev" || got["Owner"] != "ops" {
		t.Fatalf("after overwrite %v", got)
	}
	// ListPolicyTags is sorted by key.
	resp, err := e.policies.ListPolicyTags(ctx, &iamv1.ListPolicyTagsRequest{Name: pol.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, tg := range resp.GetTags() {
		keys = append(keys, tg.GetKey())
	}
	if strings.Join(keys, ",") != "Owner,Team,env" {
		t.Fatalf("keys %v, want sorted", keys)
	}
	p, err := e.policies.GetPolicy(ctx, &iamv1.GetPolicyRequest{Name: pol.GetName()})
	if err != nil || p.GetGeneration() != 3 {
		t.Fatalf("generation after two tag mutations: %v %v", p.GetGeneration(), err)
	}
	// UntagPolicy removes the named keys and ignores a key that is not attached.
	req := &iamv1.UntagPolicyRequest{Name: pol.GetName(), TagKeys: []string{"Team", "missing"}}
	if _, err := e.policies.UntagPolicy(ctx, req); err != nil {
		t.Fatal(err)
	}
	got = tagsOf(t, ctx, e, pol.GetName())
	if len(got) != 2 || got["env"] != "dev" || got["Owner"] != "ops" {
		t.Fatalf("after untag %v", got)
	}
	// Case is significant on a policy, as in AWS: a differently cased key is a new tag.
	caseTag := &iamv1.TagPolicyRequest{Name: pol.GetName(), Tags: []*iamv1.Tag{tag("ENV", "PROD")}}
	if _, err := e.policies.TagPolicy(ctx, caseTag); err != nil {
		t.Fatal(err)
	}
	got = tagsOf(t, ctx, e, pol.GetName())
	if len(got) != 3 || got["env"] != "dev" || got["ENV"] != "PROD" {
		t.Fatalf("after case-different tag %v", got)
	}
	// validate_only reports success and stores nothing.
	dry := &iamv1.TagPolicyRequest{Name: pol.GetName(), Tags: []*iamv1.Tag{tag("dry", "run")}, ValidateOnly: true}
	if _, err := e.policies.TagPolicy(ctx, dry); err != nil {
		t.Fatal(err)
	}
	if _, ok := tagsOf(t, ctx, e, pol.GetName())["dry"]; ok {
		t.Fatal("validate_only stored the tag")
	}
	// The same request_id returns the same operation; a different request with
	// it is IDEMPOTENCY_CONFLICT.
	req1 := &iamv1.TagPolicyRequest{
		Name: pol.GetName(), Tags: []*iamv1.Tag{tag("replay", "1")},
		RequestId: "8a3a6f6e-7a44-4a4e-9f70-0f8f8b4e2c11",
	}
	if _, err := e.policies.TagPolicy(ctx, req1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.policies.TagPolicy(ctx, req1); err != nil {
		t.Fatalf("replay: %v", err)
	}
	_, err = e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{
		Name: pol.GetName(), Tags: []*iamv1.Tag{tag("replay", "2")}, RequestId: req1.RequestId,
	})
	wantErr(t, err, codes.Aborted, "IDEMPOTENCY_CONFLICT", "IdempotentParameterMismatch")
}

func TestPolicyTagsPage(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	pol := e.createPolicy(t, ctx, "paged", tagPolicyDoc)
	var all []*iamv1.Tag
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		all = append(all, tag(k, k+"-value"))
	}
	if _, err := e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: pol.GetName(), Tags: all}); err != nil {
		t.Fatal(err)
	}
	var keys []string
	token := ""
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("pagination did not end")
		}
		req := &iamv1.ListPolicyTagsRequest{Name: pol.GetName(), PageSize: 2, PageToken: token}
		resp, err := e.policies.ListPolicyTags(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		for _, tg := range resp.GetTags() {
			keys = append(keys, tg.GetKey())
		}
		token = resp.GetNextPageToken()
		if token == "" {
			break
		}
		if len(resp.GetTags()) != 2 {
			t.Fatalf("page returned %d tags", len(resp.GetTags()))
		}
	}
	if strings.Join(keys, "") != "abcde" {
		t.Fatalf("paged keys %v", keys)
	}
}

func TestPolicyTagErrors(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	pol := e.createPolicy(t, ctx, "errors", tagPolicyDoc)
	name := pol.GetName()
	missing := parentName + "/policies/ghost"

	_, err := e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: missing, Tags: []*iamv1.Tag{tag("k", "v")}})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	_, err = e.policies.UntagPolicy(ctx, &iamv1.UntagPolicyRequest{Name: missing, TagKeys: []string{"k"}})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	_, err = e.policies.ListPolicyTags(ctx, &iamv1.ListPolicyTagsRequest{Name: missing})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")

	for _, tc := range []struct {
		name string
		tags []*iamv1.Tag
	}{
		{"no tags", nil},
		{"empty key", []*iamv1.Tag{tag("", "v")}},
		{"key with a forbidden character", []*iamv1.Tag{tag("bad#key", "v")}},
		{"key too long", []*iamv1.Tag{tag(strings.Repeat("k", 129), "v")}},
		{"value too long", []*iamv1.Tag{tag("k", strings.Repeat("v", 257))}},
		{"reserved key prefix", []*iamv1.Tag{tag("aws:team", "v")}},
		{"reserved value prefix", []*iamv1.Tag{tag("team", "aws:value")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: name, Tags: tc.tags})
			if tc.name == "no tags" {
				wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
				return
			}
			wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "InvalidInput")
		})
	}

	many := make([]*iamv1.Tag, 51)
	for i := range many {
		many[i] = tag("k"+strings.Repeat("x", i+1), "v")
	}
	_, err = e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: name, Tags: many})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")

	// The 51st tag is the AWS LimitExceeded; nothing of the failed request is stored.
	fill := make([]*iamv1.Tag, 49)
	for i := range fill {
		fill[i] = tag("k"+strings.Repeat("x", i+1), "v")
	}
	if _, err := e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: name, Tags: fill}); err != nil {
		t.Fatal(err)
	}
	_, err = e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{
		Name: name, Tags: []*iamv1.Tag{tag("extra1", "v"), tag("extra2", "v")},
	})
	wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
	if n := len(tagsOf(t, ctx, e, name)); n != 49 {
		t.Fatalf("stored %d tags after the refused request", n)
	}
	// Overwriting an attached key at the limit is not a new tag.
	overwrite := &iamv1.TagPolicyRequest{Name: name, Tags: []*iamv1.Tag{tag("k"+strings.Repeat("x", 49), "new")}}
	if _, err := e.policies.TagPolicy(ctx, overwrite); err != nil {
		t.Fatalf("overwrite at the limit: %v", err)
	}

	_, err = e.policies.UntagPolicy(ctx, &iamv1.UntagPolicyRequest{Name: name, TagKeys: nil})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	_, err = e.policies.UntagPolicy(ctx, &iamv1.UntagPolicyRequest{Name: name, TagKeys: make([]string, 51)})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	_, err = e.policies.UntagPolicy(ctx, &iamv1.UntagPolicyRequest{Name: name, TagKeys: []string{"bad#key"}})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "InvalidInput")

	_, err = e.policies.ListPolicyTags(ctx, &iamv1.ListPolicyTagsRequest{Name: name, PageToken: "not base64!"})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "InvalidInput")
}

// Tags survive on a shared store: a second replica reads what the first wrote.
func TestPolicyTagsOnSharedStore(t *testing.T) {
	now := time.Now().UTC()
	store := memstore.New()
	e1 := newEnvOn(t, store, &now)
	e2 := newEnvOn(t, store, &now)
	ctx := t.Context()
	pol := e1.createPolicy(t, ctx, "shared", tagPolicyDoc)
	req := &iamv1.TagPolicyRequest{Name: pol.GetName(), Tags: []*iamv1.Tag{tag("env", "prod")}}
	if _, err := e1.policies.TagPolicy(ctx, req); err != nil {
		t.Fatal(err)
	}
	if got := tagsOf(t, ctx, e2, pol.GetName()); got["env"] != "prod" {
		t.Fatalf("second replica reads %v", got)
	}
}
