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

// createVirtualMfaDevice makes an unassigned device the tag calls can target.
func createVirtualMfaDevice(t *testing.T, e *env, ctx context.Context, name string) *iamv1.MfaDevice {
	t.Helper()
	d, err := e.mfa.CreateVirtualMfaDevice(ctx, &iamv1.CreateVirtualMfaDeviceRequest{
		Parent: parentName, MfaDeviceId: name, MfaDevice: &iamv1.MfaDevice{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d.GetMfaDevice()
}

func mfaTagsOf(t *testing.T, ctx context.Context, e *env, device string) map[string]string {
	t.Helper()
	out := map[string]string{}
	resp, err := e.mfa.ListMFADeviceTags(ctx, &iamv1.ListMFADeviceTagsRequest{Name: device})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range resp.GetTags() {
		out[tag.GetKey()] = tag.GetValue()
	}
	return out
}

func TestMFADeviceTags(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	dev := createVirtualMfaDevice(t, e, ctx, "tagged-phone")
	if n := len(mfaTagsOf(t, ctx, e, dev.GetName())); n != 0 {
		t.Fatalf("fresh device has %d tags", n)
	}
	op, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: dev.GetName(), Tags: []*iamv1.Tag{
		tag("Team", "platform"), tag("env", "prod"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	unpack(t, op, &iamv1.MfaDevice{})
	if got := mfaTagsOf(t, ctx, e, dev.GetName()); len(got) != 2 || got["Team"] != "platform" || got["env"] != "prod" {
		t.Fatalf("tags %v", got)
	}
	// TagMFADevice overwrites a key it names and leaves other keys alone.
	if _, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: dev.GetName(), Tags: []*iamv1.Tag{
		tag("env", "dev"), tag("Owner", "ops"),
	}}); err != nil {
		t.Fatal(err)
	}
	got := mfaTagsOf(t, ctx, e, dev.GetName())
	if len(got) != 3 || got["Team"] != "platform" || got["env"] != "dev" || got["Owner"] != "ops" {
		t.Fatalf("after overwrite %v", got)
	}
	// ListMFADeviceTags is sorted by key.
	resp, err := e.mfa.ListMFADeviceTags(ctx, &iamv1.ListMFADeviceTagsRequest{Name: dev.GetName()})
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
	d, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: dev.GetName()})
	if err != nil || d.GetGeneration() != 3 {
		t.Fatalf("generation after two tag mutations: %v %v", d.GetGeneration(), err)
	}
	// UntagMFADevice removes the named keys and ignores a key that is not attached.
	if _, err := e.mfa.UntagMFADevice(ctx, &iamv1.UntagMFADeviceRequest{
		Name: dev.GetName(), TagKeys: []string{"Team", "missing"},
	}); err != nil {
		t.Fatal(err)
	}
	got = mfaTagsOf(t, ctx, e, dev.GetName())
	if len(got) != 2 || got["env"] != "dev" || got["Owner"] != "ops" {
		t.Fatalf("after untag %v", got)
	}
	// Case is significant on a device, as in AWS: a differently cased key is a new tag.
	if _, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: dev.GetName(), Tags: []*iamv1.Tag{
		tag("ENV", "PROD"),
	}}); err != nil {
		t.Fatal(err)
	}
	got = mfaTagsOf(t, ctx, e, dev.GetName())
	if len(got) != 3 || got["env"] != "dev" || got["ENV"] != "PROD" {
		t.Fatalf("after case-different tag %v", got)
	}
	// validate_only reports success and stores nothing.
	dry := &iamv1.TagMFADeviceRequest{Name: dev.GetName(), Tags: []*iamv1.Tag{tag("dry", "run")}, ValidateOnly: true}
	if _, err := e.mfa.TagMFADevice(ctx, dry); err != nil {
		t.Fatal(err)
	}
	if _, ok := mfaTagsOf(t, ctx, e, dev.GetName())["dry"]; ok {
		t.Fatal("validate_only stored the tag")
	}
	// The same request_id returns the same operation; a different request with
	// it is IDEMPOTENCY_CONFLICT.
	req1 := &iamv1.TagMFADeviceRequest{
		Name: dev.GetName(), Tags: []*iamv1.Tag{tag("replay", "1")},
		RequestId: "0b6a4a56-3f0e-4bb6-8f9f-6a1d2f2f9a11",
	}
	if _, err := e.mfa.TagMFADevice(ctx, req1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.mfa.TagMFADevice(ctx, req1); err != nil {
		t.Fatalf("replay: %v", err)
	}
	_, err = e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{
		Name: dev.GetName(), Tags: []*iamv1.Tag{tag("replay", "2")}, RequestId: req1.RequestId,
	})
	wantErr(t, err, codes.Aborted, "IDEMPOTENCY_CONFLICT", "IdempotentParameterMismatch")
}

func TestMFADeviceTagsPage(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	dev := createVirtualMfaDevice(t, e, ctx, "paged-phone")
	var all []*iamv1.Tag
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		all = append(all, tag(k, k+"-value"))
	}
	if _, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: dev.GetName(), Tags: all}); err != nil {
		t.Fatal(err)
	}
	var keys []string
	token := ""
	for pages := 0; ; pages++ {
		if pages > 5 {
			t.Fatal("pagination did not end")
		}
		resp, err := e.mfa.ListMFADeviceTags(ctx, &iamv1.ListMFADeviceTagsRequest{
			Name: dev.GetName(), PageSize: 2, PageToken: token,
		})
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

func TestMFADeviceTagErrors(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	dev := createVirtualMfaDevice(t, e, ctx, "errors-phone")
	name := dev.GetName()
	missing := parentName + "/mfaDevices/ghost"

	_, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: missing, Tags: []*iamv1.Tag{tag("k", "v")}})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	_, err = e.mfa.UntagMFADevice(ctx, &iamv1.UntagMFADeviceRequest{Name: missing, TagKeys: []string{"k"}})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
	_, err = e.mfa.ListMFADeviceTags(ctx, &iamv1.ListMFADeviceTagsRequest{Name: missing})
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
			_, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: name, Tags: tc.tags})
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
	_, err = e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: name, Tags: many})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")

	// The 51st tag is the AWS LimitExceeded; nothing of the failed request is stored.
	fill := make([]*iamv1.Tag, 49)
	for i := range fill {
		fill[i] = tag("k"+strings.Repeat("x", i+1), "v")
	}
	if _, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: name, Tags: fill}); err != nil {
		t.Fatal(err)
	}
	_, err = e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{
		Name: name, Tags: []*iamv1.Tag{tag("extra1", "v"), tag("extra2", "v")},
	})
	wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
	if n := len(mfaTagsOf(t, ctx, e, name)); n != 49 {
		t.Fatalf("stored %d tags after the refused request", n)
	}
	// Overwriting an attached key at the limit is not a new tag.
	overwrite := &iamv1.TagMFADeviceRequest{Name: name, Tags: []*iamv1.Tag{tag("k"+strings.Repeat("x", 49), "new")}}
	if _, err := e.mfa.TagMFADevice(ctx, overwrite); err != nil {
		t.Fatalf("overwrite at the limit: %v", err)
	}

	_, err = e.mfa.UntagMFADevice(ctx, &iamv1.UntagMFADeviceRequest{Name: name, TagKeys: nil})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	_, err = e.mfa.UntagMFADevice(ctx, &iamv1.UntagMFADeviceRequest{Name: name, TagKeys: make([]string, 51)})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	_, err = e.mfa.UntagMFADevice(ctx, &iamv1.UntagMFADeviceRequest{Name: name, TagKeys: []string{"bad#key"}})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "InvalidInput")

	_, err = e.mfa.ListMFADeviceTags(ctx, &iamv1.ListMFADeviceTagsRequest{Name: name, PageToken: "not base64!"})
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "InvalidInput")
}

// Tags survive on a shared store: a second replica reads what the first wrote.
func TestMFADeviceTagsOnSharedStore(t *testing.T) {
	now := time.Now().UTC()
	store := memstore.New()
	e1 := newEnvOn(t, store, &now)
	e2 := newEnvOn(t, store, &now)
	ctx := t.Context()
	dev := createVirtualMfaDevice(t, e1, ctx, "shared-phone")
	if _, err := e1.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{
		Name: dev.GetName(), Tags: []*iamv1.Tag{tag("env", "prod")},
	}); err != nil {
		t.Fatal(err)
	}
	if got := mfaTagsOf(t, ctx, e2, dev.GetName()); got["env"] != "prod" {
		t.Fatalf("second replica reads %v", got)
	}
}

// A tag change must not move any timestamp: AWS has no update time for a
// virtual MFA device.
func TestMFADeviceTagsKeepTimestamps(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.createUser(t, ctx, "alice")
	enableMFA(t, e, ctx, "alice")
	name := parentName + "/mfaDevices/alice-phone"
	before, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	*e.now = e.now.Add(time.Hour)
	if _, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{
		Name: name, Tags: []*iamv1.Tag{tag("env", "prod")},
	}); err != nil {
		t.Fatal(err)
	}
	after, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if !after.GetCreateTime().AsTime().Equal(before.GetCreateTime().AsTime()) {
		t.Fatalf("tagging moved CreateTime to %v, want %v", after.GetCreateTime().AsTime(), before.GetCreateTime().AsTime())
	}
	if !after.GetUpdateTime().AsTime().Equal(before.GetUpdateTime().AsTime()) {
		t.Fatalf("tagging moved UpdateTime to %v, want %v", after.GetUpdateTime().AsTime(), before.GetUpdateTime().AsTime())
	}
	if !after.GetStatus().GetEnableTime().AsTime().Equal(before.GetStatus().GetEnableTime().AsTime()) {
		t.Fatalf("tagging moved EnableTime to %v, want %v",
			after.GetStatus().GetEnableTime().AsTime(), before.GetStatus().GetEnableTime().AsTime())
	}
	untag := &iamv1.UntagMFADeviceRequest{Name: name, TagKeys: []string{"env"}}
	if _, err := e.mfa.UntagMFADevice(ctx, untag); err != nil {
		t.Fatal(err)
	}
	after, err = e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if !after.GetUpdateTime().AsTime().Equal(before.GetUpdateTime().AsTime()) {
		t.Fatalf("untagging moved UpdateTime to %v, want %v", after.GetUpdateTime().AsTime(), before.GetUpdateTime().AsTime())
	}
}
