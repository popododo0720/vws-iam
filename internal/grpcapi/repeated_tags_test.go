package grpcapi_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// tagTarget is one resource kind a Tag request writes: a managed policy or
// a virtual MFA device. vws-proto#52 gives both the same rule for a key that
// repeats within one request: the request succeeds and the last value wins.
type tagTarget struct {
	create func(t *testing.T, ctx context.Context, e *env, name string) string
	tag    func(ctx context.Context, e *env, name, requestID string, tags []*iamv1.Tag) error
	list   func(t *testing.T, ctx context.Context, e *env, name string) []*iamv1.Tag
}

var tagTargets = map[string]tagTarget{
	"TagPolicy": {
		create: func(t *testing.T, ctx context.Context, e *env, name string) string {
			return e.createPolicy(t, ctx, name, tagPolicyDoc).GetName()
		},
		tag: func(ctx context.Context, e *env, name, requestID string, tags []*iamv1.Tag) error {
			_, err := e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: name, Tags: tags, RequestId: requestID})
			return err
		},
		list: func(t *testing.T, ctx context.Context, e *env, name string) []*iamv1.Tag {
			t.Helper()
			resp, err := e.policies.ListPolicyTags(ctx, &iamv1.ListPolicyTagsRequest{Name: name, PageSize: 100})
			if err != nil {
				t.Fatal(err)
			}
			return resp.GetTags()
		},
	},
	"TagMFADevice": {
		create: func(t *testing.T, ctx context.Context, e *env, name string) string {
			return createVirtualMfaDevice(t, e, ctx, name).GetName()
		},
		tag: func(ctx context.Context, e *env, name, requestID string, tags []*iamv1.Tag) error {
			_, err := e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: name, Tags: tags, RequestId: requestID})
			return err
		},
		list: func(t *testing.T, ctx context.Context, e *env, name string) []*iamv1.Tag {
			t.Helper()
			resp, err := e.mfa.ListMFADeviceTags(ctx, &iamv1.ListMFADeviceTagsRequest{Name: name, PageSize: 100})
			if err != nil {
				t.Fatal(err)
			}
			return resp.GetTags()
		},
	},
}

// wantOnlyTag fails unless the resource holds exactly one tag, key=value.
func wantOnlyTag(t *testing.T, got []*iamv1.Tag, key, value string) {
	t.Helper()
	if len(got) != 1 || got[0].GetKey() != key || got[0].GetValue() != value {
		t.Fatalf("tags %v, want only %s=%s", got, key, value)
	}
}

// A key repeated within one request is stored once with the last value, on
// a fresh resource and over a key the resource already holds.
func TestRepeatedTagKeyLastWins(t *testing.T) {
	for kind, tt := range tagTargets {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			ctx := t.Context()
			name := tt.create(t, ctx, e, "repeat")
			if err := tt.tag(ctx, e, name, "", []*iamv1.Tag{tag("k", "a"), tag("k", "b")}); err != nil {
				t.Fatalf("repeated key: %v", err)
			}
			wantOnlyTag(t, tt.list(t, ctx, e, name), "k", "b")

			// Over a stored key the request's last value wins too, whatever the
			// stored value was.
			if err := tt.tag(ctx, e, name, "", []*iamv1.Tag{tag("k", "c"), tag("k", "b"), tag("k", "d")}); err != nil {
				t.Fatalf("repeated stored key: %v", err)
			}
			wantOnlyTag(t, tt.list(t, ctx, e, name), "k", "d")

			// Key case is significant: K and k are two keys, each last-wins.
			if err := tt.tag(ctx, e, name, "", []*iamv1.Tag{
				tag("K", "x"), tag("k", "e"), tag("K", "y"),
			}); err != nil {
				t.Fatalf("mixed-case keys: %v", err)
			}
			got := tt.list(t, ctx, e, name)
			if len(got) != 2 || got[0].GetKey() != "K" || got[0].GetValue() != "y" ||
				got[1].GetKey() != "k" || got[1].GetValue() != "e" {
				t.Fatalf("tags %v, want K=y, k=e", got)
			}
		})
	}
}

// A repeated key counts once against the 50 tags a resource may keep. The
// request itself may still carry at most 50 tags (vws-proto#52), repeats
// included, as AWS validates the Tags array before it applies it.
func TestRepeatedTagKeyCountsOnce(t *testing.T) {
	for kind, tt := range tagTargets {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			ctx := t.Context()
			name := tt.create(t, ctx, e, "limit")
			if err := tt.tag(ctx, e, name, "", []*iamv1.Tag{tag("k00", "stored")}); err != nil {
				t.Fatal(err)
			}

			// 51 tags with one repeat: 50 distinct keys, but 51 items in the
			// request, which is ValidationError and stores nothing.
			over := make([]*iamv1.Tag, 0, 51)
			for i := 1; i <= 50; i++ {
				over = append(over, tag(fmt.Sprintf("k%02d", i), "v"))
			}
			over = append(over, tag("k01", "again"))
			err := tt.tag(ctx, e, name, "", over)
			wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
			wantOnlyTag(t, tt.list(t, ctx, e, name), "k00", "stored")

			// 50 items, 49 new distinct keys and one repeat: with the stored key
			// that is 50 tags, so it is accepted. Counting the repeat twice would
			// make 51 and LimitExceeded.
			full := make([]*iamv1.Tag, 0, 50)
			for i := 1; i <= 49; i++ {
				full = append(full, tag(fmt.Sprintf("k%02d", i), "v"))
			}
			full = append(full, tag("k01", "last"))
			if err := tt.tag(ctx, e, name, "", full); err != nil {
				t.Fatalf("49 new keys and one repeat over 1 stored: %v", err)
			}
			got := tt.list(t, ctx, e, name)
			if len(got) != 50 {
				t.Fatalf("stored %d tags, want 50", len(got))
			}
			for _, tg := range got {
				if tg.GetKey() == "k01" && tg.GetValue() != "last" {
					t.Fatalf("k01=%s, want the last value", tg.GetValue())
				}
			}

			// A repeat that would add a 51st distinct key is still refused.
			err = tt.tag(ctx, e, name, "", []*iamv1.Tag{tag("k50", "a"), tag("k50", "b")})
			wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
			if n := len(tt.list(t, ctx, e, name)); n != 50 {
				t.Fatalf("stored %d tags after the refused request", n)
			}
		})
	}
}

// A repeated-key request delivered twice with one request_id applies once,
// and another replica on the same store, as after a restart, reads the last
// value.
func TestRepeatedTagKeyReplayAndRestart(t *testing.T) {
	ids := map[string]string{
		"TagPolicy":    "3f1c2b7e-9d4a-4c55-8b6e-2a7d9e0c4f12",
		"TagMFADevice": "6d2e8a91-4b7c-4f30-9a1e-5c8b3d7f2e64",
	}
	for kind, tt := range tagTargets {
		t.Run(kind, func(t *testing.T) {
			now := time.Now().UTC()
			b := memstore.New()
			e1 := newEnvOn(t, b, &now)
			ctx := t.Context()
			name := tt.create(t, ctx, e1, "replayed")
			req := []*iamv1.Tag{tag("k", "a"), tag("k", "b")}
			for i := range 2 {
				if err := tt.tag(ctx, e1, name, ids[kind], req); err != nil {
					t.Fatalf("delivery %d: %v", i+1, err)
				}
			}
			wantOnlyTag(t, tt.list(t, ctx, e1, name), "k", "b")

			e2 := newEnvOn(t, b, &now)
			wantOnlyTag(t, tt.list(t, ctx, e2, name), "k", "b")
			if err := tt.tag(ctx, e2, name, ids[kind], req); err != nil {
				t.Fatalf("delivery on the second replica: %v", err)
			}
			wantOnlyTag(t, tt.list(t, ctx, e2, name), "k", "b")
		})
	}
}
