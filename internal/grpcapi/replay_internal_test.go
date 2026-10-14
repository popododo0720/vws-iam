package grpcapi

import (
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestClaimReplayStaleEntry covers an expired entry that GC has not yet
// removed: the claim replaces it once instead of refusing forever.
func TestClaimReplayStaleEntry(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	b := memstore.New()
	s := New(b, nil, WithClock(func() time.Time { return now }))
	r := &iamv1.AuthenticateRequest{AccessKeyId: "AKIA", Signature: "sig"}
	h := replayHash(r)
	if _, err := store.Create(ctx, b, iam.ReplayEntry{Hash: h, Expires: now.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := s.claimReplay(ctx, r); err != nil {
		t.Fatalf("stale entry: %v", err)
	}
	v, err := store.Get[iam.ReplayEntry](ctx, b, h)
	if err != nil || !v.Object.Expires.Equal(now.Add(replayTTL)) {
		t.Fatalf("entry not renewed: %+v %v", v, err)
	}
	if err := s.claimReplay(ctx, r); err == nil {
		t.Fatal("replay after renewal accepted")
	}
	// A second replica with an empty front is refused by the store.
	if err := New(b, nil, WithClock(func() time.Time { return now })).claimReplay(ctx, r); err == nil {
		t.Fatal("replay on second replica accepted")
	}
}

// TestGCPaginates deletes expired entries across several Limit/Continue
// pages and keeps live ones.
func TestGCPaginates(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	b := memstore.New()
	s := New(b, nil, WithClock(func() time.Time { return now }))
	s.gcPage = 2
	for i := range 7 {
		exp := now.Add(-time.Minute)
		if i == 3 {
			exp = now.Add(time.Minute)
		}
		h := replayHash(&iamv1.AuthenticateRequest{AccessKeyId: "AKIA", Signature: string(rune('a' + i))})
		if _, err := store.Create(ctx, b, iam.ReplayEntry{Hash: h, Expires: exp}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.GCReplayEntries(ctx)
	if err != nil || n != 6 {
		t.Fatalf("GC = %d, %v; want 6", n, err)
	}
	if vs, err := store.List[iam.ReplayEntry](ctx, b); err != nil || len(vs) != 1 {
		t.Fatalf("left %d, %v; want the 1 live entry", len(vs), err)
	}
}
