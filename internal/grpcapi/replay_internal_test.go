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
	ring := testRing(t, "a", "a")
	s := New(b, ring, WithClock(func() time.Time { return now }))
	r := &iamv1.AuthenticateRequest{AccessKeyId: "AKIA", Signature: "sig"}
	h := s.replayKeys(r)[0]
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
	if err := New(b, ring, WithClock(func() time.Time { return now })).claimReplay(ctx, r); err == nil {
		t.Fatal("replay on second replica accepted")
	}
}

// TestReplayKeysAreKeyed covers #41: a replay entry is stored under a
// digest per KEK, never the plain SHA-256 of key id and signature, and a
// used request stays refused after a restart and across a KEK rotation.
func TestReplayKeysAreKeyed(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	clock := WithClock(func() time.Time { return now })
	b := memstore.New()
	r := &iamv1.AuthenticateRequest{AccessKeyId: "AKIA", Signature: "sig"}
	a := New(b, testRing(t, "a", "a"), clock)
	if err := a.claimReplay(ctx, r); err != nil {
		t.Fatal(err)
	}
	vs, err := store.List[iam.ReplayEntry](ctx, b)
	if err != nil || len(vs) != 1 || vs[0].Object.Hash == legacyReplayHash(r) || vs[0].Object.Hash != a.replayKeys(r)[0] {
		t.Fatalf("entries %+v %v, want one under the keyed digest", vs, err)
	}
	for name, s := range map[string]*Server{
		"restart":           New(b, testRing(t, "a", "a"), clock),
		"ring {a,b}":        New(b, testRing(t, "a", "a", "b"), clock),
		"ring {a,b} b live": New(b, testRing(t, "b", "a", "b"), clock),
	} {
		if err := s.claimReplay(ctx, r); err == nil {
			t.Errorf("%s: replay accepted", name)
		}
	}

	// A request claimed under {a,b} is refused by a ring of either KEK.
	r2 := &iamv1.AuthenticateRequest{AccessKeyId: "AKIA", Signature: "sig2"}
	if err := New(b, testRing(t, "b", "a", "b"), clock).claimReplay(ctx, r2); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if err := New(b, testRing(t, id, id), clock).claimReplay(ctx, r2); err == nil {
			t.Errorf("ring {%s}: replay accepted", id)
		}
	}
}

// TestLegacyReplayEntryRefuses keeps refusing a request claimed by a
// release before #41 under the plain SHA-256 key, until it expires.
func TestLegacyReplayEntryRefuses(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	b := memstore.New()
	s := New(b, testRing(t, "a", "a"), WithClock(func() time.Time { return now }))
	r := &iamv1.AuthenticateRequest{AccessKeyId: "AKIA", Signature: "sig"}
	legacy := iam.ReplayEntry{Hash: legacyReplayHash(r), Expires: now.Add(time.Minute)}
	if _, err := store.Create(ctx, b, legacy); err != nil {
		t.Fatal(err)
	}
	if err := s.claimReplay(ctx, r); err == nil {
		t.Fatal("request in the legacy store accepted")
	}
	now = now.Add(2 * time.Minute)
	if err := s.claimReplay(ctx, r); err != nil {
		t.Fatalf("after the legacy entry expired: %v", err)
	}
}

// TestGCPaginates deletes expired entries across several Limit/Continue
// pages and keeps live ones.
func TestGCPaginates(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	b := memstore.New()
	s := New(b, testRing(t, "a", "a"), WithClock(func() time.Time { return now }))
	s.gcPage = 2
	for i := range 7 {
		exp := now.Add(-time.Minute)
		if i == 3 {
			exp = now.Add(time.Minute)
		}
		h := s.replayKeys(&iamv1.AuthenticateRequest{AccessKeyId: "AKIA", Signature: string(rune('a' + i))})[0]
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
