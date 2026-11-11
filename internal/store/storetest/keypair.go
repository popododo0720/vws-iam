package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func keyPairSample(now time.Time) iam.KeyPair {
	return iam.KeyPair{
		ID: "key-0123456789abcdef", Name: "My laptop", Region: "ap-northeast-2",
		PublicKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea",
		FingerprintSHA256: "6db5e9b8a1bace1cdd9a7c6adb9e9396acc5073465d9fe8e3a0ef6d9c60d6d4f",
		KeyType:           iam.KeyPairED25519, Created: now,
		Meta: iam.Meta{
			UID: "kp-1", Generation: 1, RequestID: "0d90bfc6-013d-4099-8e33-9b73048fe8f5",
			Requests: []string{"rq-0123456789abcdef." + strings.Repeat("a", 64)},
		},
	}
}

func keyPairReplayAndRestart(t *testing.T, b store.Backend) {
	t.Helper()
	ctx := context.Background()
	p := keyPairSample(time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC))
	first := store.Scoped(b, "proj-a")
	v, err := store.Create(ctx, first, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, first, p); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate create: %v", err)
	}
	// Reconstruct the reader from the backend, without an in-process object.
	second := store.Scoped(b, "proj-a")
	got, err := store.Get[iam.KeyPair](ctx, second, p.ID)
	if err != nil || got.Version != v || mustJSON(t, got.Object) != mustJSON(t, p) {
		t.Fatalf("fresh reader: %+v, %v", got, err)
	}
	raw, err := second.Get(ctx, iam.KindKeyPair, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw.Spec, &fields); err != nil {
		t.Fatal(err)
	}
	for name := range fields {
		if strings.Contains(strings.ToLower(name), "private") || strings.Contains(strings.ToLower(name), "secret") {
			t.Fatalf("stored secret field %q", name)
		}
	}
	other := store.Scoped(b, "proj-b")
	if _, err := store.Get[iam.KeyPair](ctx, other, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other project sees pair: %v", err)
	}
	if all, err := store.List[iam.KeyPair](ctx, other); err != nil || len(all) != 0 {
		t.Fatalf("other project lists pair: %+v, %v", all, err)
	}
	if _, err := store.Create(ctx, other, p); err != nil {
		t.Fatalf("same id in another project: %v", err)
	}
}

func invalidKeyPairIsNotStored(t *testing.T, b store.Backend) {
	t.Helper()
	ctx := context.Background()
	p := keyPairSample(time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC))
	_, err := store.Create(ctx, b, p)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := store.Get[iam.KeyPair](ctx, b, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	p.PublicKey = "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
	if _, err := store.Update(ctx, b, p, cur.Version); !errors.Is(err, iam.ErrInvalid) {
		t.Fatalf("private material update: %v", err)
	}
	p.ID = "key-fedcba9876543210"
	if _, err := store.Create(ctx, b, p); !errors.Is(err, iam.ErrInvalid) {
		t.Fatalf("private material create: %v", err)
	}
	all, err := store.List[iam.KeyPair](ctx, b)
	if err != nil || len(all) != 1 || all[0].Object.PublicKey != cur.Object.PublicKey {
		t.Fatalf("invalid write changed store: %+v, %v", all, err)
	}
}
