package etcdstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/etcdstore"
	"github.com/popododo0720/vws-iam/internal/store/storetest"
)

func TestKeyPairSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	first, _, prefix := open(t)
	var pair iam.KeyPair
	for _, sample := range storetest.Samples() {
		if p, ok := sample.(iam.KeyPair); ok {
			pair = p
		}
	}
	if pair.ID == "" {
		t.Fatal("no key pair sample")
	}
	original, err := json.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, store.Scoped(first, "proj-a"), pair); err != nil {
		t.Fatal(err)
	}
	second, err := etcdstore.Open([]string{endpoint}, nil, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
	fresh := store.Scoped(second, "proj-a")
	got, err := store.Get[iam.KeyPair](ctx, fresh, pair.ID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(got.Object)
	if err != nil || string(encoded) != string(original) {
		t.Fatalf("reopened pair changed: %s, %v", encoded, err)
	}
	if _, err := store.Create(ctx, fresh, pair); !errors.Is(err, store.ErrExists) {
		t.Fatalf("replayed create after reopen: %v", err)
	}
}
