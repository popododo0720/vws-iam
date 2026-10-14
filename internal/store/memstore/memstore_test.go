package memstore_test

import (
	"context"
	"errors"

	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"

	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Backend { return memstore.New() })
}

func TestScopedConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Backend { return store.Scoped(memstore.New(), "proj-a") })
}

func TestScopedProjectsAreIsolated(t *testing.T) {
	b := memstore.New()
	a, c := store.Scoped(b, "proj-a"), store.Scoped(b, "proj-c")
	ctx := context.Background()
	if _, err := store.Create(ctx, a, iam.User{Name: "alice", ID: "1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get[iam.User](ctx, c, "alice"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("other project sees alice: %v", err)
	}
	if _, err := store.Create(ctx, c, iam.User{Name: "alice", ID: "2"}); err != nil {
		t.Fatalf("same name in another project: %v", err)
	}
	if l, err := store.List[iam.User](ctx, a); err != nil || len(l) != 1 || l[0].Object.ID != "1" {
		t.Fatalf("list a: %v %+v", err, l)
	}
}
