package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

type flaky struct {
	store.Backend
	fails int
	calls int
}

func (f *flaky) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	f.calls++
	if f.calls <= f.fails {
		return store.Entry{}, store.ErrUnavailable
	}
	return f.Backend.Get(ctx, kind, key)
}

func TestRetryRecoversFromTransientErrors(t *testing.T) {
	m := memstore.New()
	ctx := context.Background()
	if _, err := store.Create(ctx, m, iam.Group{Name: "g", ID: "1"}); err != nil {
		t.Fatal(err)
	}
	f := &flaky{Backend: m, fails: 2}
	if _, err := store.Get[iam.Group](ctx, store.WithRetry(f, 3, time.Millisecond), "g"); err != nil || f.calls != 3 {
		t.Fatalf("%v after %d calls", err, f.calls)
	}
	f = &flaky{Backend: m, fails: 5}
	if _, err := store.Get[iam.Group](ctx, store.WithRetry(f, 3, time.Millisecond), "g"); !errors.Is(err, store.ErrUnavailable) || f.calls != 3 {
		t.Fatalf("%v after %d calls", err, f.calls)
	}
	// A permanent error is not retried.
	f = &flaky{Backend: m}
	if _, err := store.Get[iam.Group](ctx, store.WithRetry(f, 3, time.Millisecond), "missing"); !errors.Is(err, store.ErrNotFound) || f.calls != 1 {
		t.Fatalf("%v after %d calls", err, f.calls)
	}
	// A cancelled context stops the backoff.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	f = &flaky{Backend: m, fails: 5}
	if _, err := store.Get[iam.Group](cctx, store.WithRetry(f, 5, time.Hour), "g"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}
