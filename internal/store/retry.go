package store

import (
	"context"
	"errors"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// retrying retries ErrUnavailable with exponential backoff while ctx lives.
type retrying struct {
	b        Backend
	attempts int
	base     time.Duration
}

// WithRetry wraps b so a transient ErrUnavailable is retried up to attempts
// times, waiting base, 2*base, ... between tries. A Create retried after an
// unseen success reports ErrExists, which callers resolve by request id.
func WithRetry(b Backend, attempts int, base time.Duration) Backend {
	return retrying{b: b, attempts: max(attempts, 1), base: base}
}

func do[T any](ctx context.Context, r retrying, f func() (T, error)) (T, error) {
	wait := r.base
	for i := 1; ; i++ {
		v, err := f()
		if !errors.Is(err, ErrUnavailable) || i >= r.attempts {
			return v, err
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return v, errors.Join(err, ctx.Err())
		case <-t.C:
		}
		wait *= 2
	}
}

func (r retrying) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	return do(ctx, r, func() (string, error) { return r.b.Create(ctx, kind, key, spec) })
}

func (r retrying) Update(ctx context.Context, kind iam.Kind, key string, spec []byte, version string) (string, error) {
	return do(ctx, r, func() (string, error) { return r.b.Update(ctx, kind, key, spec, version) })
}

func (r retrying) Get(ctx context.Context, kind iam.Kind, key string) (Entry, error) {
	return do(ctx, r, func() (Entry, error) { return r.b.Get(ctx, kind, key) })
}

func (r retrying) List(ctx context.Context, kind iam.Kind) ([]Entry, error) {
	return do(ctx, r, func() ([]Entry, error) { return r.b.List(ctx, kind) })
}

func (r retrying) Delete(ctx context.Context, kind iam.Kind, key, version string) error {
	_, err := do(ctx, r, func() (struct{}, error) { return struct{}{}, r.b.Delete(ctx, kind, key, version) })
	return err
}
