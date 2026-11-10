package etcdstore

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// Call bounds. Every etcd call runs under callTimeout. A read that fails
// transiently is tried readAttempts times, waiting a jittered delay in
// [d/2, d] between tries, d doubling from retryBackoff. A write is sent
// once by this package: its outcome is unknown after a timeout, so the
// caller decides after reading again. The client itself resends a request
// that never reached the server at most clientRetries times.
const (
	callTimeout   = 5 * time.Second
	readAttempts  = 3
	retryBackoff  = 50 * time.Millisecond
	clientRetries = 3
	dialTimeout   = 5 * time.Second
)

// permanent etcd answers are not retried and are not ErrUnavailable.
var permanent = []error{
	rpctypes.ErrRequestTooLarge, rpctypes.ErrTooManyOps, rpctypes.ErrPermissionDenied,
	rpctypes.ErrAuthFailed, rpctypes.ErrInvalidAuthToken, rpctypes.ErrUserEmpty,
}

// translate names a failed call. The caller's own cancellation stays a
// context error; a known permanent answer stays as it is; anything else
// (no leader, timeout, lost connection) is ErrUnavailable.
func translate(ctx context.Context, op string, kind iam.Kind, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("etcd %s %s: %w", op, kind, err)
	}
	e := rpctypes.Error(err)
	for _, p := range permanent {
		if errors.Is(e, p) {
			return fmt.Errorf("etcd %s %s: %w", op, kind, err)
		}
	}
	return fmt.Errorf("%w: etcd %s %s: %w", store.ErrUnavailable, op, kind, err)
}

// call runs fn once under callTimeout.
func call[T any](ctx context.Context, op string, kind iam.Kind, fn func(context.Context) (T, error)) (T, error) {
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	r, err := fn(cctx)
	if err != nil {
		return r, translate(ctx, op, kind, err)
	}
	return r, nil
}

// read is call for a read: an ErrUnavailable is tried again, readAttempts
// tries in all.
func read[T any](ctx context.Context, op string, kind iam.Kind, fn func(context.Context) (T, error)) (T, error) {
	for attempt := 1; ; attempt++ {
		r, err := call(ctx, op, kind, fn)
		if !errors.Is(err, store.ErrUnavailable) || attempt == readAttempts {
			return r, err
		}
		d := retryBackoff << (attempt - 1)
		t := time.NewTimer(d/2 + rand.N(d/2+1))
		select {
		case <-ctx.Done():
			t.Stop()
			return r, fmt.Errorf("%w (stopped retrying: %w)", err, context.Cause(ctx))
		case <-t.C:
		}
	}
}
