package grpcapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// update reads key, checks etag, applies fn, bumps the generation and
// writes with compare-and-swap. Without an etag a lost race is retried on
// fresh state; with one it is ETAG_MISMATCH. With allowMissing a missing
// object is made by create instead.
func update[T iam.Object](ctx context.Context, b store.Backend, key, etag string, allowMissing bool, bump func(*T), fn func(*T) error, create func() (T, error)) (store.Versioned[T], bool, error) {
	for attempt := 0; ; attempt++ {
		cur, err := store.Get[T](ctx, b, key)
		if errors.Is(err, store.ErrNotFound) && allowMissing && create != nil {
			obj, err := create()
			if err != nil {
				return cur, false, err
			}
			v, err := store.Create(ctx, b, obj)
			return store.Versioned[T]{Object: obj, Version: v}, true, err
		}
		if err != nil {
			return cur, false, err
		}
		if err := checkEtag(etag, cur.Version); err != nil {
			return cur, false, err
		}
		if err := fn(&cur.Object); err != nil {
			return cur, false, err
		}
		bump(&cur.Object)
		v, err := store.Update(ctx, b, cur.Object, cur.Version)
		if errors.Is(err, store.ErrConflict) && etag == "" && attempt < 8 {
			continue
		}
		if errors.Is(err, store.ErrConflict) {
			return cur, false, checkEtag("stale", "")
		}
		cur.Version = v
		return cur, false, err
	}
}

// remove deletes key after etag and dependency checks. A missing object is
// fine with allowMissing.
func remove[T iam.Object](ctx context.Context, b store.Backend, key, etag string, allowMissing bool, check func(T) error) (store.Versioned[T], bool, error) {
	cur, err := store.Get[T](ctx, b, key)
	if errors.Is(err, store.ErrNotFound) && allowMissing {
		return cur, false, nil
	}
	if err != nil {
		return cur, false, err
	}
	if err := checkEtag(etag, cur.Version); err != nil {
		return cur, false, err
	}
	if r, ok := any(cur.Object).(iam.Renamable); ok && r.Rename().Renaming() {
		return cur, false, fmt.Errorf("%s %q: %w", cur.Object.Kind(), key, store.ErrRenaming)
	}
	if check != nil {
		if err := check(cur.Object); err != nil {
			return cur, false, err
		}
	}
	if err := store.Delete[T](ctx, b, key, cur.Version); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return cur, false, checkEtag("stale", "")
		}
		return cur, false, err
	}
	return cur, true, nil
}

// adopt resolves a create whose object already exists: if it was made by
// the same request id (a crash before the operation was recorded), the
// create is answered from the stored object.
func adopt(requestID string, m iam.Meta, err error) error {
	if errors.Is(err, store.ErrExists) && requestID != "" && m.RequestID == requestID {
		return nil
	}
	return err
}

type enveloped interface {
	iam.Object
	Envelope() iam.Meta
}

// create stores obj (unless validateOnly), adopting an object left by an
// earlier attempt of the same request id.
func create[T enveloped](ctx context.Context, b store.Backend, obj T, requestID string, validateOnly bool) (store.Versioned[T], error) {
	if err := obj.Validate(); err != nil {
		return store.Versioned[T]{}, err
	}
	if validateOnly {
		return store.Versioned[T]{Object: obj}, nil
	}
	ver, err := store.Create(ctx, b, obj)
	if err == nil {
		return store.Versioned[T]{Object: obj, Version: ver}, nil
	}
	cur, gerr := store.Get[T](ctx, b, obj.Key())
	if gerr != nil || adopt(requestID, cur.Object.Envelope(), err) != nil {
		return cur, err
	}
	return cur, nil
}

// mutateOrValidate runs update, or with validateOnly applies fn to a copy.
func mutateOrValidate[T iam.Object](ctx context.Context, b store.Backend, key, etag string, validateOnly, allowMissing bool, bump func(*T), fn func(*T) error, mk func() (T, error)) (store.Versioned[T], error) {
	if validateOnly {
		v, err := store.Get[T](ctx, b, key)
		if err == nil {
			err = checkEtag(etag, v.Version)
		}
		if err == nil {
			err = fn(&v.Object)
		}
		return v, err
	}
	v, _, err := update(ctx, b, key, etag, allowMissing, bump, fn, mk)
	return v, err
}

// errNoop aborts an update that has nothing to do.
var errNoop = errors.New("no change")
