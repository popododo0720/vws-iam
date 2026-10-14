// Package store defines the IAM repository. A Backend stores opaque specs
// per kind with optimistic concurrency; the typed helpers encode domain
// objects. memstore and kubestore are the two backends, and storetest is
// the suite both pass.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// Errors every backend returns.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrConflict = errors.New("version conflict")
)

// Entry is one stored spec and its version.
type Entry struct {
	Key     string
	Spec    []byte
	Version string
}

// Backend stores JSON specs. Keys compare case-insensitively.
type Backend interface {
	// Create stores a new key and fails with ErrExists if it is taken.
	Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (version string, err error)
	// Update replaces a key's spec if its version is still version.
	Update(ctx context.Context, kind iam.Kind, key string, spec []byte, version string) (string, error)
	Get(ctx context.Context, kind iam.Kind, key string) (Entry, error)
	// List returns every entry of kind ordered by key.
	List(ctx context.Context, kind iam.Kind) ([]Entry, error)
	// Delete removes key; a non-empty version must still match.
	Delete(ctx context.Context, kind iam.Kind, key, version string) error
}

// Fold is the canonical form of a key: IAM names are case-insensitive.
func Fold(key string) string { return strings.ToLower(key) }

// Versioned is a decoded object with the version it was read at.
type Versioned[T iam.Object] struct {
	Object  T
	Version string
}

func encode(obj iam.Object) ([]byte, error) {
	if err := obj.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", obj.Kind(), err)
	}
	return b, nil
}

func decode[T iam.Object](e Entry) (Versioned[T], error) {
	var v Versioned[T]
	if err := json.Unmarshal(e.Spec, &v.Object); err != nil {
		return v, fmt.Errorf("decode %s: %w", e.Key, err)
	}
	v.Version = e.Version
	return v, nil
}

// Create validates and stores a new object.
func Create[T iam.Object](ctx context.Context, b Backend, obj T) (string, error) {
	spec, err := encode(obj)
	if err != nil {
		return "", err
	}
	return b.Create(ctx, obj.Kind(), obj.Key(), spec)
}

// Update validates and replaces an object read at version.
func Update[T iam.Object](ctx context.Context, b Backend, obj T, version string) (string, error) {
	spec, err := encode(obj)
	if err != nil {
		return "", err
	}
	return b.Update(ctx, obj.Kind(), obj.Key(), spec, version)
}

// Get reads one object.
func Get[T iam.Object](ctx context.Context, b Backend, key string) (Versioned[T], error) {
	var zero T
	e, err := b.Get(ctx, zero.Kind(), key)
	if err != nil {
		return Versioned[T]{}, err
	}
	return decode[T](e)
}

// List reads every object of T's kind.
func List[T iam.Object](ctx context.Context, b Backend) ([]Versioned[T], error) {
	var zero T
	es, err := b.List(ctx, zero.Kind())
	if err != nil {
		return nil, err
	}
	out := make([]Versioned[T], 0, len(es))
	for _, e := range es {
		v, err := decode[T](e)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// Delete removes an object; version may be empty to skip the check.
func Delete[T iam.Object](ctx context.Context, b Backend, key, version string) error {
	var zero T
	return b.Delete(ctx, zero.Kind(), key, version)
}

// Mutate reads key, applies fn, and writes the result, retrying on a
// version conflict so a lost race reapplies fn to fresh state.
func Mutate[T iam.Object](ctx context.Context, b Backend, key string, fn func(*T) error) (T, error) {
	for attempt := 0; ; attempt++ {
		cur, err := Get[T](ctx, b, key)
		if err != nil {
			var zero T
			return zero, err
		}
		if err := fn(&cur.Object); err != nil {
			var zero T
			return zero, err
		}
		_, err = Update(ctx, b, cur.Object, cur.Version)
		if errors.Is(err, ErrConflict) && attempt < 8 {
			continue
		}
		return cur.Object, err
	}
}
