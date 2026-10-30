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
	// ErrUnavailable is a transient backend failure; the call may be retried.
	ErrUnavailable = errors.New("store unavailable")
	// ErrRenaming is a write of a user or group whose rename is in flight
	// (iam.RenameState). Only the rename coordinator writes it, through
	// CreateMarked and UpdateMarked; the caller may retry once the rename
	// finished.
	ErrRenaming = errors.New("entity is being renamed")
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
	// UpdateIf is Update that commits only while pre also holds: the key
	// write and the check of pre are one atomic step. If pre's object is
	// gone or no longer at pre.Version, or key is not at version, nothing
	// is written and the error is ErrConflict. A backend may advance pre's
	// version, but not its spec, as a side effect even when it refuses the
	// write (kubestore records a fence on it), so read pre again before the
	// next conditional write.
	UpdateIf(ctx context.Context, kind iam.Kind, key string, spec []byte, version string, pre Pre) (string, error)
	// DeleteIf is Delete under the same precondition. version is required.
	DeleteIf(ctx context.Context, kind iam.Kind, key, version string, pre Pre) error
}

// Pre is a precondition of a conditional write on another object: that
// object must still be at Version when the write commits. Every Update or
// Delete of the object that commits after the precondition was read makes
// a conditional write that has not committed yet fail with ErrConflict.
type Pre struct {
	Kind    iam.Kind
	Key     string
	Version string
}

// PreOf is the precondition that v is unchanged.
func PreOf[T iam.Object](v Versioned[T]) Pre {
	return Pre{Kind: v.Object.Kind(), Key: v.Object.Key(), Version: v.Version}
}

// ErrNoVersion is a DeleteIf without the version of the object to delete.
var ErrNoVersion = errors.New("conditional delete needs a version")

// Pager is an optional Backend capability: list a kind in pages. cont is
// "" for the first page; next is "" after the last one. Order across
// pages is the backend's; every entry that exists for the whole listing
// is returned once.
type Pager interface {
	ListPage(ctx context.Context, kind iam.Kind, limit int64, cont string) (page []Entry, next string, err error)
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

// frozen is ErrRenaming if obj is a user or group with a rename in flight.
func frozen(obj iam.Object) error {
	if r, ok := obj.(iam.Renamable); ok && r.Rename().Renaming() {
		return fmt.Errorf("%s %q: %w", obj.Kind(), obj.Key(), ErrRenaming)
	}
	return nil
}

// Create validates and stores a new object. An object with a rename in
// flight is refused with ErrRenaming (CreateMarked writes one).
func Create[T iam.Object](ctx context.Context, b Backend, obj T) (string, error) {
	if err := frozen(obj); err != nil {
		return "", err
	}
	spec, err := encode(obj)
	if err != nil {
		return "", err
	}
	return b.Create(ctx, obj.Kind(), obj.Key(), spec)
}

// Update validates and replaces an object read at version. An object
// read with a rename in flight is refused with ErrRenaming: a write that
// read it before the rename began fails its version check instead.
func Update[T iam.Object](ctx context.Context, b Backend, obj T, version string) (string, error) {
	if err := frozen(obj); err != nil {
		return "", err
	}
	spec, err := encode(obj)
	if err != nil {
		return "", err
	}
	return b.Update(ctx, obj.Kind(), obj.Key(), spec, version)
}

// UpdateIf validates and replaces an object read at version, only while
// pre holds (Backend.UpdateIf).
func UpdateIf[T iam.Object](ctx context.Context, b Backend, obj T, version string, pre Pre) (string, error) {
	if err := frozen(obj); err != nil {
		return "", err
	}
	spec, err := encode(obj)
	if err != nil {
		return "", err
	}
	return b.UpdateIf(ctx, obj.Kind(), obj.Key(), spec, version, pre)
}

// CreateMarked is Create without the rename guard. Only the rename
// coordinator calls it, to write an object that carries rename markers.
func CreateMarked[T iam.Renamable](ctx context.Context, b Backend, obj T) (string, error) {
	spec, err := encode(obj)
	if err != nil {
		return "", err
	}
	return b.Create(ctx, obj.Kind(), obj.Key(), spec)
}

// UpdateMarked is Update without the rename guard. Only the rename
// coordinator calls it.
func UpdateMarked[T iam.Renamable](ctx context.Context, b Backend, obj T, version string) (string, error) {
	spec, err := encode(obj)
	if err != nil {
		return "", err
	}
	return b.Update(ctx, obj.Kind(), obj.Key(), spec, version)
}

// Visible drops the new copy of an uncommitted rename from vs: an object
// renamed from a name whose object is still listed with RenameTo naming
// it. Until the old object is deleted it is the one that counts, so a
// listing shows each user or group once.
func Visible[T iam.Renamable](vs []Versioned[T]) []Versioned[T] {
	to := map[string]string{}
	for _, v := range vs {
		if r := v.Object.Rename(); r.RenameTo != "" {
			to[Fold(v.Object.Key())] = Fold(r.RenameTo)
		}
	}
	if len(to) == 0 {
		return vs
	}
	out := make([]Versioned[T], 0, len(vs))
	for _, v := range vs {
		if from := v.Object.Rename().RenamedFrom; from != "" && to[Fold(from)] == Fold(v.Object.Key()) {
			continue
		}
		out = append(out, v)
	}
	return out
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

// ListPage reads one page of T's kind. A Backend without Pager returns
// everything as one page.
func ListPage[T iam.Object](ctx context.Context, b Backend, limit int64, cont string) ([]Versioned[T], string, error) {
	var zero T
	p, ok := b.(Pager)
	if !ok {
		if cont != "" {
			return nil, "", nil
		}
		vs, err := List[T](ctx, b)
		return vs, "", err
	}
	es, next, err := p.ListPage(ctx, zero.Kind(), limit, cont)
	if err != nil {
		return nil, "", err
	}
	out := make([]Versioned[T], 0, len(es))
	for _, e := range es {
		v, err := decode[T](e)
		if err != nil {
			return nil, "", err
		}
		out = append(out, v)
	}
	return out, next, nil
}

// Delete removes an object; version may be empty to skip the check.
func Delete[T iam.Object](ctx context.Context, b Backend, key, version string) error {
	var zero T
	return b.Delete(ctx, zero.Kind(), key, version)
}

// DeleteIf removes an object read at version, only while pre holds
// (Backend.DeleteIf).
func DeleteIf[T iam.Object](ctx context.Context, b Backend, key, version string, pre Pre) error {
	var zero T
	return b.DeleteIf(ctx, zero.Kind(), key, version, pre)
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
