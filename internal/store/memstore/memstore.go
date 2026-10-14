// Package memstore is the in-memory store.Backend for tests and -namespace="".
package memstore

import (
	"context"
	"sort"
	"strconv"
	"sync"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

type item struct {
	key     string
	spec    []byte
	version uint64
}

// Store keeps entries in a map.
type Store struct {
	mu   sync.Mutex
	next uint64
	data map[iam.Kind]map[string]item
}

// New returns an empty store.
func New() *Store { return &Store{data: map[iam.Kind]map[string]item{}} }

func (s *Store) bucket(kind iam.Kind) map[string]item {
	m := s.data[kind]
	if m == nil {
		m = map[string]item{}
		s.data[kind] = m
	}
	return m
}

func ver(v uint64) string { return strconv.FormatUint(v, 10) }

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// Create implements store.Backend.
func (s *Store) Create(_ context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.bucket(kind)
	if _, ok := m[store.Fold(key)]; ok {
		return "", store.ErrExists
	}
	s.next++
	m[store.Fold(key)] = item{key: key, spec: clone(spec), version: s.next}
	return ver(s.next), nil
}

// Update implements store.Backend.
func (s *Store) Update(_ context.Context, kind iam.Kind, key string, spec []byte, version string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.bucket(kind)
	it, ok := m[store.Fold(key)]
	if !ok {
		return "", store.ErrNotFound
	}
	if ver(it.version) != version {
		return "", store.ErrConflict
	}
	s.next++
	m[store.Fold(key)] = item{key: it.key, spec: clone(spec), version: s.next}
	return ver(s.next), nil
}

// Get implements store.Backend.
func (s *Store) Get(_ context.Context, kind iam.Kind, key string) (store.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.bucket(kind)[store.Fold(key)]
	if !ok {
		return store.Entry{}, store.ErrNotFound
	}
	return store.Entry{Key: it.key, Spec: clone(it.spec), Version: ver(it.version)}, nil
}

// List implements store.Backend.
func (s *Store) List(_ context.Context, kind iam.Kind) ([]store.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.bucket(kind)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]store.Entry, 0, len(keys))
	for _, k := range keys {
		it := m[k]
		out = append(out, store.Entry{Key: it.key, Spec: clone(it.spec), Version: ver(it.version)})
	}
	return out, nil
}

// ListPage implements store.Pager: keys in order, the token is the last
// folded key of the previous page.
func (s *Store) ListPage(ctx context.Context, kind iam.Kind, limit int64, cont string) ([]store.Entry, string, error) {
	all, err := s.List(ctx, kind)
	if err != nil {
		return nil, "", err
	}
	i := sort.Search(len(all), func(i int) bool { return store.Fold(all[i].Key) > cont })
	if cont == "" {
		i = 0
	}
	all = all[i:]
	if limit <= 0 || int64(len(all)) <= limit {
		return all, "", nil
	}
	page := all[:limit]
	return page, store.Fold(page[len(page)-1].Key), nil
}

// Delete implements store.Backend.
func (s *Store) Delete(_ context.Context, kind iam.Kind, key, version string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.bucket(kind)
	it, ok := m[store.Fold(key)]
	if !ok {
		return store.ErrNotFound
	}
	if version != "" && ver(it.version) != version {
		return store.ErrConflict
	}
	delete(m, store.Fold(key))
	return nil
}
