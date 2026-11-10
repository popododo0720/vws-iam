// Package etcdstore is the store.Backend on etcd. Each object is one key
// under prefix/kind/folded-key; its value holds the key as written and the
// spec, and its mod_revision is the store version. A conditional write is
// one etcd transaction that compares both objects' mod_revision, so no
// fence is needed.
package etcdstore

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// Store is a store.Backend on an etcd client.
type Store struct {
	c      *clientv3.Client
	prefix string
}

// New wraps a client; every key lives under prefix.
func New(c *clientv3.Client, prefix string) *Store {
	return &Store{c: c, prefix: prefix}
}

// Open connects to endpoints (tlsConfig nil: plaintext) with the call
// bounds above. The caller closes the client with Close.
func Open(endpoints []string, tlsConfig *tls.Config, prefix string) (*Store, error) {
	c, err := clientv3.New(clientv3.Config{
		Endpoints:             endpoints,
		TLS:                   tlsConfig,
		DialTimeout:           dialTimeout,
		DialKeepAliveTime:     30 * time.Second,
		DialKeepAliveTimeout:  10 * time.Second,
		MaxUnaryRetries:       clientRetries,
		BackoffWaitBetween:    retryBackoff,
		BackoffJitterFraction: 0.5,
		Logger:                zap.NewNop(),
	})
	if err != nil {
		return nil, fmt.Errorf("etcd client: %w", err)
	}
	return New(c, prefix), nil
}

// Close closes the client.
func (s *Store) Close() error {
	if err := s.c.Close(); err != nil {
		return fmt.Errorf("etcd close: %w", err)
	}
	return nil
}

// value is what one etcd key holds.
type value struct {
	Key  string          `json:"key"`
	Spec json.RawMessage `json:"spec"`
}

func (s *Store) kindPrefix(kind iam.Kind) string { return s.prefix + "/" + string(kind) + "/" }

func (s *Store) path(kind iam.Kind, key string) string { return s.kindPrefix(kind) + store.Fold(key) }

func marshal(key string, spec []byte) (string, error) {
	b, err := json.Marshal(value{Key: key, Spec: spec})
	if err != nil {
		return "", fmt.Errorf("encode %s: %w", key, err)
	}
	return string(b), nil
}

func entry(raw []byte, rev int64) (store.Entry, error) {
	var v value
	if err := json.Unmarshal(raw, &v); err != nil {
		return store.Entry{}, fmt.Errorf("decode etcd value: %w", err)
	}
	return store.Entry{Key: v.Key, Spec: v.Spec, Version: strconv.FormatInt(rev, 10)}, nil
}

// revision parses a store version. A version that is not a revision
// matches no key: -1 is no mod_revision, and a missing key has 0.
func revision(version string) int64 {
	r, err := strconv.ParseInt(version, 10, 64)
	if err != nil || r <= 0 {
		return -1
	}
	return r
}

func (s *Store) get(ctx context.Context, kind iam.Kind, key string) (*clientv3.GetResponse, error) {
	return read(ctx, "get", kind, func(ctx context.Context) (*clientv3.GetResponse, error) {
		return s.c.Get(ctx, s.path(kind, key))
	})
}

// Create implements store.Backend.
func (s *Store) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	val, err := marshal(key, spec)
	if err != nil {
		return "", err
	}
	k := s.path(kind, key)
	r, err := call(ctx, "create", kind, func(ctx context.Context) (*clientv3.TxnResponse, error) {
		return s.c.Txn(ctx).If(clientv3.Compare(clientv3.CreateRevision(k), "=", 0)).
			Then(clientv3.OpPut(k, val)).Commit()
	})
	if err != nil {
		return "", err
	}
	if !r.Succeeded {
		return "", store.ErrExists
	}
	return strconv.FormatInt(r.Header.Revision, 10), nil
}

// Update implements store.Backend.
func (s *Store) Update(ctx context.Context, kind iam.Kind, key string, spec []byte, version string) (string, error) {
	return s.updateIf(ctx, kind, key, spec, version, nil)
}

// UpdateIf implements store.Backend: the version checks of key and pre
// and the write are one transaction.
func (s *Store) UpdateIf(
	ctx context.Context, kind iam.Kind, key string, spec []byte, version string, pre store.Pre,
) (string, error) {
	return s.updateIf(ctx, kind, key, spec, version, &pre)
}

// updateIf writes key at version, under pre when it is not nil. The key
// keeps the spelling it was created with, as in memstore.
func (s *Store) updateIf(
	ctx context.Context, kind iam.Kind, key string, spec []byte, version string, pre *store.Pre,
) (string, error) {
	cur, err := s.get(ctx, kind, key)
	if err != nil {
		return "", err
	}
	name := key
	if len(cur.Kvs) > 0 {
		e, err := entry(cur.Kvs[0].Value, cur.Kvs[0].ModRevision)
		if err != nil {
			return "", err
		}
		name = e.Key
	}
	val, err := marshal(name, spec)
	if err != nil {
		return "", err
	}
	k := s.path(kind, key)
	r, err := s.commit(ctx, "update", kind, k, version, pre, clientv3.OpPut(k, val))
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(r.Header.Revision, 10), nil
}

// commit runs op in one transaction that holds only while k is at
// version and pre's object at pre.Version. A refused transaction reads
// both back, so the error is the one memstore gives: ErrConflict for a
// broken precondition, else ErrNotFound for a missing key, else
// ErrConflict for a stale one.
func (s *Store) commit(
	ctx context.Context, opName string, kind iam.Kind, k, version string, pre *store.Pre, op clientv3.Op,
) (*clientv3.TxnResponse, error) {
	cmps := []clientv3.Cmp{clientv3.Compare(clientv3.ModRevision(k), "=", revision(version))}
	reads := []clientv3.Op{clientv3.OpGet(k, clientv3.WithCountOnly())}
	if pre != nil {
		pk := s.path(pre.Kind, pre.Key)
		cmps = append(cmps, clientv3.Compare(clientv3.ModRevision(pk), "=", revision(pre.Version)))
		reads = append(reads, clientv3.OpGet(pk, clientv3.WithKeysOnly()))
	}
	r, err := call(ctx, opName, kind, func(ctx context.Context) (*clientv3.TxnResponse, error) {
		return s.c.Txn(ctx).If(cmps...).Then(op).Else(reads...).Commit()
	})
	if err != nil {
		return nil, err
	}
	if r.Succeeded {
		return r, nil
	}
	if pre != nil {
		kvs := r.Responses[1].GetResponseRange().Kvs
		if len(kvs) == 0 || kvs[0].ModRevision != revision(pre.Version) {
			return nil, store.ErrConflict
		}
	}
	if r.Responses[0].GetResponseRange().Count == 0 {
		return nil, store.ErrNotFound
	}
	return nil, store.ErrConflict
}

// Get implements store.Backend.
func (s *Store) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	r, err := s.get(ctx, kind, key)
	if err != nil {
		return store.Entry{}, err
	}
	if len(r.Kvs) == 0 {
		return store.Entry{}, store.ErrNotFound
	}
	return entry(r.Kvs[0].Value, r.Kvs[0].ModRevision)
}

// List implements store.Backend.
func (s *Store) List(ctx context.Context, kind iam.Kind) ([]store.Entry, error) {
	out, _, err := s.ListPage(ctx, kind, 0, "")
	return out, err
}

// ListPage implements store.Pager: keys in folded order, the token is the
// last folded key of the previous page.
func (s *Store) ListPage(ctx context.Context, kind iam.Kind, limit int64, cont string) ([]store.Entry, string, error) {
	p := s.kindPrefix(kind)
	from := p
	if cont != "" {
		from = p + cont + "\x00"
	}
	r, err := read(ctx, "list", kind, func(ctx context.Context) (*clientv3.GetResponse, error) {
		return s.c.Get(ctx, from, clientv3.WithRange(clientv3.GetPrefixRangeEnd(p)),
			clientv3.WithSort(clientv3.SortByKey, clientv3.SortAscend), clientv3.WithLimit(max(limit, 0)))
	})
	if err != nil {
		return nil, "", err
	}
	out := make([]store.Entry, 0, len(r.Kvs))
	for _, kv := range r.Kvs {
		e, err := entry(kv.Value, kv.ModRevision)
		if err != nil {
			return nil, "", err
		}
		out = append(out, e)
	}
	if !r.More || len(out) == 0 {
		return out, "", nil
	}
	return out, store.Fold(out[len(out)-1].Key), nil
}

// Delete implements store.Backend.
func (s *Store) Delete(ctx context.Context, kind iam.Kind, key, version string) error {
	k := s.path(kind, key)
	if version != "" {
		_, err := s.commit(ctx, "delete", kind, k, version, nil, clientv3.OpDelete(k))
		return err
	}
	r, err := call(ctx, "delete", kind, func(ctx context.Context) (*clientv3.DeleteResponse, error) {
		return s.c.Delete(ctx, k)
	})
	if err != nil {
		return err
	}
	if r.Deleted == 0 {
		return store.ErrNotFound
	}
	return nil
}

// DeleteIf implements store.Backend like UpdateIf.
func (s *Store) DeleteIf(ctx context.Context, kind iam.Kind, key, version string, pre store.Pre) error {
	if version == "" {
		return store.ErrNoVersion
	}
	k := s.path(kind, key)
	_, err := s.commit(ctx, "delete", kind, k, version, &pre, clientv3.OpDelete(k))
	return err
}
