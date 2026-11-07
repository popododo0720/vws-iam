package sts_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// countingBackend counts store calls per kind and verb.
type countingBackend struct {
	store.Backend
	creates, gets, lists atomic.Int64
}

func (c *countingBackend) List(ctx context.Context, kind iam.Kind) ([]store.Entry, error) {
	c.lists.Add(1)
	return c.Backend.List(ctx, kind)
}

func (c *countingBackend) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	c.creates.Add(1)
	return c.Backend.Create(ctx, kind, key, spec)
}

func (c *countingBackend) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	c.gets.Add(1)
	return c.Backend.Get(ctx, kind, key)
}

// BenchmarkGetSessionTokenKeyIndex measures what the session key index
// entry (#188) adds to issuing: GetSessionToken with and without the
// index, on memstore and on kubestore against a real kube-apiserver
// (skipped without KUBEBUILDER_ASSETS), with the store writes and reads
// each issue makes, and the index create alone as the baseline of what
// one store write costs on that backend. On an otherwise idle
// kube-apiserver the issue's List of groups after the previous issue's
// write waits for the watch cache to reach the new etcd revision
// (consistent list from cache), which a busy cluster pays anyway.
func BenchmarkGetSessionTokenKeyIndex(b *testing.B) {
	benchIssue(b, "memstore", func(testing.TB) store.Backend { return memstore.New() })
	b.Run("apiserver", func(b *testing.B) { benchIssue(b, "kubestore", apiServer(b)) })
}

func benchIssue(b *testing.B, name string, open func(testing.TB) store.Backend) {
	b.Run(name+"/index-create-only", func(b *testing.B) {
		bk := open(b)
		ctx := context.Background()
		exp := time.Now().Add(time.Hour)
		for b.Loop() {
			id, err := accesskey.NewKeyID("ASIA")
			if err != nil {
				b.Fatal(err)
			}
			if _, err := store.Create(ctx, bk, iam.KeyIndex{ID: id, Project: acct, Expires: exp}); err != nil {
				b.Fatal(err)
			}
		}
	})
	for _, indexed := range []bool{false, true} {
		label := name + "/no-index"
		if indexed {
			label = name + "/index"
		}
		b.Run(label, func(b *testing.B) {
			cb := &countingBackend{Backend: open(b)}
			e := keyInfoSetupOn(b, cb)
			sb := store.Scoped(cb, acct)
			var opts []sts.Option
			if indexed {
				opts = append(opts, sts.WithKeyIndex(cb))
			}
			svc := sts.New(sb, e.keys, authz.New(sb, acct, e.clk.now), acct, e.clk.now, opts...)
			c := e.resolve(b, "nobody")
			ctx := context.Background()
			cb.creates.Store(0)
			cb.gets.Store(0)
			cb.lists.Store(0)
			for b.Loop() {
				if _, err := svc.GetSessionToken(ctx, c, time.Hour, sts.MFA{}); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(cb.creates.Load())/float64(b.N), "creates/op")
			b.ReportMetric(float64(cb.gets.Load())/float64(b.N), "gets/op")
			b.ReportMetric(float64(cb.lists.Load())/float64(b.N), "lists/op")
		})
	}
}
