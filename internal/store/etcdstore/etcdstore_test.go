package etcdstore_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/etcdstore"
	"github.com/popododo0720/vws-iam/internal/store/storetest"
)

// endpoint is the client URL of the embedded etcd server every test shares;
// each test gets its own key prefix.
var endpoint string

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	dir, err := os.MkdirTemp("", "etcdstore")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	cfg := embed.NewConfig()
	cfg.Dir = dir
	cfg.LogLevel = "error"
	local, err := url.Parse("http://127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cfg.ListenClientUrls = []url.URL{*local}
	cfg.ListenPeerUrls = []url.URL{*local}
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer e.Close()
	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		fmt.Fprintln(os.Stderr, "embedded etcd did not start")
		return 1
	}
	endpoint = "http://" + e.Clients[0].Addr().String()
	return m.Run()
}

var prefixes atomic.Int64

// open connects a store under a fresh prefix and the raw client beside it.
func open(t *testing.T) (*etcdstore.Store, *clientv3.Client, string) {
	t.Helper()
	prefix := "/test-" + strconv.FormatInt(prefixes.Add(1), 10)
	s, err := etcdstore.Open([]string{endpoint}, nil, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, c, prefix
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Backend {
		s, _, _ := open(t)
		return s
	})
}

func TestScopedConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Backend {
		s, _, _ := open(t)
		return store.Scoped(s, "proj-a")
	})
}

// TestConditionalWriteRacesPreconditionWriter runs a conditional key write
// against a concurrent write of its precondition user, many times. Etcd
// revisions are one global order, so a key write that committed must sit
// before the user write that moved the precondition, and a refused one
// must leave the key as it was.
func TestConditionalWriteRacesPreconditionWriter(t *testing.T) {
	s, _, _ := open(t)
	ctx := context.Background()
	for i := range 50 {
		name := "user" + strconv.Itoa(i)
		id := "AKIA" + strings.Repeat("A", 14) + string(rune('A'+i/26)) + string(rune('A'+i%26))
		uv, err := store.Create(ctx, s, iam.User{Name: name, ID: "AIDA" + strconv.Itoa(i)})
		if err != nil {
			t.Fatal(err)
		}
		k := iam.AccessKey{
			ID: id, UserName: name, Status: iam.KeyActive,
			Secret: iam.Sealed{KeyID: "kek-1", Ciphertext: []byte{1}},
		}
		kv, err := store.Create(ctx, s, k)
		if err != nil {
			t.Fatal(err)
		}
		pre := store.Pre{Kind: iam.KindUser, Key: name, Version: uv}
		off := k
		off.Status = iam.KeyInactive
		start := make(chan struct{})
		var wg sync.WaitGroup
		var keyVer, userVer string
		var keyErr, userErr error
		wg.Go(func() {
			<-start
			if i%2 == 0 {
				keyVer, keyErr = store.UpdateIf(ctx, s, off, kv, pre)
			} else {
				keyErr = store.DeleteIf[iam.AccessKey](ctx, s, id, kv, pre)
			}
		})
		wg.Go(func() {
			<-start
			userVer, userErr = store.Update(ctx, s, iam.User{Name: name, ID: "AIDA" + strconv.Itoa(i), Path: "/moved/"}, uv)
		})
		close(start)
		wg.Wait()
		if userErr != nil {
			t.Fatalf("round %d: user write: %v", i, userErr)
		}
		got, getErr := store.Get[iam.AccessKey](ctx, s, id)
		switch {
		case errors.Is(keyErr, store.ErrConflict):
			if getErr != nil || got.Version != kv || got.Object.Status != iam.KeyActive {
				t.Fatalf("round %d: refused write changed the key: %v %+v", i, getErr, got)
			}
		case keyErr != nil:
			t.Fatalf("round %d: key write: %v", i, keyErr)
		case i%2 == 0:
			if rev(t, keyVer) >= rev(t, userVer) {
				t.Fatalf("round %d: key committed at %s after the user moved at %s", i, keyVer, userVer)
			}
		default:
			if !errors.Is(getErr, store.ErrNotFound) {
				t.Fatalf("round %d: deleted key still readable: %v", i, getErr)
			}
		}
	}
}

func rev(t *testing.T, v string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSecretIsSealedInEtcd creates an access key through the service and
// reads every raw etcd value: none holds the plaintext secret, and the key
// value carries the KEK id.
func TestSecretIsSealedInEtcd(t *testing.T) {
	s, c, prefix := open(t)
	ctx := context.Background()
	if _, err := store.Create(ctx, s, iam.User{Name: "alice", ID: "AIDAalice"}); err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	if _, err := rand.NewChaCha8([32]byte{1}).Read(kek); err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyring("kek-1", map[string][]byte{"kek-1": kek})
	if err != nil {
		t.Fatal(err)
	}
	svc := accesskey.New(s, s, "proj-a", ring, nil)
	cred, err := svc.Create(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Get(ctx, prefix+"/", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
	sealed := false
	for _, kv := range r.Kvs {
		if strings.Contains(string(kv.Value), cred.Secret) {
			t.Fatalf("etcd value %s holds the plaintext secret", kv.Key)
		}
		if strings.Contains(string(kv.Key), "/"+string(iam.KindAccessKey)+"/") {
			sealed = strings.Contains(string(kv.Value), `"keyId":"kek-1"`)
		}
	}
	if !sealed {
		t.Fatalf("no access key value with a KEK id among %d values", len(r.Kvs))
	}
}

// TestCallsAreBoundedWhenEtcdIsDown points a store at a port nothing
// listens on: every call returns ErrUnavailable within its timeout and
// retries instead of hanging.
func TestCallsAreBoundedWhenEtcdIsDown(t *testing.T) {
	s, err := etcdstore.Open([]string{"http://127.0.0.1:1"}, nil, "/down")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	begin := time.Now()
	if _, err := s.Get(ctx, iam.KindUser, "alice"); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("get: %v, want ErrUnavailable", err)
	}
	if _, err := s.Create(ctx, iam.KindUser, "alice", []byte(`{}`)); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("create: %v, want ErrUnavailable", err)
	}
	if d := time.Since(begin); d > time.Minute {
		t.Fatalf("calls took %s", d)
	}
}

// TestCallerCancellationIsNotUnavailable keeps the caller's own context
// error apart from a backend failure.
func TestCallerCancellationIsNotUnavailable(t *testing.T) {
	s, _, _ := open(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Get(ctx, iam.KindUser, "alice")
	if !errors.Is(err, context.Canceled) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("get with a canceled context: %v", err)
	}
}
