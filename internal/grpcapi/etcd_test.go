package grpcapi_test

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.etcd.io/etcd/server/v3/embed"

	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/etcdstore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// embeddedEtcd is one etcd server shared by every test of the package,
// started by the first test that asks for it and stopped by TestMain.
var embeddedEtcd struct {
	once     sync.Once
	server   *embed.Etcd
	dir      string
	endpoint string
	err      error
	prefixes atomic.Int64
}

func TestMain(m *testing.M) {
	code := m.Run()
	if e := embeddedEtcd.server; e != nil {
		e.Close()
	}
	if embeddedEtcd.dir != "" {
		if err := os.RemoveAll(embeddedEtcd.dir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}

func startEtcd() (string, error) {
	dir, err := os.MkdirTemp("", "grpcapi-etcd")
	if err != nil {
		return "", err
	}
	embeddedEtcd.dir = dir
	cfg := embed.NewConfig()
	cfg.Dir = dir
	cfg.LogLevel = "error"
	local, err := url.Parse("http://127.0.0.1:0")
	if err != nil {
		return "", err
	}
	cfg.ListenClientUrls = []url.URL{*local}
	cfg.ListenPeerUrls = []url.URL{*local}
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return "", err
	}
	embeddedEtcd.server = e
	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		return "", fmt.Errorf("embedded etcd did not start in 30s")
	}
	return "http://" + e.Clients[0].Addr().String(), nil
}

// etcdBackend is etcdstore on the shared embedded etcd, under a key
// prefix of its own.
func etcdBackend(t *testing.T) store.Backend {
	t.Helper()
	embeddedEtcd.once.Do(func() { embeddedEtcd.endpoint, embeddedEtcd.err = startEtcd() })
	if embeddedEtcd.err != nil {
		t.Fatal(embeddedEtcd.err)
	}
	prefix := "/grpcapi-" + strconv.FormatInt(embeddedEtcd.prefixes.Add(1), 10)
	s, err := etcdstore.Open([]string{embeddedEtcd.endpoint}, nil, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

// etcdBackends are the backends a test runs on when it must cover the
// etcd store: memstore as the reference and etcdstore.
var etcdBackends = []struct {
	name string
	open func(t *testing.T) store.Backend
}{
	{"memstore", func(*testing.T) store.Backend { return memstore.New() }},
	{"etcdstore", etcdBackend},
}
