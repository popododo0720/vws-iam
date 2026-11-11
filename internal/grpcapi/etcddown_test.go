package grpcapi_test

import (
	"context"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"go.etcd.io/etcd/server/v3/embed"
	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/store/etcdstore"
)

// downCallBound is how long a handler may take to answer while etcd is
// down: three reads of at most 5 s each, with room to spare. A call that
// hangs ends in DEADLINE_EXCEEDED and fails the test.
const downCallBound = 30 * time.Second

// TestHandlerAnswersUnavailableWhenEtcdIsDown serves the gRPC API on an
// etcd store whose endpoint refuses connections, first one nothing ever
// listened on, then a real etcd server that is stopped: every call answers
// UNAVAILABLE/ServiceUnavailable within downCallBound, the same on a
// repeat, and the service reads its data again once etcd is back.
func TestHandlerAnswersUnavailableWhenEtcdIsDown(t *testing.T) {
	t.Run("nothing listening", func(t *testing.T) {
		e := newEnvOnEtcd(t, "http://"+freeAddr(t))
		wantUnavailable(t, e, "alice")
		wantUnavailable(t, e, "alice")
	})
	t.Run("stopped etcd", func(t *testing.T) {
		dir := t.TempDir()
		client, peer := "http://"+freeAddr(t), "http://"+freeAddr(t)
		stop := startRestartableEtcd(t, dir, client, peer)
		e := newEnvOnEtcd(t, client)
		u := e.createUser(t, t.Context(), "alice")
		stop()
		wantUnavailable(t, e, "alice")
		wantUnavailable(t, e, "alice")
		startRestartableEtcd(t, dir, client, peer)
		ctx, cancel := context.WithTimeout(t.Context(), downCallBound)
		defer cancel()
		got, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: u.GetName()})
		if err != nil {
			t.Fatalf("get after etcd restarted: %v", err)
		}
		if got.GetStatus().GetUniqueId() != u.GetStatus().GetUniqueId() {
			t.Fatalf("user after restart %v, want %v", got, u)
		}
	})
}

func wantUnavailable(t *testing.T, e *env, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), downCallBound)
	defer cancel()
	_, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: userName(name)})
	wantAWS(t, err, codes.Unavailable, "ServiceUnavailable")
}

func newEnvOnEtcd(t *testing.T, endpoint string) *env {
	t.Helper()
	s, err := etcdstore.Open([]string{endpoint}, nil, "/iam")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	now := time.Now().UTC()
	return newEnvOn(t, s, &now)
}

// freeAddr is a loopback address nothing listens on once it returns.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// startRestartableEtcd runs an embedded etcd server on dir with fixed URLs, so a
// second start on the same dir is the same member coming back. It returns
// the stop function the test cleanup also runs.
func startRestartableEtcd(t *testing.T, dir, client, peer string) func() {
	t.Helper()
	cu, err := url.Parse(client)
	if err != nil {
		t.Fatal(err)
	}
	pu, err := url.Parse(peer)
	if err != nil {
		t.Fatal(err)
	}
	cfg := embed.NewConfig()
	cfg.Dir = dir
	cfg.LogLevel = "error"
	cfg.ListenClientUrls, cfg.AdvertiseClientUrls = []url.URL{*cu}, []url.URL{*cu}
	cfg.ListenPeerUrls, cfg.AdvertisePeerUrls = []url.URL{*pu}, []url.URL{*pu}
	cfg.InitialCluster = cfg.InitialClusterFromName(cfg.Name)
	srv, err := embed.StartEtcd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stop := sync.OnceFunc(srv.Close)
	t.Cleanup(stop)
	select {
	case <-srv.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		t.Fatal("embedded etcd did not start")
	}
	return stop
}
