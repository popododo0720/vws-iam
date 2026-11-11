package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/etcd/server/v3/embed"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
)

// writeCredentials fills a directory the way systemd fills
// $CREDENTIALS_DIRECTORY for vws-iam: an etcd client certificate from ca,
// the CA and a one-key KEK.
func writeCredentials(t *testing.T, ca testCA) string {
	t.Helper()
	dir := t.TempDir()
	cert, key := ca.leaf(t, "vws-iam", x509.ExtKeyUsageClientAuth)
	kek := make([]byte, 32)
	if _, err := rand.NewChaCha8([32]byte{1}).Read(kek); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		credEtcdCA: ca.pem, credEtcdCert: cert, credEtcdKey: key,
		credKEKPrefix + "active": []byte("k1\n"), credKEKPrefix + "k1": []byte(base64.StdEncoding.EncodeToString(kek)),
	} {
		writeFile(t, filepath.Join(dir, name), b)
	}
	return dir
}

// startEtcd starts an embedded etcd that serves clients only over mutual
// TLS and returns its endpoint and the credentials of a client it trusts.
func startEtcd(t *testing.T) (endpoint, credDir string) {
	t.Helper()
	ca := newCA(t, "etcd-ca")
	tlsDir := t.TempDir()
	srvCert, srvKey := ca.leaf(t, "localhost", x509.ExtKeyUsageServerAuth)
	cfg := embed.NewConfig()
	cfg.Dir = t.TempDir()
	cfg.LogLevel = "error"
	cfg.ClientTLSInfo.CertFile = filepath.Join(tlsDir, "server.pem")
	cfg.ClientTLSInfo.KeyFile = filepath.Join(tlsDir, "server-key.pem")
	cfg.ClientTLSInfo.TrustedCAFile = filepath.Join(tlsDir, "ca.pem")
	cfg.ClientTLSInfo.ClientCertAuth = true
	writeFile(t, cfg.ClientTLSInfo.CertFile, srvCert)
	writeFile(t, cfg.ClientTLSInfo.KeyFile, srvKey)
	writeFile(t, cfg.ClientTLSInfo.TrustedCAFile, ca.pem)
	client, peer := url.URL{Scheme: "https", Host: "127.0.0.1:0"}, url.URL{Scheme: "http", Host: "127.0.0.1:0"}
	cfg.ListenClientUrls, cfg.ListenPeerUrls = []url.URL{client}, []url.URL{peer}
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		t.Fatal("embedded etcd did not start")
	}
	return "https://" + e.Clients[0].Addr().String(), writeCredentials(t, ca)
}

func credEnv(dir string, extra map[string]string) func(string) string {
	m := map[string]string{envCredentials: dir}
	for k, v := range extra {
		m[k] = v
	}
	return envOf(m)
}

// TestEtcdStoreServes: vws-iam -store etcd starts against etcd over
// mutual TLS and answers health checks.
func TestEtcdStoreServes(t *testing.T) {
	endpoint, creds := startEtcd(t)
	addr := freeAddr(t)
	args := []string{"-etcd-endpoints", endpoint, "-health-listen=", "-listen", addr}
	cfg, err := parseConfig(args, io.Discard, credEnv(creds, nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	cctx, ccancel := context.WithTimeout(ctx, 30*time.Second)
	defer ccancel()
	res, err := healthpb.NewHealthClient(conn).Check(cctx, &healthpb.HealthCheckRequest{}, grpc.WaitForReady(true))
	if err != nil || res.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("health: %v %v", res.GetStatus(), err)
	}
}

// TestMissingCredentialFailsStartup: each missing credential file stops
// startup with an error naming that file, before etcd is dialed.
func TestMissingCredentialFailsStartup(t *testing.T) {
	for _, name := range []string{credEtcdCA, credEtcdCert, credEtcdKey, credKEKPrefix + "active", credKEKPrefix + "k1"} {
		t.Run(name, func(t *testing.T) {
			dir := writeCredentials(t, newCA(t, "etcd-ca"))
			if err := os.Remove(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			args := []string{"-etcd-endpoints", "https://127.0.0.1:1", "-health-listen=", "-listen", freeAddr(t)}
			cfg, err := parseConfig(args, io.Discard, credEnv(dir, nil))
			if err != nil {
				t.Fatal(err)
			}
			err = run(t.Context(), cfg)
			if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, name)) {
				t.Fatalf("run without %s: %v", name, err)
			}
			if strings.Contains(err.Error(), "PRIVATE KEY-----") {
				t.Fatalf("error carries key material: %v", err)
			}
		})
	}
}

type replica struct {
	b    store.Backend
	keys *secret.Keyring
}

// startReplica builds one vws-iam process's store and keyring from the
// unit's flags and credentials, as run() does.
func startReplica(t *testing.T, endpoint, creds string) replica {
	t.Helper()
	args := []string{"-etcd-endpoints", endpoint, "-listen", "0.0.0.0:9095", "-insecure-plaintext"}
	cfg, err := parseConfig(args, io.Discard, credEnv(creds, nil))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, closeStore, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeStore(); err != nil {
			t.Error(err)
		}
	})
	return replica{b: b, keys: keys}
}

func (r replica) keySvc(project string) *accesskey.Service {
	return accesskey.New(store.Scoped(r.b, project), r.b, project, r.keys, nil)
}

// TestReplicasShareDurableState is #110 on etcd: two replicas on one etcd
// see each other's writes, and a restarted replica still sees them.
func TestReplicasShareDurableState(t *testing.T) {
	endpoint, creds := startEtcd(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	const project = "acme"
	a := startReplica(t, endpoint, creds)
	bRep := startReplica(t, endpoint, creds)

	user := iam.User{Name: "Alice", ID: iam.NewUniqueID("AIDA"), Created: time.Now().UTC()}
	if _, err := store.Create(ctx, store.Scoped(a.b, project), user); err != nil {
		t.Fatalf("replica A create user: %v", err)
	}
	cred, err := a.keySvc(project).Create(ctx, "Alice")
	if err != nil {
		t.Fatalf("replica A create key: %v", err)
	}

	got, err := store.Get[iam.User](ctx, store.Scoped(bRep.b, project), "alice")
	if err != nil || got.Object.ID != user.ID {
		t.Fatalf("replica B does not see the user written on A: %v", err)
	}
	sign, err := bRep.keySvc(project).GetSigningCredential(ctx, cred.AccessKeyID)
	if err != nil || sign.Secret != cred.Secret {
		t.Fatalf("replica B cannot sign with the key created on A: %v", err)
	}
	// A stale write from A after B changed the user is a conflict, not a
	// lost update.
	changed := got.Object
	changed.Path = "/b/"
	if _, err := store.Update(ctx, store.Scoped(bRep.b, project), changed, got.Version); err != nil {
		t.Fatalf("replica B update: %v", err)
	}
	_, err = store.Update(ctx, store.Scoped(a.b, project), got.Object, got.Version)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale write from replica A: got %v, want ErrConflict", err)
	}

	// Restart: a new process reads the same state.
	c := startReplica(t, endpoint, creds)
	if _, err := store.Get[iam.User](ctx, store.Scoped(c.b, project), "ALICE"); err != nil {
		t.Fatalf("restarted replica lost the user: %v", err)
	}
	keys, err := c.keySvc(project).List(ctx, "Alice")
	if err != nil || len(keys) != 1 || keys[0].ID != cred.AccessKeyID {
		t.Fatalf("restarted replica lost the access key: %v %d", err, len(keys))
	}
	if err := c.keySvc(project).Delete(ctx, "Alice", cred.AccessKeyID); err != nil {
		t.Fatalf("restarted replica delete key: %v", err)
	}
	if _, err := a.keySvc(project).GetSigningCredential(ctx, cred.AccessKeyID); err == nil {
		t.Fatal("replica A still signs with a key deleted on another replica")
	}
}

// TestBootstrapOnEtcd: vws-iam bootstrap imports the root key into etcd,
// a second run keeps it, and a serving replica signs with it.
func TestBootstrapOnEtcd(t *testing.T) {
	endpoint, creds := startEtcd(t)
	sec, err := accesskey.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	id, err := accesskey.NewKeyID("AKIA")
	if err != nil {
		t.Fatal(err)
	}
	root := map[string]string{envRootProject: "acme", envRootKeyID: id, envRootSecret: sec}
	cfg, err := parseConfig([]string{"bootstrap", "-etcd-endpoints", endpoint}, io.Discard, credEnv(creds, root))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := runBootstrap(t.Context(), cfg); err != nil {
			t.Fatalf("bootstrap: %v", err)
		}
	}
	got, err := startReplica(t, endpoint, creds).keySvc("acme").GetSigningCredential(t.Context(), id)
	if err != nil || !got.Root || got.Secret != sec {
		t.Fatalf("root key after bootstrap: %v root=%v", err, got.Root)
	}
}
