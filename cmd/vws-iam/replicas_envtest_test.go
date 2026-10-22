package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
)

// startAPIServer starts envtest with deploy/crds, creates a namespace and
// returns a kubeconfig path for it. It skips without KUBEBUILDER_ASSETS.
func startAPIServer(t *testing.T) (kubeconfig, namespace string) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set")
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "deploy", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "vws-iam-"}}
	if err := c.Create(t.Context(), ns); err != nil {
		t.Fatal(err)
	}
	kubeconfig = filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(kubeconfig, env.KubeConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	return kubeconfig, ns.Name
}

// podEnv is the environment of a vws-iam pod as the vws-deploy chart runs
// it: the KEK from a Secret, the Kubernetes service env every pod gets,
// and the pod namespace from the downward API. No -namespace flag.
func podEnv(namespace string) func(string) string {
	return envOf(map[string]string{
		secret.EnvKEK:             base64.StdEncoding.EncodeToString(make([]byte, 32)),
		secret.EnvKEKID:           "k1",
		"KUBERNETES_SERVICE_HOST": "10.96.0.1",
		"POD_NAMESPACE":           namespace,
	})
}

type replica struct {
	b    store.Backend
	keys *secret.Keyring
}

// startReplica builds one vws-iam process's store and keyring from the
// chart's flags, as run() does.
func startReplica(t *testing.T, kubeconfig, namespace string) replica {
	t.Helper()
	cfg, err := parseConfig([]string{"-listen", "0.0.0.0:9095", "-kubeconfig", kubeconfig}, io.Discard, podEnv(namespace))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return replica{b: b, keys: keys}
}

func (r replica) keySvc(project string) *accesskey.Service {
	return accesskey.New(store.Scoped(r.b, project), r.b, project, r.keys, nil)
}

// TestReplicasShareDurableState is #110: two replicas started the way the
// chart starts them see each other's writes, and a restarted replica
// still sees them.
func TestReplicasShareDurableState(t *testing.T) {
	kubeconfig, namespace := startAPIServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	const project = "acme"
	a := startReplica(t, kubeconfig, namespace)
	bRep := startReplica(t, kubeconfig, namespace)

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
	if _, err := store.Update(ctx, store.Scoped(a.b, project), got.Object, got.Version); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale write from replica A: got %v, want ErrConflict", err)
	}

	// Restart: both processes go away; a new one reads the same state.
	c := startReplica(t, kubeconfig, namespace)
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
