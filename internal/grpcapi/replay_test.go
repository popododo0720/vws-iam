package grpcapi_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestSharedReplayMemstore runs the #33 replica suite on one shared
// in-memory backend.
func TestSharedReplayMemstore(t *testing.T) {
	testSharedReplay(t, func(*testing.T) store.Backend { return memstore.New() })
}

// TestSharedReplayOnAPIServer runs the #33 replica suite on kubestore
// against a real kube-apiserver with deploy/crds (IamReplayEntry). It
// skips without KUBEBUILDER_ASSETS.
func TestSharedReplayOnAPIServer(t *testing.T) {
	testSharedReplay(t, apiServerBackends(t))
}

// apiServerBackends starts envtest with deploy/crds and returns a
// constructor of kubestore backends, each in a fresh namespace. It skips
// the test without KUBEBUILDER_ASSETS.
func apiServerBackends(t *testing.T) func(*testing.T) store.Backend {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set")
	}
	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "deploy", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := te.Stop(); err != nil {
			t.Error(err)
		}
	})
	// The suites send hundreds of requests; lift client-side throttling.
	cfg.QPS, cfg.Burst = 1000, 2000
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	// Warm the client's REST mapper for every kind, so the first RPC of a
	// suite does not spend its deadline on API discovery.
	warm := kubestore.New(c, "default")
	for _, k := range iam.Kinds {
		if _, err := warm.List(t.Context(), k); err != nil {
			t.Fatal(err)
		}
	}
	return func(t *testing.T) store.Backend {
		t.Helper()
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "vws-iam-"}}
		if err := c.Create(context.Background(), ns); err != nil {
			t.Fatal(err)
		}
		return kubestore.New(c, ns.Name)
	}
}

// replicas starts two servers (A and B) on one backend and one clock and
// returns them with an access key of user alice.
func replicas(t *testing.T, b store.Backend) (a, bb *env, kid, secret string) {
	t.Helper()
	now := time.Now().UTC()
	a, bb = newEnvOn(t, b, &now), newEnvOn(t, b, &now)
	ctx := t.Context()
	u := a.createUser(t, ctx, "alice")
	key, err := a.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid = key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
	return a, bb, kid, key.GetSecretAccessKey()
}

func gst(ctx context.Context, e *env, r *iamv1.AuthenticateRequest) error {
	_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(r)})
	return err
}

func testSharedReplay(t *testing.T, backend func(*testing.T) store.Backend) {
	t.Run("ReplayOnOtherReplica", func(t *testing.T) {
		b := backend(t)
		a, rb, kid, secret := replicas(t, b)
		ctx := t.Context()
		signed := a.stsSign(kid, secret, "", "GetSessionToken")
		if err := gst(ctx, a, signed); err != nil {
			t.Fatal(err)
		}
		wantErr(t, gst(ctx, rb, signed), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		wantErr(t, gst(ctx, a, signed), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		// A different request still works on B.
		if err := gst(ctx, rb, a.stsSign(kid, secret, "", "GetSessionToken")); err != nil {
			t.Fatal(err)
		}
		// Only the SHA-256 is stored: neither the signature nor the secret.
		es, err := b.List(ctx, iam.KindReplay)
		if err != nil {
			t.Fatal(err)
		}
		if len(es) != 2 {
			t.Fatalf("replay entries = %d, want 2", len(es))
		}
		for _, e := range es {
			if s := string(e.Spec); strings.Contains(s, signed.GetSignature()) || strings.Contains(s, secret) || strings.Contains(s, kid) {
				t.Fatalf("replay entry holds plaintext: %s", s)
			}
		}
	})

	t.Run("ConcurrentExactlyOneWins", func(t *testing.T) {
		a, rb, kid, secret := replicas(t, backend(t))
		ctx := t.Context()
		signed := a.stsSign(kid, secret, "", "GetSessionToken")
		const n = 16
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			e := a
			if i%2 == 1 {
				e = rb
			}
			wg.Go(func() { errs[i] = gst(ctx, e, signed) })
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
				continue
			}
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		}
		if ok != 1 {
			t.Fatalf("%d of %d identical requests succeeded, want exactly 1", ok, n)
		}
	})

	t.Run("RestartPersistence", func(t *testing.T) {
		b := backend(t)
		a, _, kid, secret := replicas(t, b)
		ctx := t.Context()
		signed := a.stsSign(kid, secret, "", "GetSessionToken")
		if err := gst(ctx, a, signed); err != nil {
			t.Fatal(err)
		}
		// A fresh process has an empty in-memory front; the store refuses.
		restarted := newEnvOn(t, b, a.now)
		wantErr(t, gst(ctx, restarted, signed), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	})

	t.Run("ExpiryAndGC", func(t *testing.T) {
		b := backend(t)
		a, rb, kid, secret := replicas(t, b)
		ctx := t.Context()
		signed := a.stsSign(kid, secret, "", "GetSessionToken")
		if err := gst(ctx, a, signed); err != nil {
			t.Fatal(err)
		}
		if n, err := rb.api.GCReplayEntries(ctx); err != nil || n != 0 {
			t.Fatalf("GC before expiry = %d, %v; want 0", n, err)
		}
		*a.now = a.now.Add(31 * time.Minute)
		// Past the X-Amz-Date window the request fails on its own.
		wantErr(t, gst(ctx, rb, signed), codes.Unauthenticated, "INVALID_CREDENTIALS", "RequestTimeTooSkewed")
		if n, err := rb.api.GCReplayEntries(ctx); err != nil || n != 1 {
			t.Fatalf("GC after expiry = %d, %v; want 1", n, err)
		}
		if vs, err := store.List[iam.ReplayEntry](ctx, b); err != nil || len(vs) != 0 {
			t.Fatalf("after GC: %d entries, %v", len(vs), err)
		}
		// A fresh request after GC is unaffected.
		if err := gst(ctx, a, a.stsSign(kid, secret, "", "GetSessionToken")); err != nil {
			t.Fatal(err)
		}
	})
}
