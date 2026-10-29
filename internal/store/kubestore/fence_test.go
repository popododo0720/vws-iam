package kubestore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
)

// hooks runs a function once, inside the client, just before the next
// write (update or delete) of an access key: after the conditional write
// fenced the user and before the key write reaches the API server.
type hooks struct {
	mu     sync.Mutex
	before func(ctx context.Context) error
	// lose, when set, drops the next key update without sending it and
	// reports a timeout: a write whose outcome the caller cannot know.
	lose bool
}

func (h *hooks) take() (func(ctx context.Context) error, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f, lose := h.before, h.lose
	h.before, h.lose = nil, false
	return f, lose
}

func isKey(obj client.Object) bool {
	return obj.GetObjectKind().GroupVersionKind().Kind == string(iam.KindAccessKey)
}

func (h *hooks) funcs() interceptor.Funcs {
	return interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if isKey(obj) && obj.GetAnnotations()[kubestore.Group+"/voided-fence"] == "" {
				f, lose := h.take()
				if f != nil {
					if err := f(ctx); err != nil {
						return err
					}
				}
				if lose {
					gr := schema.GroupResource{Group: kubestore.Group, Resource: "iamaccesskeys"}
					return apierrors.NewTimeoutError("lost "+gr.String()+" update", 1)
				}
			}
			return c.Update(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if isKey(obj) {
				if f, _ := h.take(); f != nil {
					if err := f(ctx); err != nil {
						return err
					}
				}
			}
			return c.Delete(ctx, obj, opts...)
		},
	}
}

// fenceSuite proves conditional writes atomic against a precondition
// change that lands between the fence and the key write. newClient wraps
// a fresh store's client with funcs.
func fenceSuite(t *testing.T, newClient func(t *testing.T, funcs interceptor.Funcs) (client.Client, string)) {
	type fixture struct {
		c  client.Client
		ns string
	}
	type userV = store.Versioned[iam.User]
	type keyV = store.Versioned[iam.AccessKey]
	setup := func(t *testing.T) (*hooks, fixture, *kubestore.Store, userV, keyV) {
		t.Helper()
		h := &hooks{}
		c, ns := newClient(t, h.funcs())
		s := kubestore.New(c, ns)
		ctx := context.Background()
		u := iam.User{Name: "Carol", ID: "AIDA1", Path: "/allowed/"}
		uv, err := store.Create(ctx, s, u)
		if err != nil {
			t.Fatal(err)
		}
		k := iam.AccessKey{
			ID: "AKIAABCDEFGHIJKLMNOP", UserName: "Carol", Status: iam.KeyActive,
			Secret: iam.Sealed{KeyID: "kek-1", Ciphertext: []byte{1}},
		}
		kv, err := store.Create(ctx, s, k)
		if err != nil {
			t.Fatal(err)
		}
		return h, fixture{c: c, ns: ns}, s, store.Versioned[iam.User]{Object: u, Version: uv},
			store.Versioned[iam.AccessKey]{Object: k, Version: kv}
	}
	moveUser := func(s *kubestore.Store) func(ctx context.Context) error {
		return func(ctx context.Context) error {
			_, err := store.Mutate(ctx, s, "carol", func(u *iam.User) error {
				u.Path = "/denied/"
				return nil
			})
			return err
		}
	}
	userState := func(t *testing.T, f fixture, s *kubestore.Store) (string, int) {
		t.Helper()
		u, err := store.Get[iam.User](context.Background(), s, "carol")
		if err != nil {
			t.Fatal(err)
		}
		return u.Object.Path, fenceCount(t, f.c, f.ns, iam.KindUser)
	}

	t.Run("UpdateIfLosesToMoveBeforeCommit", func(t *testing.T) {
		h, c, s, u, k := setup(t)
		h.before = moveUser(s)
		off := k.Object
		off.Status = iam.KeyInactive
		_, err := store.UpdateIf(context.Background(), s, off, k.Version, store.PreOf(u))
		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("key update with the user moved before its commit: %v, want ErrConflict", err)
		}
		got, err := store.Get[iam.AccessKey](context.Background(), s, k.Object.ID)
		if err != nil || got.Object.Status != iam.KeyActive {
			t.Fatalf("key changed by a refused write: %v %q", err, got.Object.Status)
		}
		if path, fences := userState(t, c, s); path != "/denied/" || fences != 0 {
			t.Fatalf("user path %q with %d fences, want /denied/ and none", path, fences)
		}
	})
	t.Run("DeleteIfLosesToMoveBeforeCommit", func(t *testing.T) {
		h, c, s, u, k := setup(t)
		h.before = moveUser(s)
		err := store.DeleteIf[iam.AccessKey](context.Background(), s, k.Object.ID, k.Version, store.PreOf(u))
		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("key delete with the user moved before its commit: %v, want ErrConflict", err)
		}
		if _, err := store.Get[iam.AccessKey](context.Background(), s, k.Object.ID); err != nil {
			t.Fatalf("refused delete removed the key: %v", err)
		}
		if path, fences := userState(t, c, s); path != "/denied/" || fences != 0 {
			t.Fatalf("user path %q with %d fences, want /denied/ and none", path, fences)
		}
	})
	t.Run("CommittedWriteLeavesNoFence", func(t *testing.T) {
		_, c, s, u, k := setup(t)
		off := k.Object
		off.Status = iam.KeyInactive
		if _, err := store.UpdateIf(context.Background(), s, off, k.Version, store.PreOf(u)); err != nil {
			t.Fatal(err)
		}
		if path, fences := userState(t, c, s); path != "/allowed/" || fences != 0 {
			t.Fatalf("user path %q with %d fences, want /allowed/ and none", path, fences)
		}
	})
	t.Run("UnknownOutcomeIsVoidedByTheNextMove", func(t *testing.T) {
		// The key write times out with its outcome unknown, so the fence
		// stays. The next change of the user voids the key's version, and
		// the write, if it reaches the API server only now, fails.
		h, c, s, u, k := setup(t)
		h.lose = true
		off := k.Object
		off.Status = iam.KeyInactive
		ctx := context.Background()
		if _, err := store.UpdateIf(ctx, s, off, k.Version, store.PreOf(u)); !errors.Is(err, store.ErrUnavailable) {
			t.Fatalf("lost key write: %v, want ErrUnavailable", err)
		}
		if _, fences := userState(t, c, s); fences != 1 {
			t.Fatalf("%d fences after a write with an unknown outcome, want 1", fences)
		}
		if err := moveUser(s)(ctx); err != nil {
			t.Fatal(err)
		}
		if path, fences := userState(t, c, s); path != "/denied/" || fences != 0 {
			t.Fatalf("user path %q with %d fences, want /denied/ and none", path, fences)
		}
		late, err := store.Update(ctx, s, off, k.Version)
		if !errors.Is(err, store.ErrConflict) {
			t.Fatalf("late key write after the move: %v (version %q), want ErrConflict", err, late)
		}
		got, err := store.Get[iam.AccessKey](ctx, s, k.Object.ID)
		if err != nil || got.Object.Status != iam.KeyActive {
			t.Fatalf("key after the late write: %v %q", err, got.Object.Status)
		}
	})
}

// fenceCount counts fence annotations on every object of kind in ns.
func fenceCount(t *testing.T, c client.Client, ns string, kind iam.Kind) int {
	t.Helper()
	l := &unstructured.UnstructuredList{}
	gvk := kubestore.GVK(kind)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	if err := c.List(context.Background(), l, client.InNamespace(ns)); err != nil {
		t.Fatal(err)
	}
	n := 0
	for i := range l.Items {
		for a := range l.Items[i].GetAnnotations() {
			if strings.HasPrefix(a, kubestore.Group+"/fence-") {
				n++
			}
		}
	}
	return n
}

func TestFences(t *testing.T) {
	fenceSuite(t, func(_ *testing.T, funcs interceptor.Funcs) (client.Client, string) {
		return fake.NewClientBuilder().WithScheme(scheme()).WithInterceptorFuncs(funcs).Build(), "vws-iam"
	})
}

// TestFencesOnAPIServer runs the fence suite against a real
// kube-apiserver, which skips no-op updates and enforces resourceVersion
// preconditions itself. It skips without KUBEBUILDER_ASSETS.
func TestFencesOnAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set")
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "deploy", "crds")},
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
	base, err := client.NewWithWatch(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fenceSuite(t, func(t *testing.T, funcs interceptor.Funcs) (client.Client, string) {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "vws-iam-"}}
		if err := base.Create(context.Background(), ns); err != nil {
			t.Fatal(err)
		}
		c := interceptor.NewClient(base, funcs)
		return c, ns.Name
	})
}
