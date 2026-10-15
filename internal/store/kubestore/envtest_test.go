package kubestore_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/storetest"
)

// TestConformanceOnAPIServer runs the suite against a real kube-apiserver
// with the CRDs from deploy/crds. It skips without KUBEBUILDER_ASSETS.
func TestConformanceOnAPIServer(t *testing.T) {
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
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	storetest.Run(t, func(t *testing.T) store.Backend {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "vws-iam-"}}
		if err := c.Create(context.Background(), ns); err != nil {
			t.Fatal(err)
		}
		return kubestore.New(c, ns.Name)
	})
}

func TestLongPolicyNameOnAPIServer(t *testing.T) {
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
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "vws-iam-"}}
	if err := c.Create(context.Background(), ns); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	upper := strings.Repeat("P", 128)
	for _, n := range []int{29, 63} {
		project := strings.Repeat("a", n)
		b := store.Scoped(kubestore.New(c, ns.Name), project)
		pol := iam.Policy{
			Name: upper, ID: "ANPA1", Created: now, DefaultVersion: "v1",
			Versions: []iam.PolicyVersion{{ID: "v1", Document: `{}`, Created: now}},
		}
		if _, err := store.Create(ctx, b, pol); err != nil {
			t.Fatalf("create project length %d: %v", n, err)
		}
		got, err := store.Get[iam.Policy](ctx, b, strings.Repeat("p", 128))
		if err != nil || got.Object.Name != upper {
			t.Fatalf("get project length %d: %v %q", n, err, got.Object.Name)
		}
	}
	l := &unstructured.UnstructuredList{}
	gvk := kubestore.GVK(iam.KindPolicy)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	if err := c.List(ctx, l, client.InNamespace(ns.Name)); err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 2 {
		t.Fatalf("%d policies", len(l.Items))
	}
	for i := range l.Items {
		name := l.Items[i].GetName()
		if len(name) > 253 {
			t.Fatalf("object name length %d", len(name))
		}
	}
}
