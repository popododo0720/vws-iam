package kubestore_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

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
