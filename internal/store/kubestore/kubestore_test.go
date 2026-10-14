package kubestore_test

import (
	"context"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/storetest"
)

func scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	for _, k := range iam.Kinds {
		gvk := kubestore.GVK(k)
		s.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		gvk.Kind += "List"
		s.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
	}
	return s
}

func newFake() client.Client { return fake.NewClientBuilder().WithScheme(scheme()).Build() }

func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) store.Backend { return kubestore.New(newFake(), "vws-iam") })
}

func TestObjectsAreNamespacedCRsWithDNSNames(t *testing.T) {
	c := newFake()
	b := kubestore.New(c, "vws-iam")
	ctx := context.Background()
	if _, err := store.Create(ctx, b, iam.User{Name: "Mixed.Case+name@x", ID: "1"}); err != nil {
		t.Fatal(err)
	}
	l := &unstructured.UnstructuredList{}
	gvk := kubestore.GVK(iam.KindUser)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	if err := c.List(ctx, l, client.InNamespace("vws-iam")); err != nil {
		t.Fatal(err)
	}
	if len(l.Items) != 1 {
		t.Fatalf("%d objects", len(l.Items))
	}
	name := l.Items[0].GetName()
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			t.Fatalf("name %q is not DNS-1123", name)
		}
	}
	if !strings.HasPrefix(name, "k") {
		t.Fatalf("name %q", name)
	}
}
