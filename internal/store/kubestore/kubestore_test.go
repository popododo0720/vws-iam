package kubestore_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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

func policy(name string) iam.Policy {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	return iam.Policy{
		Name: name, ID: "ANPA1", Created: now, DefaultVersion: "v1",
		Versions: []iam.PolicyVersion{{ID: "v1", Document: `{}`, Created: now}},
	}
}

func policyObjectNames(t *testing.T, c client.Client, namespace string) map[string]string {
	t.Helper()
	l := &unstructured.UnstructuredList{}
	gvk := kubestore.GVK(iam.KindPolicy)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	if err := c.List(context.Background(), l, client.InNamespace(namespace)); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for i := range l.Items {
		key := l.Items[i].GetAnnotations()[kubestore.Group+"/key"]
		out[key] = l.Items[i].GetName()
	}
	return out
}

func TestLongPolicyNameFitsDNS1123(t *testing.T) {
	ctx := context.Background()
	c := newFake()
	raw := kubestore.New(c, "vws-iam")
	short := store.Scoped(raw, "acme")
	if _, err := store.Create(ctx, short, policy("p")); err != nil {
		t.Fatal(err)
	}
	names := policyObjectNames(t, c, "vws-iam")
	if names["acme/p"] != "kc5hmqp9fe0" {
		t.Fatalf("short key name %q", names["acme/p"])
	}

	fit := strings.Repeat("a", 28)
	overflow := strings.Repeat("b", 29)
	widest := strings.Repeat("c", 63)
	upper := strings.Repeat("P", 128)
	lower := strings.Repeat("p", 128)
	for _, project := range []string{fit, overflow, widest} {
		b := store.Scoped(raw, project)
		if _, err := store.Create(ctx, b, policy(upper)); err != nil {
			t.Fatalf("create %s: %v", project, err)
		}
		got, err := store.Get[iam.Policy](ctx, b, lower)
		if err != nil || got.Object.Name != upper {
			t.Fatalf("get %s: %v %q", project, err, got.Object.Name)
		}
		if _, err := store.Create(ctx, b, policy(lower)); !errors.Is(err, store.ErrExists) {
			t.Fatalf("second create %s: %v", project, err)
		}
	}
	names = policyObjectNames(t, c, "vws-iam")
	seen := map[string]string{}
	for _, project := range []string{fit, overflow, widest} {
		key := project + "/" + upper
		name := names[key]
		if name == "" || len(name) > 253 {
			t.Fatalf("key %s object name %q length %d", project, name, len(name))
		}
		if other, ok := seen[name]; ok {
			t.Fatalf("object name %q used by %s and %s", name, other, project)
		}
		seen[name] = project
		for _, r := range name {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				t.Fatalf("name %q is not DNS-1123", name)
			}
		}
	}
	if !strings.HasPrefix(names[fit+"/"+upper], "k") || len(names[fit+"/"+upper]) != 253 {
		t.Fatalf("fitting name %q", names[fit+"/"+upper])
	}
}
