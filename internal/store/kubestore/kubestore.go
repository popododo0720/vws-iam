// Package kubestore is the store.Backend on IAM custom resources in one
// namespace. Each kind is a CRD in group iam.vws.popododo0720.io; the spec
// is the domain object's JSON, and the resourceVersion is the store version.
package kubestore

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// Group and Version of every IAM CRD.
const (
	Group   = "iam.vws.popododo0720.io"
	Version = "v1alpha1"
	keyAnno = Group + "/key"
)

// GVK returns the GroupVersionKind of kind.
func GVK(kind iam.Kind) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: Group, Version: Version, Kind: string(kind)}
}

var enc = base32.HexEncoding.WithPadding(base32.NoPadding)

// objectName maps a case-insensitive IAM key to a DNS-1123 subdomain.
func objectName(key string) string {
	return "k" + strings.ToLower(enc.EncodeToString([]byte(store.Fold(key))))
}

// Store is a store.Backend on a controller-runtime client.
type Store struct {
	c  client.Client
	ns string
}

// New wraps a client. Tests pass a fake client.
func New(c client.Client, namespace string) *Store { return &Store{c: c, ns: namespace} }

// Open builds a client from kubeconfig (empty: in-cluster).
func Open(kubeconfig, namespace string) (*Store, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("kube client: %w", err)
	}
	return New(c, namespace), nil
}

func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case apierrors.IsNotFound(err):
		return store.ErrNotFound
	case apierrors.IsAlreadyExists(err):
		return store.ErrExists
	case apierrors.IsConflict(err):
		return store.ErrConflict
	case apierrors.IsServerTimeout(err), apierrors.IsTimeout(err), apierrors.IsTooManyRequests(err), apierrors.IsServiceUnavailable(err), apierrors.IsInternalError(err):
		return fmt.Errorf("%w: %w", store.ErrUnavailable, err)
	}
	return fmt.Errorf("kube: %w", err)
}

func (s *Store) object(kind iam.Kind, key string, spec []byte) (*unstructured.Unstructured, error) {
	var m map[string]any
	if err := json.Unmarshal(spec, &m); err != nil {
		return nil, fmt.Errorf("spec: %w", err)
	}
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(GVK(kind))
	u.SetNamespace(s.ns)
	u.SetName(objectName(key))
	u.SetAnnotations(map[string]string{keyAnno: key})
	u.Object["spec"] = m
	return u, nil
}

func entry(u *unstructured.Unstructured) (store.Entry, error) {
	spec, err := json.Marshal(u.Object["spec"])
	if err != nil {
		return store.Entry{}, fmt.Errorf("spec: %w", err)
	}
	return store.Entry{Key: u.GetAnnotations()[keyAnno], Spec: spec, Version: u.GetResourceVersion()}, nil
}

// Create implements store.Backend.
func (s *Store) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	u, err := s.object(kind, key, spec)
	if err != nil {
		return "", err
	}
	if err := s.c.Create(ctx, u); err != nil {
		return "", translate(err)
	}
	return u.GetResourceVersion(), nil
}

// Update implements store.Backend.
func (s *Store) Update(ctx context.Context, kind iam.Kind, key string, spec []byte, version string) (string, error) {
	cur, err := s.get(ctx, kind, key)
	if err != nil {
		return "", err
	}
	u, err := s.object(kind, cur.GetAnnotations()[keyAnno], spec)
	if err != nil {
		return "", err
	}
	u.SetResourceVersion(version)
	if err := s.c.Update(ctx, u); err != nil {
		return "", translate(err)
	}
	return u.GetResourceVersion(), nil
}

func (s *Store) get(ctx context.Context, kind iam.Kind, key string) (*unstructured.Unstructured, error) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(GVK(kind))
	if err := s.c.Get(ctx, client.ObjectKey{Namespace: s.ns, Name: objectName(key)}, u); err != nil {
		return nil, translate(err)
	}
	return u, nil
}

// Get implements store.Backend.
func (s *Store) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	u, err := s.get(ctx, kind, key)
	if err != nil {
		return store.Entry{}, err
	}
	return entry(u)
}

// List implements store.Backend.
func (s *Store) List(ctx context.Context, kind iam.Kind) ([]store.Entry, error) {
	l := &unstructured.UnstructuredList{}
	gvk := GVK(kind)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	if err := s.c.List(ctx, l, client.InNamespace(s.ns)); err != nil {
		return nil, translate(err)
	}
	out := make([]store.Entry, 0, len(l.Items))
	for i := range l.Items {
		e, err := entry(&l.Items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return store.Fold(out[i].Key) < store.Fold(out[j].Key) })
	return out, nil
}

// ListPage implements store.Pager with the API server's limit and
// continue token.
func (s *Store) ListPage(ctx context.Context, kind iam.Kind, limit int64, cont string) ([]store.Entry, string, error) {
	l := &unstructured.UnstructuredList{}
	gvk := GVK(kind)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	opts := []client.ListOption{client.InNamespace(s.ns), client.Limit(limit)}
	if cont != "" {
		opts = append(opts, client.Continue(cont))
	}
	if err := s.c.List(ctx, l, opts...); err != nil {
		return nil, "", translate(err)
	}
	out := make([]store.Entry, 0, len(l.Items))
	for i := range l.Items {
		e, err := entry(&l.Items[i])
		if err != nil {
			return nil, "", err
		}
		out = append(out, e)
	}
	return out, l.GetContinue(), nil
}

// Delete implements store.Backend.
func (s *Store) Delete(ctx context.Context, kind iam.Kind, key, version string) error {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(GVK(kind))
	u.SetNamespace(s.ns)
	u.SetName(objectName(key))
	var opts []client.DeleteOption
	if version != "" {
		opts = append(opts, client.Preconditions(metav1.Preconditions{ResourceVersion: &version}))
	}
	return translate(s.c.Delete(ctx, u, opts...))
}
