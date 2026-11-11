// Package kubestore is the store.Backend on IAM custom resources in one
// namespace. Each kind is a CRD in group iam.vws.popododo0720.io; the spec
// is the domain object's JSON, and the resourceVersion is the store version.
package kubestore

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
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

// maxDNS1123Name is the Kubernetes subdomain limit.
const maxDNS1123Name = 253

// objectName maps a case-insensitive IAM key to a DNS-1123 subdomain.
// A key whose base32 form fits keeps that form, so an object stored
// before the hash fallback is still found. A longer key is h plus the
// SHA-256 hex of the folded key. That form cannot collide with a k name.
func objectName(key string) string {
	folded := store.Fold(key)
	name := "k" + strings.ToLower(enc.EncodeToString([]byte(folded)))
	if len(name) <= maxDNS1123Name {
		return name
	}
	sum := sha256.Sum256([]byte(folded))
	return "h" + hex.EncodeToString(sum[:])
}

// Store is a store.Backend on a controller-runtime client.
type Store struct {
	c   client.Client
	ns  string
	tel telemetry
}

// New wraps a client. Tests pass a fake client. Spans and metrics go to
// the global OTel providers.
func New(c client.Client, namespace string) *Store {
	return &Store{c: c, ns: namespace, tel: globalTelemetry()}
}

// Open builds a client from kubeconfig (empty: in-cluster).
func Open(kubeconfig, namespace string) (*Store, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	// No client-side rate limit (#51). client-go's default of 5 QPS made
	// a burst of CAS retries on one object wait past the request deadline,
	// and its "would exceed context deadline" error wraps no context error.
	// The API server's priority and fairness throttles instead, and its
	// 429 is ErrUnavailable, which callers retry with backoff.
	cfg.QPS = -1
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("kube client: %w", err)
	}
	return New(c, namespace), nil
}

// translate maps an API error to the store sentinels. Not found, exists
// and conflict stay bare: their text reaches clients and must match
// memstore. Any other failure names the call and kind it came from.
func translate(op string, kind iam.Kind, err error) error {
	switch {
	case err == nil:
		return nil
	case apierrors.IsNotFound(err):
		return store.ErrNotFound
	case apierrors.IsAlreadyExists(err):
		return store.ErrExists
	case apierrors.IsConflict(err):
		return store.ErrConflict
	case apierrors.IsServerTimeout(err),
		apierrors.IsTimeout(err),
		apierrors.IsTooManyRequests(err),
		apierrors.IsServiceUnavailable(err),
		apierrors.IsInternalError(err):
		return fmt.Errorf("%w: kube %s %s: %w", store.ErrUnavailable, op, kind, err)
	}
	return fmt.Errorf("kube %s %s: %w", op, kind, err)
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
func (s *Store) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (_ string, err error) {
	ctx, end := s.tel.start(ctx, "create", kind)
	defer func() { end(err) }()
	u, err := s.object(kind, key, spec)
	if err != nil {
		return "", err
	}
	if err := s.c.Create(ctx, u); err != nil {
		return "", translate("create", kind, err)
	}
	return u.GetResourceVersion(), nil
}

// Update implements store.Backend. Before the write it voids every
// conditional write still fenced on this object (see UpdateIf); the new
// object carries no fence.
func (s *Store) Update(
	ctx context.Context, kind iam.Kind, key string, spec []byte, version string,
) (_ string, err error) {
	ctx, end := s.tel.start(ctx, "update", kind)
	defer func() { end(err) }()
	cur, err := s.get(ctx, kind, key)
	if err != nil {
		return "", err
	}
	if cur.GetResourceVersion() == version {
		if err := s.voidFences(ctx, cur); err != nil {
			return "", err
		}
	}
	u, err := s.object(kind, cur.GetAnnotations()[keyAnno], spec)
	if err != nil {
		return "", err
	}
	u.SetResourceVersion(version)
	if err := s.c.Update(ctx, u); err != nil {
		return "", translate("update", kind, err)
	}
	return u.GetResourceVersion(), nil
}

func (s *Store) get(ctx context.Context, kind iam.Kind, key string) (*unstructured.Unstructured, error) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(GVK(kind))
	if err := s.c.Get(ctx, client.ObjectKey{Namespace: s.ns, Name: objectName(key)}, u); err != nil {
		return nil, translate("get", kind, err)
	}
	return u, nil
}

// Get implements store.Backend.
func (s *Store) Get(ctx context.Context, kind iam.Kind, key string) (_ store.Entry, err error) {
	ctx, end := s.tel.start(ctx, "get", kind)
	defer func() { end(err) }()
	u, err := s.get(ctx, kind, key)
	if err != nil {
		return store.Entry{}, err
	}
	return entry(u)
}

// List implements store.Backend.
func (s *Store) List(ctx context.Context, kind iam.Kind) (_ []store.Entry, err error) {
	ctx, end := s.tel.start(ctx, "list", kind)
	defer func() { end(err) }()
	l := &unstructured.UnstructuredList{}
	gvk := GVK(kind)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	if err := s.c.List(ctx, l, client.InNamespace(s.ns)); err != nil {
		return nil, translate("list", kind, err)
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
func (s *Store) ListPage(
	ctx context.Context, kind iam.Kind, limit int64, cont string,
) (_ []store.Entry, _ string, err error) {
	ctx, end := s.tel.start(ctx, "list_page", kind)
	defer func() { end(err) }()
	l := &unstructured.UnstructuredList{}
	gvk := GVK(kind)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	opts := []client.ListOption{client.InNamespace(s.ns), client.Limit(limit)}
	if cont != "" {
		opts = append(opts, client.Continue(cont))
	}
	if err := s.c.List(ctx, l, opts...); err != nil {
		return nil, "", translate("list", kind, err)
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

// Delete implements store.Backend. Like Update, it voids the conditional
// writes fenced on the object first, then deletes it at the version it read.
func (s *Store) Delete(ctx context.Context, kind iam.Kind, key, version string) (err error) {
	ctx, end := s.tel.start(ctx, "delete", kind)
	defer func() { end(err) }()
	for attempt := 0; ; attempt++ {
		cur, err := s.get(ctx, kind, key)
		if err != nil {
			return err
		}
		rv := cur.GetResourceVersion()
		if version != "" && rv != version {
			return store.ErrConflict
		}
		if err := s.voidFences(ctx, cur); err != nil {
			return err
		}
		pre := client.Preconditions(metav1.Preconditions{ResourceVersion: &rv})
		err = translate("delete", kind, s.c.Delete(ctx, cur, pre))
		if errors.Is(err, store.ErrConflict) && version == "" && attempt < 8 {
			continue
		}
		return err
	}
}
