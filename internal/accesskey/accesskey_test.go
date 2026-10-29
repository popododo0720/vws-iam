package accesskey_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func kek(t *testing.T) []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func ring(t *testing.T, active string, keys map[string][]byte) *secret.Keyring {
	k, err := secret.NewKeyring(active, keys)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func withUser(t *testing.T, b store.Backend, name string) {
	if _, err := store.Create(context.Background(), b, iam.User{Name: name, ID: "AIDA" + name}); err != nil {
		t.Fatal(err)
	}
}

func fakeKube() client.Client {
	s := runtime.NewScheme()
	for _, k := range iam.Kinds {
		gvk := kubestore.GVK(k)
		s.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		gvk.Kind += "List"
		s.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
	}
	return fake.NewClientBuilder().WithScheme(s).Build()
}

func TestSecretIsNeverStoredInPlaintext(t *testing.T) {
	c := fakeKube()
	b := kubestore.New(c, "vws-iam")
	withUser(t, b, "alice")
	svc := accesskey.New(b, b, "proj-a", ring(t, "kek-1", map[string][]byte{"kek-1": kek(t)}), nil)
	cred, err := svc.Create(context.Background(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(cred.Secret) != 40 || !strings.HasPrefix(cred.AccessKeyID, "AKIA") || len(cred.AccessKeyID) != 20 {
		t.Fatalf("credential shape %s", cred)
	}
	if strings.Contains(fmt.Sprintf("%v %+v", cred, cred), cred.Secret) {
		t.Fatal("Credential formatting prints the secret")
	}
	// Inspect the raw custom resource as the API server stores it.
	l := &unstructured.UnstructuredList{}
	gvk := kubestore.GVK(iam.KindAccessKey)
	gvk.Kind += "List"
	l.SetGroupVersionKind(gvk)
	if err := c.List(context.Background(), l); err != nil || len(l.Items) != 1 {
		t.Fatalf("list: %v %d", err, len(l.Items))
	}
	raw, err := l.Items[0].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), cred.Secret) {
		t.Fatal("custom resource contains the plaintext secret")
	}
	if !strings.Contains(string(raw), `"keyId":"kek-1"`) {
		t.Fatalf("custom resource has no KEK id: %s", raw)
	}
	got, err := svc.GetSigningCredential(context.Background(), cred.AccessKeyID)
	if err != nil || got.Secret != cred.Secret || got.UserName != "alice" {
		t.Fatalf("signing credential: %v %s", err, got)
	}
	ks, err := svc.List(context.Background(), "alice")
	if err != nil || len(ks) != 1 || len(ks[0].Secret.Ciphertext) != 0 {
		t.Fatalf("list returns sealed secret or wrong count: %v %+v", err, ks)
	}
}

func TestInactiveKeyIsRejected(t *testing.T) {
	b := memstore.New()
	withUser(t, b, "bob")
	svc := accesskey.New(b, b, "proj-a", ring(t, "k", map[string][]byte{"k": kek(t)}), nil)
	ctx := context.Background()
	cred, err := svc.Create(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetStatus(ctx, "bob", cred.AccessKeyID, iam.KeyInactive); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSigningCredential(ctx, cred.AccessKeyID); !errors.Is(err, accesskey.ErrInactive) {
		t.Fatalf("inactive key: %v", err)
	}
	if err := svc.SetStatus(ctx, "bob", cred.AccessKeyID, "Enabled"); !errors.Is(err, iam.ErrInvalid) {
		t.Fatalf("bad status: %v", err)
	}
	if err := svc.SetStatus(ctx, "bob", cred.AccessKeyID, iam.KeyActive); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSigningCredential(ctx, cred.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "bob", cred.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSigningCredential(ctx, cred.AccessKeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted key: %v", err)
	}
}

func TestAtMostTwoKeysPerUserAndOwnership(t *testing.T) {
	b := memstore.New()
	withUser(t, b, "carol")
	withUser(t, b, "dave")
	svc := accesskey.New(b, b, "proj-a", ring(t, "k", map[string][]byte{"k": kek(t)}), nil)
	ctx := context.Background()
	var ids []string
	for range 2 {
		c, err := svc.Create(ctx, "carol")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, c.AccessKeyID)
	}
	if _, err := svc.Create(ctx, "carol"); !errors.Is(err, accesskey.ErrLimitExceeded) {
		t.Fatalf("third key: %v", err)
	}
	if _, err := svc.Create(ctx, "nobody"); !errors.Is(err, accesskey.ErrNoSuchUser) {
		t.Fatalf("unknown user: %v", err)
	}
	if err := svc.Delete(ctx, "dave", ids[0]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("dave deleted carol's key: %v", err)
	}
	if err := svc.SetStatus(ctx, "dave", ids[0], iam.KeyInactive); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("dave disabled carol's key: %v", err)
	}
}

func TestKEKRotationReadsOldKeyIDAndRewraps(t *testing.T) {
	b := memstore.New()
	withUser(t, b, "erin")
	k1, k2 := kek(t), kek(t)
	ctx := context.Background()
	cred, err := accesskey.New(b, b, "proj-a", ring(t, "kek-1", map[string][]byte{"kek-1": k1}), nil).Create(ctx, "erin")
	if err != nil {
		t.Fatal(err)
	}
	// Restart with a rotated keyring: kek-2 active, kek-1 still present.
	rotated := accesskey.New(b, b, "proj-a", ring(t, "kek-2", map[string][]byte{"kek-1": k1, "kek-2": k2}), nil)
	got, err := rotated.GetSigningCredential(ctx, cred.AccessKeyID)
	if err != nil || got.Secret != cred.Secret {
		t.Fatalf("after rotation: %v", err)
	}
	stored, err := store.Get[iam.AccessKey](ctx, b, cred.AccessKeyID)
	if err != nil || stored.Object.Secret.KeyID != "kek-2" {
		t.Fatalf("not rewrapped: %v %q", err, stored.Object.Secret.KeyID)
	}
	// kek-1 can now be retired.
	only2 := accesskey.New(b, b, "proj-a", ring(t, "kek-2", map[string][]byte{"kek-2": k2}), nil)
	if got, err := only2.GetSigningCredential(ctx, cred.AccessKeyID); err != nil || got.Secret != cred.Secret {
		t.Fatalf("after retiring kek-1: %v", err)
	}
	// A keyring without the KEK cannot open it.
	other := accesskey.New(b, b, "proj-a", ring(t, "kek-9", map[string][]byte{"kek-9": kek(t)}), nil)
	if _, err := other.GetSigningCredential(ctx, cred.AccessKeyID); !errors.Is(err, secret.ErrUnknownKEK) {
		t.Fatalf("foreign keyring: %v", err)
	}
}

func TestImportKeepsExistingCredentialAndIsIdempotentlyRejected(t *testing.T) {
	b := memstore.New()
	withUser(t, b, "root")
	svc := accesskey.New(b, b, "proj-a", ring(t, "k", map[string][]byte{"k": kek(t)}), nil)
	ctx := context.Background()
	id, sec := "AKIAABCDEFGHIJKLMNOP", "0123456789012345678901234567890123456789"
	if _, err := svc.Import(ctx, "root", id, sec, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Import(ctx, "root", id, sec, false); !errors.Is(err, store.ErrExists) {
		t.Fatalf("replayed import: %v", err)
	}
	if _, err := svc.Import(ctx, "root", "AKIA-bad", sec, false); !errors.Is(err, iam.ErrInvalid) {
		t.Fatalf("hostile id: %v", err)
	}
	got, err := svc.GetSigningCredential(ctx, id)
	if err != nil || got.Secret != sec {
		t.Fatalf("imported key: %v", err)
	}
}

func TestIndexAndRootKey(t *testing.T) {
	b := memstore.New()
	scopedA := store.Scoped(b, "proj-a")
	withUser(t, scopedA, "alice")
	svc := accesskey.New(scopedA, b, "proj-a", ring(t, "k", map[string][]byte{"k": kek(t)}), nil)
	ctx := context.Background()
	cred, err := svc.Create(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := accesskey.ProjectOf(ctx, b, cred.AccessKeyID); err != nil || p != "proj-a" {
		t.Fatalf("index: %q %v", p, err)
	}
	root, err := svc.Import(ctx, "", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := svc.GetSigningCredential(ctx, root.AccessKeyID); err != nil || !got.Root {
		t.Fatalf("root key: %v %s", err, got)
	}
	if ks, err := svc.List(ctx, "alice"); err != nil || len(ks) != 1 {
		t.Fatalf("root key listed under a user: %v %d", err, len(ks))
	}
	if err := svc.Delete(ctx, "alice", cred.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := accesskey.ProjectOf(ctx, b, cred.AccessKeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("index survives delete: %v", err)
	}
}

func TestDeleteCheckedKeepsTheKeyUnlessThePreconditionHolds(t *testing.T) {
	b := memstore.New()
	withUser(t, b, "frank")
	svc := accesskey.New(b, b, "proj-a", ring(t, "k", map[string][]byte{"k": kek(t)}), nil)
	ctx := context.Background()
	cred, err := svc.Create(ctx, "frank")
	if err != nil {
		t.Fatal(err)
	}
	kept := func(what string) {
		t.Helper()
		if _, err := svc.Get(ctx, "frank", cred.AccessKeyID); err != nil {
			t.Fatalf("%s deleted the key: %v", what, err)
		}
		if _, err := accesskey.ProjectOf(ctx, b, cred.AccessKeyID); err != nil {
			t.Fatalf("%s deleted the key index: %v", what, err)
		}
	}

	refused := errors.New("parent user moved")
	refuse := func(iam.AccessKey) (store.Pre, bool, error) { return store.Pre{}, false, refused }
	if err := svc.DeleteChecked(ctx, "frank", cred.AccessKeyID, refuse); !errors.Is(err, refused) {
		t.Fatalf("refused check: %v", err)
	}
	kept("a refused check")

	// The check reads the user; the user changes before the delete commits.
	u, err := store.Get[iam.User](ctx, b, "frank")
	if err != nil {
		t.Fatal(err)
	}
	stale := func(iam.AccessKey) (store.Pre, bool, error) {
		_, err := store.Mutate(ctx, b, "frank", func(u *iam.User) error {
			u.Path = "/moved/"
			return nil
		})
		return store.PreOf(u), true, err
	}
	if err := svc.DeleteChecked(ctx, "frank", cred.AccessKeyID, stale); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete after the user moved: %v, want ErrConflict", err)
	}
	kept("a stale precondition")

	current := func(iam.AccessKey) (store.Pre, bool, error) {
		u, err := store.Get[iam.User](ctx, b, "frank")
		return store.PreOf(u), true, err
	}
	if err := svc.DeleteChecked(ctx, "frank", cred.AccessKeyID, current); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, "frank", cred.AccessKeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("key after a delete under a holding precondition: %v", err)
	}
	if _, err := accesskey.ProjectOf(ctx, b, cred.AccessKeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("key index after the delete: %v", err)
	}
}
