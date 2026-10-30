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

// TestReservedKeyIsInertUntilActivated is a writer that reserved its key
// under the quota lock and died before the user-fenced activation (#139):
// the key authenticates nothing, is not listed or counted, the next sweep
// removes it, and a sweep that won the race makes the activation fail.
func TestReservedKeyIsInertUntilActivated(t *testing.T) {
	b := memstore.New()
	withUser(t, b, "gina")
	svc := accesskey.New(b, b, "proj-a", ring(t, "k", map[string][]byte{"k": kek(t)}), nil)
	ctx := context.Background()
	lock := iam.MembershipLock{Name: iam.MembershipLockKey}
	lv, err := store.Create(ctx, b, lock)
	if err != nil {
		t.Fatal(err)
	}
	pre := store.PreOf(store.Versioned[iam.MembershipLock]{Object: lock, Version: lv})
	cred, version, err := svc.CreatePending(ctx, "gina", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reserve(ctx, cred.AccessKeyID, "stale", pre); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("reserve at a stale key version: %v, want ErrConflict", err)
	}
	reserved, err := svc.Reserve(ctx, cred.AccessKeyID, version, pre)
	if err != nil {
		t.Fatal(err)
	}
	if ks, err := svc.List(ctx, "gina"); err != nil || len(ks) != 0 {
		t.Fatalf("reserved key listed: %v %v", ks, err)
	}
	if _, err := svc.GetSigningCredential(ctx, cred.AccessKeyID); err == nil {
		t.Fatal("a reserved key authenticates")
	}
	if err := svc.SweepPending(ctx, "gina", pre); err != nil {
		t.Fatal(err)
	}
	u, err := store.Get[iam.User](ctx, b, "gina")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Activate(ctx, cred.AccessKeyID, reserved, store.PreOf(u)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("activate after the sweep: %v, want ErrNotFound", err)
	}
	if _, err := accesskey.ProjectOf(ctx, b, cred.AccessKeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("swept key index: %v", err)
	}
}

// failingKeyDelete fails every conditional delete of an access key with
// store.ErrUnavailable while on is set.
type failingKeyDelete struct {
	store.Backend
	on *bool
}

func (f failingKeyDelete) DeleteIf(ctx context.Context, kind iam.Kind, key, version string, pre store.Pre) error {
	if *f.on && kind == iam.KindAccessKey {
		return store.ErrUnavailable
	}
	return f.Backend.DeleteIf(ctx, kind, key, version, pre)
}

// TestFailedSweepOfReservedKeyFailsClosed is a writer that reserved its
// key and then lost the quota lock (the lease ran out) before its
// user-fenced activation (#139). The next holder's sweep cannot remove
// the reserved key: it must fail rather than let the holder count without
// it, or the paused writer's activation would make a third key. Once the
// sweep can remove the key, the paused activation fails and the user
// keeps at most accesskey.MaxPerUser keys.
func TestFailedSweepOfReservedKeyFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func() store.Backend
	}{
		{"memstore", func() store.Backend { return memstore.New() }},
		{"kubestore", func() store.Backend { return kubestore.New(fakeKube(), "vws-iam") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failing := false
			b := failingKeyDelete{Backend: tc.open(), on: &failing}
			withUser(t, b, "gina")
			svc := accesskey.New(b, b, "proj-a", ring(t, "k", map[string][]byte{"k": kek(t)}), nil)
			ctx := context.Background()
			if _, err := svc.Create(ctx, "gina"); err != nil {
				t.Fatal(err)
			}
			lock := iam.MembershipLock{Name: iam.MembershipLockKey, Epoch: 1}
			lv, err := store.Create(ctx, b, lock)
			if err != nil {
				t.Fatal(err)
			}
			hold1 := store.PreOf(store.Versioned[iam.MembershipLock]{Object: lock, Version: lv})
			u, err := store.Get[iam.User](ctx, b, "gina")
			if err != nil {
				t.Fatal(err)
			}
			userPre := store.PreOf(u)

			// The first writer reserves its key and pauses past its lease.
			paused, version, err := svc.CreatePending(ctx, "gina", "")
			if err != nil {
				t.Fatal(err)
			}
			reserved, err := svc.Reserve(ctx, paused.AccessKeyID, version, hold1)
			if err != nil {
				t.Fatal(err)
			}

			// The next writer takes the lock and sweeps; the delete fails.
			cur, err := store.Get[iam.MembershipLock](ctx, b, iam.MembershipLockKey)
			if err != nil {
				t.Fatal(err)
			}
			cur.Object.Epoch = 2
			lv2, err := store.Update(ctx, b, cur.Object, cur.Version)
			if err != nil {
				t.Fatal(err)
			}
			hold2 := store.PreOf(store.Versioned[iam.MembershipLock]{Object: cur.Object, Version: lv2})
			failing = true
			if err := svc.SweepPending(ctx, "gina", hold2); !errors.Is(err, store.ErrUnavailable) {
				t.Fatalf("sweep that could not remove a reserved key: %v, want ErrUnavailable", err)
			}

			// The next writer retries; now the sweep removes the key.
			failing = false
			if err := svc.SweepPending(ctx, "gina", hold2); err != nil {
				t.Fatalf("sweep: %v", err)
			}
			// A kubestore fence may advance the lock; the hold is still ours.
			cur, err = store.Get[iam.MembershipLock](ctx, b, iam.MembershipLockKey)
			if err != nil {
				t.Fatal(err)
			}
			if cur.Object.Epoch != 2 {
				t.Fatalf("lock epoch %d, want 2", cur.Object.Epoch)
			}
			hold2 = store.PreOf(cur)
			second, v2, err := svc.CreatePending(ctx, "gina", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.Activate(ctx, second.AccessKeyID, v2, hold2); err != nil {
				t.Fatalf("activate under the current hold: %v", err)
			}
			if err := svc.Activate(ctx, paused.AccessKeyID, reserved, userPre); err == nil {
				t.Fatal("the paused writer's swept key was activated")
			}
			ks, err := svc.List(ctx, "gina")
			if err != nil {
				t.Fatal(err)
			}
			if len(ks) > accesskey.MaxPerUser {
				t.Fatalf("user has %d keys, MaxPerUser is %d", len(ks), accesskey.MaxPerUser)
			}
		})
	}
}

// TestFailedSweepOfUnreservedKeyIsHousekeeping keeps the old behaviour for
// a pending key that was never reserved: it can never be activated, so a
// failed removal does not block the create.
func TestFailedSweepOfUnreservedKeyIsHousekeeping(t *testing.T) {
	failing := false
	b := failingKeyDelete{Backend: memstore.New(), on: &failing}
	withUser(t, b, "gina")
	svc := accesskey.New(b, b, "proj-a", ring(t, "k", map[string][]byte{"k": kek(t)}), nil)
	ctx := context.Background()
	lock := iam.MembershipLock{Name: iam.MembershipLockKey}
	lv, err := store.Create(ctx, b, lock)
	if err != nil {
		t.Fatal(err)
	}
	pre := store.PreOf(store.Versioned[iam.MembershipLock]{Object: lock, Version: lv})
	if _, _, err := svc.CreatePending(ctx, "gina", ""); err != nil {
		t.Fatal(err)
	}
	failing = true
	if err := svc.SweepPending(ctx, "gina", pre); err != nil {
		t.Fatalf("failed removal of an unreserved pending key: %v, want nil", err)
	}
}
