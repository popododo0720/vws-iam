package grpcapi_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestDeleteUserWithFidoKey: a user with a registered FIDO security key
// is not deleted (AWS DeleteConflict), so no key outlives its user; once
// the key is removed the user deletes. FIDO keys are registered through
// internal/mfa until vws-proto has a registration RPC (#133).
func TestDeleteUserWithFidoKey(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	fido := mfa.New(store.Scoped(b, proj), nil, proj, nil)
	cred := mfa.FidoCredential{ID: []byte("alice-credential-1"), PublicKey: []byte{0xa5}}
	d, err := fido.RegisterFido(ctx, "alice", "yubikey", cred)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()})
	wantErr(t, err, codes.FailedPrecondition, "DEPENDENCY_MISSING", "DeleteConflict")
	if _, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: u.GetName()}); err != nil {
		t.Fatalf("user deleted despite the conflict: %v", err)
	}
	if err := fido.DeactivateFido(ctx, "alice", fido.FidoSerial(d)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()}); err != nil {
		t.Fatalf("delete after removing the key: %v", err)
	}
}

// beforeFidoCreate runs hook once, just before the first FIDO device
// create reaches the backend.
type beforeFidoCreate struct {
	store.Backend
	once sync.Once
	hook func()
}

func (b *beforeFidoCreate) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	if kind == iam.KindFidoDevice {
		b.once.Do(b.hook)
	}
	return b.Backend.Create(ctx, kind, key, spec)
}

// TestDeleteUserDuringFidoRegistration: DeleteUser runs after
// RegisterFido read the user and before it created the device. The key
// must not outlive its user: registration fails, the key is not
// readable, and a new user with the same name neither inherits it nor is
// blocked from DeleteUser by it, and can register the same credential.
func TestDeleteUserDuringFidoRegistration(t *testing.T) {
	ctx := t.Context()
	b := &beforeFidoCreate{Backend: memstore.New()}
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	u := e.createUser(t, ctx, "alice")
	b.hook = func() {
		if _, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()}); err != nil {
			t.Errorf("DeleteUser during registration: %v", err)
		}
	}
	fido := mfa.New(store.Scoped(b, proj), nil, proj, nil)
	cred := mfa.FidoCredential{ID: []byte("alice-credential-1"), PublicKey: []byte{0xa5}}
	d, err := fido.RegisterFido(ctx, "alice", "yubikey", cred)
	if !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("RegisterFido racing DeleteUser = %+v, %v; want ErrNotAssociated", d, err)
	}
	u2 := e.createUser(t, ctx, "alice")
	if l, err := fido.ListFido(ctx, "alice"); err != nil || len(l) != 0 {
		t.Fatalf("new alice lists %d fido keys (%v), want 0", len(l), err)
	}
	if _, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u2.GetName()}); err != nil {
		t.Fatalf("delete of the new alice blocked by the old key: %v", err)
	}
	e.createUser(t, ctx, "alice")
	d, err = fido.RegisterFido(ctx, "alice", "yubikey", cred)
	if err != nil {
		t.Fatalf("register the credential to the new alice: %v", err)
	}
	if _, err := fido.GetFido(ctx, fido.FidoSerial(d), "alice"); err != nil {
		t.Fatalf("GetFido after re-registering: %v", err)
	}
}

// TestFidoOrphanAfterCrash: a device left behind by a registration that
// crashed after DeleteUser removed its user (stored, never undone) is
// invisible, does not block the next user with that name, and is
// replaced when its credential is registered again.
func TestFidoOrphanAfterCrash(t *testing.T) {
	ctx := t.Context()
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	u := e.createUser(t, ctx, "alice")
	sb := store.Scoped(b, proj)
	fido := mfa.New(sb, nil, proj, nil)
	cred := mfa.FidoCredential{ID: []byte("alice-credential-1"), PublicKey: []byte{0xa5}}
	d, err := fido.RegisterFido(ctx, "alice", "yubikey", cred)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the crash: the user goes away with the device still stored.
	if err := store.Delete[iam.User](ctx, sb, "alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: u.GetName()}); err == nil {
		t.Fatal("user still there")
	}
	u2 := e.createUser(t, ctx, "alice")
	if _, err := fido.GetFido(ctx, fido.FidoSerial(d), ""); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("orphan GetFido = %v, want ErrNotAssociated", err)
	}
	if err := fido.DeactivateFido(ctx, "alice", fido.FidoSerial(d)); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("orphan DeactivateFido = %v, want ErrNotAssociated", err)
	}
	if _, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u2.GetName()}); err != nil {
		t.Fatalf("orphan blocked DeleteUser: %v", err)
	}
	e.createUser(t, ctx, "alice")
	if _, err := fido.RegisterFido(ctx, "alice", "key2", cred); err != nil {
		t.Fatalf("re-register over the orphan: %v", err)
	}
	if _, err := fido.RegisterFido(ctx, "alice", "key3", cred); !errors.Is(err, mfa.ErrEntityInUse) {
		t.Fatalf("second register of an owned credential = %v, want ErrEntityInUse", err)
	}
}

// beforeUserDelete runs hook once, just before the first user delete
// reaches the backend.
type beforeUserDelete struct {
	store.Backend
	once sync.Once
	hook func()
}

func (b *beforeUserDelete) Delete(ctx context.Context, kind iam.Kind, key, version string) error {
	if kind == iam.KindUser {
		b.once.Do(b.hook)
	}
	return b.Backend.Delete(ctx, kind, key, version)
}

// TestFidoRegistrationDuringDeleteUser: a whole RegisterFido runs after
// DeleteUser listed the user's (no) FIDO keys and before its delete. Both
// must not succeed: the registration wins, DeleteUser fails, and the user
// and its readable key remain.
func TestFidoRegistrationDuringDeleteUser(t *testing.T) {
	ctx := t.Context()
	b := &beforeUserDelete{Backend: memstore.New()}
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	u := e.createUser(t, ctx, "alice")
	fido := mfa.New(store.Scoped(b, proj), nil, proj, nil)
	cred := mfa.FidoCredential{ID: []byte("alice-credential-1"), PublicKey: []byte{0xa5}}
	var d iam.FidoDevice
	var regErr error
	b.hook = func() { d, regErr = fido.RegisterFido(ctx, "alice", "yubikey", cred) }
	_, delErr := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()})
	if regErr != nil {
		t.Fatalf("RegisterFido during DeleteUser: %v", regErr)
	}
	if delErr == nil {
		t.Fatal("DeleteUser and RegisterFido both succeeded; the key is an orphan")
	}
	wantErr(t, delErr, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	if _, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: u.GetName()}); err != nil {
		t.Fatalf("user gone after the failed delete: %v", err)
	}
	if _, err := fido.GetFido(ctx, fido.FidoSerial(d), "alice"); err != nil {
		t.Fatalf("registered key not readable: %v", err)
	}
	_, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: u.GetName()})
	wantErr(t, err, codes.FailedPrecondition, "DEPENDENCY_MISSING", "DeleteConflict")
}

// TestFidoRegistrationSurvivesUserUpdate: an unrelated update of the
// user between RegisterFido's read and its commit does not fail the
// registration; the commit reads the user again and retries.
func TestFidoRegistrationSurvivesUserUpdate(t *testing.T) {
	ctx := t.Context()
	b := &beforeFidoCreate{Backend: memstore.New()}
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	u := e.createUser(t, ctx, "alice")
	sb := store.Scoped(b, proj)
	b.hook = func() {
		if _, err := store.Mutate(ctx, sb, "alice", func(u *iam.User) error {
			u.Labels = map[string]string{"team": "a"}
			return nil
		}); err != nil {
			t.Errorf("update during registration: %v", err)
		}
	}
	fido := mfa.New(sb, nil, proj, nil)
	cred := mfa.FidoCredential{ID: []byte("alice-credential-1"), PublicKey: []byte{0xa5}}
	d, err := fido.RegisterFido(ctx, "alice", "yubikey", cred)
	if err != nil {
		t.Fatalf("RegisterFido after an unrelated user update: %v", err)
	}
	if _, err := fido.GetFido(ctx, fido.FidoSerial(d), "alice"); err != nil {
		t.Fatalf("GetFido: %v", err)
	}
	got, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: u.GetName()})
	if err != nil || got.GetLabels()["team"] != "a" {
		t.Fatalf("GetUser = %v, %v; want the update kept", got.GetLabels(), err)
	}
}
