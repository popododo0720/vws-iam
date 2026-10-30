package grpcapi_test

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

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
