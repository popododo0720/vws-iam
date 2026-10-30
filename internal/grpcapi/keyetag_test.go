package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// etagFixture is an env and, on the same store, a server called directly
// for the user etag that vws-proto does not carry yet (#139).
type etagFixture struct {
	e   *env
	b   store.Backend
	api *grpcapi.Server
}

func newEtagFixture(t *testing.T, b store.Backend) etagFixture {
	t.Helper()
	now := time.Now().UTC()
	keys, err := secret.NewKeyring("k1", map[string][]byte{"k1": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	api := grpcapi.New(b, keys, grpcapi.WithClock(func() time.Time { return now }))
	return etagFixture{e: newEnvOn(t, b, &now), b: b, api: api}
}

// etag is the user's current etag.
func (f etagFixture) etag(t *testing.T, user string) string {
	t.Helper()
	u, err := f.e.users.GetUser(t.Context(), &iamv1.GetUserRequest{Name: user})
	if err != nil {
		t.Fatal(err)
	}
	return u.GetEtag()
}

func (f etagFixture) create(t *testing.T, user, etag string) (*iamv1.CreateAccessKeyResponse, error) {
	t.Helper()
	return f.api.CreateAccessKeyUserEtag(t.Context(), &iamv1.CreateAccessKeyRequest{Parent: user}, etag)
}

func (f etagFixture) remove(t *testing.T, key, etag string) error {
	t.Helper()
	_, err := f.api.DeleteAccessKeyUserEtag(t.Context(), &iamv1.DeleteAccessKeyRequest{Name: key}, etag)
	return err
}

// keys fails unless user has n listed keys and no committed key is
// hidden: every stored key of the project is listed or pending.
func (f etagFixture) keys(t *testing.T, user string, n int) {
	t.Helper()
	got, err := f.e.keys.ListAccessKeys(t.Context(), &iamv1.ListAccessKeysRequest{Parent: user})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetAccessKeys()) != n {
		t.Fatalf("%s has %d access keys, want %d", user, len(got.GetAccessKeys()), n)
	}
	all, err := store.List[iam.AccessKey](t.Context(), store.Scoped(f.b, proj))
	if err != nil {
		t.Fatal(err)
	}
	active := 0
	for _, k := range all {
		if k.Object.Status != iam.KeyPending {
			active++
		}
	}
	if active != n {
		t.Fatalf("%d committed access keys stored, want %d", active, n)
	}
}

func TestAccessKeyUserEtag(t *testing.T) {
	f := newEtagFixture(t, memstore.New())
	ctx := t.Context()
	u := f.e.createUser(t, ctx, "alice")
	read := f.etag(t, u.GetName())
	if read == "" {
		t.Fatal("user has no etag")
	}

	// Hostile or malformed etags are rejected before any read or write.
	for _, bad := range []string{"1 2", "x\n", strings.Repeat("9", 129), "é"} {
		_, err := f.create(t, u.GetName(), bad)
		wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	}
	f.keys(t, u.GetName(), 0)

	// The user moves after the caller read it: the stale etag creates
	// nothing.
	f.e.updateUserPath(t, u.GetName(), "/moved/")
	_, err := f.create(t, u.GetName(), read)
	wantErr(t, err, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	f.keys(t, u.GetName(), 0)
	_, err = f.create(t, parentName+"/users/nobody", read)
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")

	// The current etag creates a key; no etag keeps the old behavior.
	created, err := f.create(t, u.GetName(), f.etag(t, u.GetName()))
	if err != nil {
		t.Fatalf("create with the current etag: %v", err)
	}
	state := created.GetAccessKey().GetSpec().GetState()
	if created.GetSecretAccessKey() == "" || state != iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE {
		t.Fatalf("created key: %v", created.GetAccessKey())
	}
	if _, err := f.create(t, u.GetName(), ""); err != nil {
		t.Fatalf("create without an etag: %v", err)
	}
	f.keys(t, u.GetName(), 2)

	// Delete: a stale etag deletes nothing, the current one deletes.
	key := created.GetAccessKey().GetName()
	read = f.etag(t, u.GetName())
	f.e.updateUserPath(t, u.GetName(), "/again/")
	wantErr(t, f.remove(t, key, read), codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
	wantErr(t, f.remove(t, key, "bad etag"), codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	f.keys(t, u.GetName(), 2)
	if err := f.remove(t, key, f.etag(t, u.GetName())); err != nil {
		t.Fatalf("delete with the current etag: %v", err)
	}
	f.keys(t, u.GetName(), 1)
}

// TestAccessKeyUserEtagMoveBeforeCommit is the concurrent case: the user
// moves after the server matched the etag and before the key write
// commits. The create must make no key and the delete must keep the key,
// both ABORTED, on both backends.
func TestAccessKeyUserEtagMoveBeforeCommit(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(p *trap) store.Backend
	}{
		{"memstore", func(p *trap) store.Backend { return trapped{Backend: memstore.New(), p: p} }},
		{"kubestore", trappedKube},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &trap{}
			f := newEtagFixture(t, tc.open(p))
			ctx := t.Context()
			u := f.e.createUser(t, ctx, "carol")
			moved := false
			move := func(path string) func() {
				return func() {
					f.e.updateUserPath(t, u.GetName(), path)
					moved = true
				}
			}

			p.arm(move("/denied/"))
			_, err := f.create(t, u.GetName(), f.etag(t, u.GetName()))
			wantErr(t, err, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
			if !moved {
				t.Fatal("the move did not run inside the create")
			}
			f.keys(t, u.GetName(), 0)

			created, err := f.e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
			if err != nil {
				t.Fatal(err)
			}
			key := created.GetAccessKey().GetName()
			moved = false
			p.arm(move("/allowed/"))
			err = f.remove(t, key, f.etag(t, u.GetName()))
			wantErr(t, err, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
			if !moved {
				t.Fatal("the move did not run inside the delete")
			}
			f.keys(t, u.GetName(), 1)

			// With nothing moving, the current etag creates and deletes.
			second, err := f.create(t, u.GetName(), f.etag(t, u.GetName()))
			if err != nil {
				t.Fatalf("create with the current etag: %v", err)
			}
			f.keys(t, u.GetName(), 2)
			if err := f.remove(t, second.GetAccessKey().GetName(), f.etag(t, u.GetName())); err != nil {
				t.Fatalf("delete with the current etag: %v", err)
			}
			f.keys(t, u.GetName(), 1)
		})
	}
}

// updateUserPath is UpdateUser moving user to path, which changes its
// etag and ARN.
func (e *env) updateUserPath(t *testing.T, user, path string) {
	t.Helper()
	_, err := e.users.UpdateUser(t.Context(), &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: user, Spec: &iamv1.UserSpec{Path: path}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.path"}},
	})
	if err != nil {
		t.Fatalf("UpdateUser %s to %s: %v", user, path, err)
	}
}
