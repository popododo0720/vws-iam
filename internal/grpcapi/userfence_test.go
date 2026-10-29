package grpcapi_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// hookStore runs a hook once, before the next backend call of the armed
// kind and operation, so a test can interleave another request there.
type hookStore struct {
	store.Backend
	mu   sync.Mutex
	kind iam.Kind
	op   string
	hook func() error
}

func (h *hookStore) arm(kind iam.Kind, op string, hook func() error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.kind, h.op, h.hook = kind, op, hook
}

func (h *hookStore) fire(kind iam.Kind, op string) error {
	h.mu.Lock()
	hook := h.hook
	if hook == nil || kind != h.kind || op != h.op {
		h.mu.Unlock()
		return nil
	}
	h.hook = nil
	h.mu.Unlock()
	return hook()
}

func (h *hookStore) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	if err := h.fire(k, "get"); err != nil {
		return store.Entry{}, err
	}
	return h.Backend.Get(ctx, k, key)
}

func (h *hookStore) Update(ctx context.Context, k iam.Kind, key string, spec []byte, version string) (string, error) {
	if err := h.fire(k, "update"); err != nil {
		return "", err
	}
	return h.Backend.Update(ctx, k, key, spec, version)
}

func (h *hookStore) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if err := h.fire(k, "delete"); err != nil {
		return err
	}
	return h.Backend.Delete(ctx, k, key, version)
}

type fenceEnv struct {
	*env
	h    *hookStore
	now  *time.Time
	user *iamv1.User
	key  string
}

func newFenceEnv(t *testing.T) fenceEnv {
	t.Helper()
	now := time.Now().UTC()
	h := &hookStore{Backend: memstore.New()}
	e := newEnvOn(t, h, &now)
	op, err := e.users.CreateUser(t.Context(), &iamv1.CreateUserRequest{
		Parent: parentName, UserId: "carol", User: &iamv1.User{Spec: &iamv1.UserSpec{Path: "/allowed/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := unpack(t, op, &iamv1.User{})
	created, err := e.keys.CreateAccessKey(t.Context(), &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	return fenceEnv{env: e, h: h, now: &now, user: u, key: created.GetAccessKey().GetName()}
}

func (f fenceEnv) move(ctx context.Context, path string) error {
	_, err := f.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: f.user.GetName(), Spec: &iamv1.UserSpec{Path: path}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.path"}},
	})
	return err
}

func (f fenceEnv) deactivate(ctx context.Context) error {
	_, err := f.keys.UpdateAccessKey(ctx, &iamv1.UpdateAccessKeyRequest{
		AccessKey: &iamv1.AccessKey{
			Name: f.key, Spec: &iamv1.AccessKeySpec{State: iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE},
		},
		UpdateMask:      &fieldmaskpb.FieldMask{Paths: []string{"spec.state"}},
		ExpectedUserArn: f.user.GetStatus().GetArn(),
	})
	return err
}

func (f fenceEnv) del(ctx context.Context) error {
	req := &iamv1.DeleteAccessKeyRequest{Name: f.key, ExpectedUserArn: f.user.GetStatus().GetArn()}
	_, err := f.keys.DeleteAccessKey(ctx, req)
	return err
}

func (f fenceEnv) path(t *testing.T) string {
	t.Helper()
	u, err := f.users.GetUser(t.Context(), &iamv1.GetUserRequest{Name: f.user.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	return u.GetSpec().GetPath()
}

func (f fenceEnv) keyState(t *testing.T) iamv1.AccessKeyState {
	t.Helper()
	k, err := f.keys.GetAccessKey(t.Context(), &iamv1.GetAccessKeyRequest{Name: f.key})
	if err != nil {
		t.Fatal(err)
	}
	return k.GetSpec().GetState()
}

// TestAccessKeyARNMoveBeforeWrite interleaves an UpdateUser path move
// after the access key write read the user and before it pinned the ARN:
// the write is refused and the key is unchanged.
func TestAccessKeyARNMoveBeforeWrite(t *testing.T) {
	for _, op := range []string{"update", "delete"} {
		t.Run(op, func(t *testing.T) {
			f := newFenceEnv(t)
			ctx := t.Context()
			moved := false
			f.h.arm(iam.KindUser, "get", func() error {
				moved = true
				return f.move(ctx, "/denied/")
			})
			var err error
			if op == "update" {
				err = f.deactivate(ctx)
			} else {
				err = f.del(ctx)
			}
			if !moved {
				t.Fatal("the move did not run inside the key write")
			}
			wantErr(t, err, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
			if got := f.keyState(t); got != iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE {
				t.Fatalf("key state %v after a refused write, want ACTIVE", got)
			}
			if got := f.path(t); got != "/denied/" {
				t.Fatalf("user path %q, want /denied/", got)
			}
		})
	}
}

// TestAccessKeyARNMoveDuringWrite interleaves an UpdateUser path move
// between the ARN check and the key's compare-and-swap: the move is
// refused, so the key write commits against the ARN that is still current.
func TestAccessKeyARNMoveDuringWrite(t *testing.T) {
	for _, op := range []string{"update", "delete"} {
		t.Run(op, func(t *testing.T) {
			f := newFenceEnv(t)
			ctx := t.Context()
			var moveErr error
			f.h.arm(iam.KindAccessKey, op, func() error {
				moveErr = f.move(ctx, "/denied/")
				return nil
			})
			var err error
			if op == "update" {
				err = f.deactivate(ctx)
			} else {
				err = f.del(ctx)
			}
			if err != nil {
				t.Fatalf("key write: %v", err)
			}
			wantErr(t, moveErr, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
			if got := f.path(t); got != "/allowed/" {
				t.Fatalf("user path %q moved under a key write", got)
			}
			// The lease is released: the same move now succeeds.
			if err := f.move(ctx, "/denied/"); err != nil {
				t.Fatalf("move after the key write: %v", err)
			}
		})
	}
}

// TestAccessKeyARNLeaseExpires leaves a lease behind, as a holder that
// crashed before releasing it: path moves are refused until it expires,
// and changes that keep the path are never blocked.
func TestAccessKeyARNLeaseExpires(t *testing.T) {
	f := newFenceEnv(t)
	ctx := t.Context()
	// The key write succeeds; then the release's user update fails.
	f.h.arm(iam.KindAccessKey, "update", func() error {
		f.h.arm(iam.KindUser, "update", func() error { return store.ErrUnavailable })
		return nil
	})
	if err := f.deactivate(ctx); err != nil {
		t.Fatalf("key write: %v", err)
	}
	if got := f.keyState(t); got != iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE {
		t.Fatalf("key state %v, want INACTIVE", got)
	}
	wantErr(t, f.move(ctx, "/denied/"), codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
	if err := f.move(ctx, "/allowed/"); err != nil {
		t.Fatalf("an update that keeps the path was blocked: %v", err)
	}
	*f.now = f.now.Add(16 * time.Minute)
	if err := f.move(ctx, "/denied/"); err != nil {
		t.Fatalf("move after the lease expired: %v", err)
	}
}
