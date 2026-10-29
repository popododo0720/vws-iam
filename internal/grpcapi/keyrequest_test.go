package grpcapi_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const rid = "6f1c2b9e-4d3a-4b8e-9a7f-2c5d1e0f3a4b"

// createKeyWith calls CreateAccessKey on e with a request_id.
func createKeyWith(ctx context.Context, e *env, parent, id string) (*iamv1.CreateAccessKeyResponse, error) {
	return e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: parent, RequestId: id})
}

// newEnvOnShared starts one replica on b with its own clock.
func newEnvOnShared(t *testing.T, b store.Backend) *env {
	t.Helper()
	now := time.Now().UTC()
	return newEnvOn(t, b, &now)
}

func keyID(k *iamv1.CreateAccessKeyResponse) string {
	n := k.GetAccessKey().GetName()
	return n[strings.LastIndex(n, "/")+1:]
}

// wantRepeat checks a repeated request_id: ALREADY_EXISTS naming the key
// first created with it, and never a secret.
func wantRepeat(t *testing.T, resp *iamv1.CreateAccessKeyResponse, err error, first *iamv1.CreateAccessKeyResponse) {
	t.Helper()
	wantErr(t, err, codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
	if resp.GetSecretAccessKey() != "" {
		t.Fatal("a repeated request_id returned a secret")
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, keyID(first)) {
		t.Fatalf("message %q does not name key %s", msg, keyID(first))
	}
	if strings.Contains(msg, first.GetSecretAccessKey()) {
		t.Fatal("the message carries the secret")
	}
}

// TestCreateAccessKeyRequestID: a repeated CreateAccessKey request_id is
// ALREADY_EXISTS naming the key, without its secret, on any replica and
// after a restart; other ids, and no id, create keys (#137).
func TestCreateAccessKeyRequestID(t *testing.T) {
	t.Run("RepeatIsAlreadyExists", func(t *testing.T) {
		b := memstore.New()
		e := newEnvOnShared(t, b)
		ctx := t.Context()
		u := e.createUser(t, ctx, "alice")
		first, err := createKeyWith(ctx, e, u.GetName(), rid)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := createKeyWith(ctx, e, u.GetName(), rid)
		wantRepeat(t, resp, err, first)
		// Another replica, or this one restarted, reads it from the store.
		other := newEnvOnShared(t, b)
		resp, err = createKeyWith(ctx, other, u.GetName(), rid)
		wantRepeat(t, resp, err, first)
		if n := keysOf(t, b, "alice"); n != 1 {
			t.Fatalf("alice has %d keys, want 1", n)
		}
	})
	t.Run("RepeatAtQuotaIsAlreadyExists", func(t *testing.T) {
		b := memstore.New()
		e := newEnvOnShared(t, b)
		ctx := t.Context()
		u := e.createUser(t, ctx, "alice")
		if _, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()}); err != nil {
			t.Fatal(err)
		}
		first, err := createKeyWith(ctx, e, u.GetName(), rid)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := createKeyWith(ctx, e, u.GetName(), rid)
		wantRepeat(t, resp, err, first)
	})
	t.Run("DifferentIDsCreateTwoKeys", func(t *testing.T) {
		b := memstore.New()
		e := newEnvOnShared(t, b)
		ctx := t.Context()
		u := e.createUser(t, ctx, "alice")
		for _, id := range []string{rid, "0d9e8f7a-6b5c-4d3e-8f1a-2b3c4d5e6f70"} {
			if _, err := createKeyWith(ctx, e, u.GetName(), id); err != nil {
				t.Fatal(err)
			}
		}
		if n := keysOf(t, b, "alice"); n != 2 {
			t.Fatalf("alice has %d keys, want 2", n)
		}
	})
	t.Run("ScopedToUser", func(t *testing.T) {
		b := memstore.New()
		e := newEnvOnShared(t, b)
		ctx := t.Context()
		for _, n := range []string{"alice", "bob"} {
			u := e.createUser(t, ctx, n)
			if _, err := createKeyWith(ctx, e, u.GetName(), rid); err != nil {
				t.Fatalf("%s: %v", n, err)
			}
		}
	})
	t.Run("EmptyIDIsNotIdempotent", func(t *testing.T) {
		b := memstore.New()
		e := newEnvOnShared(t, b)
		ctx := t.Context()
		u := e.createUser(t, ctx, "alice")
		for range 2 {
			if _, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()}); err != nil {
				t.Fatal(err)
			}
		}
		if n := keysOf(t, b, "alice"); n != 2 {
			t.Fatalf("alice has %d keys, want 2", n)
		}
	})
	t.Run("DeletedKeyFreesTheID", func(t *testing.T) {
		b := memstore.New()
		e := newEnvOnShared(t, b)
		ctx := t.Context()
		u := e.createUser(t, ctx, "alice")
		first, err := createKeyWith(ctx, e, u.GetName(), rid)
		if err != nil {
			t.Fatal(err)
		}
		del := &iamv1.DeleteAccessKeyRequest{Name: first.GetAccessKey().GetName()}
		if _, err := e.keys.DeleteAccessKey(ctx, del); err != nil {
			t.Fatal(err)
		}
		if _, err := createKeyWith(ctx, e, u.GetName(), rid); err != nil {
			t.Fatalf("create after deleting the key: %v", err)
		}
	})
}

// TestCreateAccessKeyRequestIDValidation: a request_id outside 1 to 64
// characters of [A-Za-z0-9_-] is INVALID_ARGUMENT and creates nothing.
func TestCreateAccessKeyRequestIDValidation(t *testing.T) {
	b := memstore.New()
	e := newEnvOnShared(t, b)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	for _, id := range []string{strings.Repeat("a", 65), "has space", "semi;colon", "slash/", "\u00e9", "new\nline"} {
		_, err := createKeyWith(ctx, e, u.GetName(), id)
		wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	}
	if n := keysOf(t, b, "alice"); n != 0 {
		t.Fatalf("alice has %d keys, want 0", n)
	}
	if _, err := createKeyWith(ctx, e, u.GetName(), strings.Repeat("a", 64)); err != nil {
		t.Fatalf("64-character request_id: %v", err)
	}
}

// TestConcurrentAccessKeyRequestIDMemstore races creates with one
// request_id across two replicas on one in-memory backend.
func TestConcurrentAccessKeyRequestIDMemstore(t *testing.T) {
	testConcurrentAccessKeyRequestID(t, func(*testing.T) store.Backend { return memstore.New() })
}

// TestConcurrentAccessKeyRequestIDOnAPIServer runs it on kubestore
// against a real kube-apiserver. It skips without KUBEBUILDER_ASSETS.
func TestConcurrentAccessKeyRequestIDOnAPIServer(t *testing.T) {
	testConcurrentAccessKeyRequestID(t, apiServerBackends(t))
}

func testConcurrentAccessKeyRequestID(t *testing.T, backend func(*testing.T) store.Backend) {
	const creates = 8
	b := backend(t)
	a, rb, _, _ := replicas(t, b) // alice already has one key
	ctx := t.Context()
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		won  []*iamv1.CreateAccessKeyResponse
		errs []error
	)
	for i := range creates {
		e := a
		if i%2 == 1 {
			e = rb
		}
		wg.Go(func() {
			resp, err := createKeyWith(ctx, e, userName("alice"), rid)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				won = append(won, resp)
				return
			}
			if resp.GetSecretAccessKey() != "" {
				t.Error("a refused create returned a secret")
			}
			errs = append(errs, err)
		})
	}
	wg.Wait()
	if len(won) != 1 {
		t.Fatalf("%d creates succeeded, want 1 (errors %v)", len(won), errs)
	}
	for _, err := range errs {
		wantRepeat(t, nil, err, won[0])
	}
	if n := keysOf(t, b, "alice"); n != 2 {
		t.Fatalf("alice has %d keys after concurrent creates, want 2", n)
	}
}

// TestCreateAccessKeyRequestIDPendingKey: a pending key left with the
// request_id by a writer that lost its quota lock is inert and never
// activated, so it does not answer a repeat; the create sweeps it and
// makes the one key.
func TestCreateAccessKeyRequestIDPendingKey(t *testing.T) {
	b := memstore.New()
	e := newEnvOnShared(t, b)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	ring, err := secret.NewKeyring("k1", map[string][]byte{"k1": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	svc := accesskey.New(store.Scoped(b, proj), b, proj, ring, nil)
	orphan, _, err := svc.CreatePending(ctx, "alice", rid)
	if err != nil {
		t.Fatal(err)
	}
	first, err := createKeyWith(ctx, e, u.GetName(), rid)
	if err != nil {
		t.Fatalf("create with a pending key holding the request_id: %v", err)
	}
	if keyID(first) == orphan.AccessKeyID {
		t.Fatal("the pending key was returned")
	}
	_, err = store.Get[iam.AccessKey](ctx, store.Scoped(b, proj), orphan.AccessKeyID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("pending key not swept: %v", err)
	}
	resp, err := createKeyWith(ctx, e, u.GetName(), rid)
	wantRepeat(t, resp, err, first)
	if n := keysOf(t, b, "alice"); n != 1 {
		t.Fatalf("alice has %d keys, want 1", n)
	}
}
