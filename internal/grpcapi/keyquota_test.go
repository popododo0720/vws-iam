package grpcapi_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
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

// keysOf counts the stored access keys of user.
func keysOf(t *testing.T, b store.Backend, user string) int {
	t.Helper()
	all, err := store.List[iam.AccessKey](t.Context(), store.Scoped(b, proj))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, k := range all {
		if !k.Object.Root && store.Fold(k.Object.UserName) == store.Fold(user) {
			n++
		}
	}
	return n
}

func wantAccessKeysPerUser(t *testing.T, err error) {
	t.Helper()
	wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
	if got, want := status.Convert(err).Message(), "Cannot exceed quota for AccessKeysPerUser: 2"; got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
}

// TestAccessKeysPerUserStaleLock: a quota lock left by a crashed writer
// is taken over once its lease ends, and the third key is refused with
// the AWS message (#138).
func TestAccessKeysPerUserStaleLock(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	stale := iam.MembershipLock{
		Name: iam.MembershipLockKey, Epoch: 3, Holder: strings.Repeat("b", 64), Expires: now.Add(-time.Second),
	}
	if _, err := store.Create(ctx, store.Scoped(b, proj), stale); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	wantAccessKeysPerUser(t, err)
	if n := keysOf(t, b, "alice"); n != 2 {
		t.Fatalf("alice has %d keys, want 2", n)
	}
}

// TestConcurrentAccessKeysPerUserMemstore races key creates for one user
// across two replicas on one in-memory backend.
func TestConcurrentAccessKeysPerUserMemstore(t *testing.T) {
	testConcurrentAccessKeysPerUser(t, func(*testing.T) store.Backend { return memstore.New() })
}

// TestConcurrentAccessKeysPerUserOnAPIServer runs it on kubestore against
// a real kube-apiserver. It skips without KUBEBUILDER_ASSETS.
func TestConcurrentAccessKeysPerUserOnAPIServer(t *testing.T) {
	testConcurrentAccessKeysPerUser(t, apiServerBackends(t))
}

func testConcurrentAccessKeysPerUser(t *testing.T, backend func(*testing.T) store.Backend) {
	const creates = 10
	b := backend(t)
	a, rb, _, _ := replicas(t, b) // alice already has one key
	ctx := t.Context()
	var wg sync.WaitGroup
	errs := make(chan error, creates)
	for i := range creates {
		e := a
		if i%2 == 1 {
			e = rb
		}
		wg.Go(func() {
			_, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: userName("alice")})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	ok, refused := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case status.Code(err) == codes.ResourceExhausted:
			wantAccessKeysPerUser(t, err)
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || refused != creates-1 {
		t.Fatalf("%d accepted and %d refused, want 1 and %d", ok, refused, creates-1)
	}
	if n := keysOf(t, b, "alice"); n != 2 {
		t.Fatalf("alice has %d keys after concurrent creates, want 2", n)
	}
}

// stealOnKeyCreate takes the quota lock over (as a writer would after the
// lease ran out) right after the first access key is written.
type stealOnKeyCreate struct {
	store.Backend
	once  sync.Once
	t     *testing.T
	first string // stored key of the first access key
}

func (s *stealOnKeyCreate) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	v, err := s.Backend.Create(ctx, kind, key, spec)
	if err != nil || kind != iam.KindAccessKey {
		return v, err
	}
	s.once.Do(func() {
		s.first = key
		sb := store.Scoped(s.Backend, proj)
		l, gerr := store.Get[iam.MembershipLock](ctx, sb, iam.MembershipLockKey)
		if gerr != nil {
			s.t.Error(gerr)
			return
		}
		l.Object.Epoch++
		l.Object.Holder, l.Object.Expires = strings.Repeat("c", 64), time.Now().UTC().Add(-time.Second)
		if _, uerr := store.Update(ctx, sb, l.Object, l.Version); uerr != nil {
			s.t.Error(uerr)
		}
	})
	return v, err
}

// TestAccessKeyCreateLockLost: a key written after the lock moved is
// removed (key and index) and the create runs again, leaving one key.
func TestAccessKeyCreateLockLost(t *testing.T) {
	inner := memstore.New()
	b := &stealOnKeyCreate{Backend: inner, t: t}
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	name := k.GetAccessKey().GetName()
	if b.first == "" || strings.HasSuffix(b.first, name[strings.LastIndex(name, "/"):]) {
		t.Fatalf("the key written under the lost lock (%q) was returned", b.first)
	}
	if n := keysOf(t, inner, "alice"); n != 1 {
		t.Fatalf("alice has %d keys, want 1", n)
	}
	idx, err := store.List[iam.KeyIndex](ctx, inner)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx) != 1 || !strings.HasSuffix(k.GetAccessKey().GetName(), "/"+idx[0].Object.ID) {
		t.Fatalf("key index %v, want only %s", idx, k.GetAccessKey().GetName())
	}
}

// failKeyDelete is stealOnKeyCreate whose access key deletes fail while
// down is set, as if the writer died between writing its key and
// removing it.
type failKeyDelete struct {
	*stealOnKeyCreate
	down *atomic.Bool
}

func (f failKeyDelete) Delete(ctx context.Context, kind iam.Kind, key, version string) error {
	if kind == iam.KindAccessKey && f.down.Load() {
		return store.ErrUnavailable
	}
	return f.stealOnKeyCreate.Delete(ctx, kind, key, version)
}

func (f failKeyDelete) DeleteIf(ctx context.Context, kind iam.Kind, key, version string, pre store.Pre) error {
	if kind == iam.KindAccessKey && f.down.Load() {
		return store.ErrUnavailable
	}
	return f.stealOnKeyCreate.DeleteIf(ctx, kind, key, version, pre)
}

// TestAccessKeyCreateLockLostNoCleanup: a key written after its writer
// lost the quota lock, and never removed, is inert: it is not listed or
// counted and authenticates nothing (#138). While it cannot be removed a
// create stops before counting and fails UNAVAILABLE after a few sweep
// attempts (#139), so the user never passes two keys; once the store
// recovers the next create removes it.
func TestAccessKeyCreateLockLostNoCleanup(t *testing.T) {
	inner := memstore.New()
	var down atomic.Bool
	down.Store(true)
	b := failKeyDelete{&stealOnKeyCreate{Backend: inner, t: t}, &down}
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	_, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("create with an unremovable pending key: %v, want UNAVAILABLE", err)
	}
	if n := keysOf(t, inner, "alice"); n != 1 {
		t.Fatalf("alice has %d stored keys after the failed create, want only the orphan", n)
	}
	orphan := b.first[strings.LastIndex(b.first, "/")+1:]
	if orphan == "" {
		t.Fatal("no key was written under the lost lock")
	}
	ring, err := secret.NewKeyring("k1", map[string][]byte{"k1": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	svc := accesskey.New(store.Scoped(inner, proj), inner, proj, ring, nil)
	if _, err := svc.GetSigningCredential(ctx, orphan); !errors.Is(err, accesskey.ErrInactive) {
		t.Fatalf("orphan key %s signs: %v, want ErrInactive", orphan, err)
	}
	down.Store(false)
	for i := range 2 {
		if _, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()}); err != nil {
			t.Fatalf("key %d refused after the store recovered: %v", i+1, err)
		}
	}
	_, err = e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	wantAccessKeysPerUser(t, err)
	list, err := e.keys.ListAccessKeys(ctx, &iamv1.ListAccessKeysRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.GetAccessKeys()) != 2 {
		t.Fatalf("listed %d keys, want 2", len(list.GetAccessKeys()))
	}
	if _, err := store.Get[iam.AccessKey](ctx, store.Scoped(inner, proj), orphan); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("orphan key not swept: %v", err)
	}
	if n := keysOf(t, inner, "alice"); n != 2 {
		t.Fatalf("alice has %d stored keys, want 2", n)
	}
}

// flakyKeyDelete fails the first fails conditional access key deletes
// with store.ErrUnavailable and counts every one.
type flakyKeyDelete struct {
	store.Backend
	fails, calls atomic.Int32
}

func (f *flakyKeyDelete) DeleteIf(ctx context.Context, kind iam.Kind, key, version string, pre store.Pre) error {
	if kind == iam.KindAccessKey && f.calls.Add(1) <= f.fails.Load() {
		return store.ErrUnavailable
	}
	return f.Backend.DeleteIf(ctx, kind, key, version, pre)
}

// TestAccessKeyCreateRetriesFailedSweep: a create whose sweep cannot
// remove a stored pending key never counts past it (#139). A transient
// failure is retried and the create then succeeds with the key removed;
// a lasting one fails UNAVAILABLE after maxSweepAttempts (3) sweeps and
// writes nothing.
func TestAccessKeyCreateRetriesFailedSweep(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fails int32
		want  codes.Code
		calls int32
	}{
		{"transient", 1, codes.OK, 2},
		{"lasting", 1000, codes.Unavailable, 3}, // maxSweepAttempts
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := memstore.New()
			b := &flakyKeyDelete{Backend: inner}
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			u := e.createUser(t, ctx, "alice")
			ring, err := secret.NewKeyring("k1", map[string][]byte{"k1": make([]byte, 32)})
			if err != nil {
				t.Fatal(err)
			}
			svc := accesskey.New(store.Scoped(inner, proj), inner, proj, ring, nil)
			pending, _, err := svc.CreatePending(ctx, "alice", "")
			if err != nil {
				t.Fatal(err)
			}
			b.fails.Store(tc.fails)
			_, err = e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
			if status.Code(err) != tc.want {
				t.Fatalf("create: %v, want %v", err, tc.want)
			}
			if n := b.calls.Load(); n != tc.calls {
				t.Fatalf("%d conditional key deletes, want %d", n, tc.calls)
			}
			_, gerr := store.Get[iam.AccessKey](ctx, store.Scoped(inner, proj), pending.AccessKeyID)
			if n := keysOf(t, inner, "alice"); tc.want == codes.OK && (n != 1 || !errors.Is(gerr, store.ErrNotFound)) {
				t.Fatalf("after a retried sweep: %d keys, pending key %v; want 1 key and the pending one gone", n, gerr)
			} else if tc.want != codes.OK && (n != 1 || gerr != nil) {
				t.Fatalf("after a lasting sweep failure: %d keys, pending key %v; want only the pending key", n, gerr)
			}
		})
	}
}
