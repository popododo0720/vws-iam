package grpcapi_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestParallelRevokeMemstore runs N RevokeUserSessions at once across two
// replicas on one in-memory backend: no generation increment is lost.
func TestParallelRevokeMemstore(t *testing.T) {
	testParallelRevoke(t, func(*testing.T) store.Backend { return memstore.New() })
}

func TestParallelRevokeEtcd(t *testing.T) {
	testParallelRevoke(t, etcdBackend)
}

func testParallelRevoke(t *testing.T, backend func(*testing.T) store.Backend) {
	const n = 16
	b := backend(t)
	a, rb, _, _ := replicas(t, b)
	ctx := t.Context()
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := range n {
		e := a
		if i%2 == 1 {
			e = rb
		}
		rid := fmt.Sprintf("6f1c0a3e-8f7b-4b8e-9c55-%012d", i)
		for range 2 { // each request_id twice: the replay must not bump again
			wg.Go(func() {
				_, err := e.users.RevokeUserSessions(
					ctx,
					&iamv1.RevokeUserSessionsRequest{Name: parentName + "/users/alice", RequestId: rid},
				)
				errs <- err
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	u, err := store.Get[iam.User](ctx, store.Scoped(b, proj), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.Object.SessionsRevokeGeneration != n {
		t.Fatalf("generation %d after %d parallel revokes, want %d", u.Object.SessionsRevokeGeneration, n, n)
	}
}

// losingUserWrites loses every user write once on is set.
type losingUserWrites struct {
	store.Backend
	on atomic.Bool
}

func (l *losingUserWrites) Update(ctx context.Context, k iam.Kind, key string, spec []byte, v string) (string, error) {
	if k == iam.KindUser && l.on.Load() {
		return "", store.ErrConflict
	}
	return l.Backend.Update(ctx, k, key, spec, v)
}

// TestRevokeUnderContentionIsConcurrentModification: a RevokeUserSessions
// that loses every race until its server deadline answers ABORTED with
// ConcurrentModification, which a client may retry, never INTERNAL or a
// bare DEADLINE_EXCEEDED (#51). The server is called directly: over the
// wire a client deadline as short as the server's ends the call on the
// client first. Its retry after the contention succeeds.
func TestRevokeUnderContentionIsConcurrentModification(t *testing.T) {
	b := &losingUserWrites{Backend: memstore.New()}
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	e.createUser(t, t.Context(), "alice")
	b.on.Store(true)
	const rid = "6f1c0a3e-8f7b-4b8e-9c55-000000000001"
	req := &iamv1.RevokeUserSessionsRequest{Name: parentName + "/users/alice", RequestId: rid}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	_, err := e.api.RevokeUserSessions(ctx, req)
	wantErr(t, err, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
	b.on.Store(false)
	if _, err := e.users.RevokeUserSessions(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	u, err := store.Get[iam.User](t.Context(), store.Scoped(b, proj), "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.Object.SessionsRevokeGeneration != 1 {
		t.Fatalf("generation %d, want 1", u.Object.SessionsRevokeGeneration)
	}
}
