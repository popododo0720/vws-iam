package grpcapi_test

import (
	"fmt"
	"sync"
	"testing"

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

// TestParallelRevokeOnAPIServer runs it on kubestore against a real
// kube-apiserver. It skips without KUBEBUILDER_ASSETS.
func TestParallelRevokeOnAPIServer(t *testing.T) {
	testParallelRevoke(t, apiServerBackends(t))
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
				_, err := e.users.RevokeUserSessions(ctx, &iamv1.RevokeUserSessionsRequest{Name: parentName + "/users/alice", RequestId: rid})
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
