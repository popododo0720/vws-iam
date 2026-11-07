package grpcapi_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func (e *env) createGroupRequest(
	ctx context.Context, id, requestID string, members ...string,
) (*longrunningpb.Operation, error) {
	return e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{
		Parent: parentName, GroupId: id, RequestId: requestID,
		Group: &iamv1.Group{Spec: &iamv1.GroupSpec{Members: members}},
	})
}

// TestCreateGroupRequestIDRace: a CreateGroup with members stages the
// group empty and then adds the members. A second delivery of the same
// request_id on another replica that adopts the staged group and adds the
// members first must not turn the first delivery into ABORTED: both answer
// the one recorded operation, and one group with the members is stored
// (#162).
func TestCreateGroupRequestIDRace(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			other := newEnvOn(t, b, &now)
			h := &hooked{Backend: b}
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			other.createUser(t, ctx, "alice")
			var second *longrunningpb.Operation
			h.at("create", iam.KindMemberLock, "", func() error {
				var err error
				second, err = other.createGroupRequest(ctx, "dup", "req-162", userName("alice"))
				return err
			})
			first, err := e.createGroupRequest(ctx, "dup", "req-162", userName("alice"))
			if err != nil {
				t.Fatalf("first delivery: %v", err)
			}
			if second == nil {
				t.Fatal("the second delivery did not run inside the first")
			}
			if !proto.Equal(first, second) {
				t.Fatalf("deliveries answered differently:\n%v\n%v", first, second)
			}
			g := unpack(t, first, &iamv1.Group{})
			if m := g.GetSpec().GetMembers(); len(m) != 1 || m[0] != userName("alice") {
				t.Fatalf("members %v, want alice", m)
			}
			assertOneGroup(t, b, "dup", g.GetUid())
		})
	}
}

// TestConcurrentCreateGroupRequestID: deliveries of one CreateGroup
// request_id racing on two replicas all succeed with one answer.
func TestConcurrentCreateGroupRequestID(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			a, rb, _, _ := replicas(t, b)
			ctx := t.Context()
			const n = 8
			ops := make([]*longrunningpb.Operation, n)
			errs := make([]error, n)
			var wg sync.WaitGroup
			for i := range n {
				e := a
				if i%2 == 1 {
					e = rb
				}
				wg.Go(func() {
					ops[i], errs[i] = e.createGroupRequest(ctx, "dup", "req-162", userName("alice"))
				})
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("delivery %d: %v (%s)", i, err, status.Code(err))
				}
				if !proto.Equal(ops[i], ops[0]) {
					t.Fatalf("delivery %d answered differently:\n%v\n%v", i, ops[i], ops[0])
				}
			}
			assertOneGroup(t, b, "dup", unpack(t, ops[0], &iamv1.Group{}).GetUid())
		})
	}
}

// TestCreateGroupRequestIDOtherWriterStillAborts: when another request
// changes the members of the staged group first, the create is not
// answered as if it had applied.
func TestCreateGroupRequestIDOtherWriterStillAborts(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			other := newEnvOn(t, b, &now)
			h := &hooked{Backend: b}
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			other.createUser(t, ctx, "alice")
			other.createUser(t, ctx, "bob")
			h.at("create", iam.KindMemberLock, "", func() error {
				return other.setMembers(ctx, "dup", "", false, userName("bob"))
			})
			_, err := e.createGroupRequest(ctx, "dup", "req-162", userName("alice"))
			if status.Code(err) != codes.Aborted {
				t.Fatalf("got %v, want ABORTED", err)
			}
		})
	}
}

func assertOneGroup(t *testing.T, b store.Backend, name, uid string) {
	t.Helper()
	all, err := store.List[iam.Group](t.Context(), store.Scoped(b, proj))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Object.Name != name || all[0].Object.UID != uid {
		t.Fatalf("stored groups %v, want one %s with uid %s", all, name, uid)
	}
}
