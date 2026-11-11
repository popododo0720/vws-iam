package grpcapi_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

type op = *longrunningpb.Operation

// onceCase is one update RPC that takes a request_id. send issues the
// same request for one rid each time, or with alt another request. state
// reads the generation of the object it changes and a count that moves
// only when the change is applied.
type onceCase struct {
	name  string
	setup func(t *testing.T, e *env) string
	send  func(ctx context.Context, e *env, target, rid string, alt bool) (op, error)
	state stateFn
}

type stateFn = func(t *testing.T, b store.Backend, target string) (gen int64, count int)

func stored[T iam.Object](key string, gen func(T) int64, count func(T) int) stateFn {
	return func(t *testing.T, b store.Backend, _ string) (int64, int) {
		t.Helper()
		v, err := store.Get[T](t.Context(), store.Scoped(b, proj), key)
		if err != nil {
			t.Fatal(err)
		}
		return gen(v.Object), count(v.Object)
	}
}

const onceDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`

func labelsMask() *fieldmaskpb.FieldMask { return &fieldmaskpb.FieldMask{Paths: []string{"labels"}} }

// labelsFor is the labels a send sets: alt adds a key.
func labelsFor(alt bool) map[string]string {
	if alt {
		return map[string]string{"k": "w", "x": "y"}
	}
	return map[string]string{"k": "v"}
}

// pick returns a, or b with alt.
func pick[T any](alt bool, a, b T) T {
	if alt {
		return b
	}
	return a
}

var (
	policyState = stored("p1", func(p iam.Policy) int64 { return p.Generation },
		func(p iam.Policy) int { return len(p.Versions) + len(p.Tags) + len(p.Labels) })
	mfaState = stored("d1", func(d iam.MfaDevice) int64 { return d.Generation },
		func(d iam.MfaDevice) int { return len(d.Tags) })
)

func seedPolicy(t *testing.T, e *env) string {
	return e.createPolicy(t, t.Context(), "p1", onceDoc).GetName()
}

func seedTaggedPolicy(t *testing.T, e *env) string {
	pol := seedPolicy(t, e)
	req := &iamv1.TagPolicyRequest{Name: pol, Tags: []*iamv1.Tag{tag("a", "1"), tag("b", "2")}}
	if _, err := e.policies.TagPolicy(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	return pol
}

func seedTaggedDevice(t *testing.T, e *env) string {
	d := createVirtualMfaDevice(t, e, t.Context(), "d1")
	req := &iamv1.TagMFADeviceRequest{Name: d.GetName(), Tags: []*iamv1.Tag{tag("a", "1"), tag("b", "2")}}
	if _, err := e.mfa.TagMFADevice(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	return d.GetName()
}

func seedPolicyVersions(t *testing.T, e *env) string {
	pol := seedPolicy(t, e)
	for range 2 {
		v := &iamv1.PolicyVersion{Spec: &iamv1.PolicyVersionSpec{Document: onceDoc}}
		req := &iamv1.CreatePolicyVersionRequest{Parent: pol, PolicyVersion: v}
		if _, err := e.policies.CreatePolicyVersion(t.Context(), req); err != nil {
			t.Fatal(err)
		}
	}
	return pol
}

func keyCase(name, arn string) onceCase {
	return onceCase{
		name: name,
		setup: func(t *testing.T, e *env) string {
			k, err := e.keys.CreateAccessKey(t.Context(), &iamv1.CreateAccessKeyRequest{Parent: parentName + "/users/alice"})
			if err != nil {
				t.Fatal(err)
			}
			return k.GetAccessKey().GetName()
		},
		send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
			return e.keys.UpdateAccessKey(ctx, &iamv1.UpdateAccessKeyRequest{
				AccessKey:  &iamv1.AccessKey{Name: target, Labels: labelsFor(alt)},
				UpdateMask: labelsMask(), ExpectedUserArn: arn, RequestId: rid,
			})
		},
		state: func(t *testing.T, b store.Backend, target string) (int64, int) {
			id := target[strings.LastIndex(target, "/")+1:]
			return stored(id, func(k iam.AccessKey) int64 { return k.Generation },
				func(k iam.AccessKey) int { return len(k.Labels) })(t, b, target)
		},
	}
}

func onceCases() []onceCase {
	alice := parentName + "/users/alice"
	return []onceCase{
		{
			name:  "UpdateUser",
			setup: func(*testing.T, *env) string { return alice },
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				u := &iamv1.User{Name: target, Labels: labelsFor(alt)}
				return e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{User: u, UpdateMask: labelsMask(), RequestId: rid})
			},
			state: stored("alice", func(u iam.User) int64 { return u.Generation },
				func(u iam.User) int { return len(u.Labels) }),
		},
		{
			name: "UpdateGroup",
			setup: func(t *testing.T, e *env) string {
				e.createGroupWith(t, "g1")
				return groupName("g1")
			},
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				g := &iamv1.Group{Name: target, Spec: &iamv1.GroupSpec{Members: []string{alice}}}
				mask := &fieldmaskpb.FieldMask{Paths: []string{"spec.members"}}
				if alt {
					g, mask = &iamv1.Group{Name: target, Labels: labelsFor(true)}, labelsMask()
				}
				return e.groups.UpdateGroup(ctx, &iamv1.UpdateGroupRequest{Group: g, UpdateMask: mask, RequestId: rid})
			},
			state: stored("g1", func(g iam.Group) int64 { return g.Generation },
				func(g iam.Group) int { return len(g.Members) + len(g.Labels) }),
		},
		{
			name: "UpdateRole",
			setup: func(t *testing.T, e *env) string {
				seedRole(t, e, "r1")
				return parentName + "/roles/r1"
			},
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				r := &iamv1.Role{Name: target, Labels: labelsFor(alt)}
				return e.roles.UpdateRole(ctx, &iamv1.UpdateRoleRequest{Role: r, UpdateMask: labelsMask(), RequestId: rid})
			},
			state: stored("r1", func(r iam.Role) int64 { return r.Generation }, func(r iam.Role) int { return len(r.Labels) }),
		},
		{
			name:  "UpdatePolicy",
			setup: seedPolicy,
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				pol := &iamv1.Policy{Name: target, Labels: labelsFor(alt)}
				req := &iamv1.UpdatePolicyRequest{Policy: pol, UpdateMask: labelsMask(), RequestId: rid}
				return e.policies.UpdatePolicy(ctx, req)
			},
			state: policyState,
		},
		{
			name:  "CreatePolicyVersion",
			setup: seedPolicy,
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				v := &iamv1.PolicyVersion{Spec: &iamv1.PolicyVersionSpec{Document: onceDoc, SetAsDefault: alt}}
				req := &iamv1.CreatePolicyVersionRequest{Parent: target, PolicyVersion: v, RequestId: rid}
				return e.policies.CreatePolicyVersion(ctx, req)
			},
			state: policyState,
		},
		{
			name:  "DeletePolicyVersion",
			setup: seedPolicyVersions,
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				name := target + pick(alt, "/versions/v2", "/versions/v3")
				return e.policies.DeletePolicyVersion(ctx, &iamv1.DeletePolicyVersionRequest{Name: name, RequestId: rid})
			},
			state: policyState,
		},
		{
			name:  "TagPolicy",
			setup: seedPolicy,
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				tags := pick(alt, []*iamv1.Tag{tag("Team", "a")}, []*iamv1.Tag{tag("Team", "a"), tag("Env", "b")})
				return e.policies.TagPolicy(ctx, &iamv1.TagPolicyRequest{Name: target, Tags: tags, RequestId: rid})
			},
			state: policyState,
		},
		{
			name:  "UntagPolicy",
			setup: seedTaggedPolicy,
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				keys := []string{pick(alt, "a", "b")}
				return e.policies.UntagPolicy(ctx, &iamv1.UntagPolicyRequest{Name: target, TagKeys: keys, RequestId: rid})
			},
			state: policyState,
		},
		{
			name:  "TagMFADevice",
			setup: seedTaggedDevice,
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				tags := []*iamv1.Tag{pick(alt, tag("c", "3"), tag("d", "4"))}
				return e.mfa.TagMFADevice(ctx, &iamv1.TagMFADeviceRequest{Name: target, Tags: tags, RequestId: rid})
			},
			state: mfaState,
		},
		{
			name:  "UntagMFADevice",
			setup: seedTaggedDevice,
			send: func(ctx context.Context, e *env, target, rid string, alt bool) (op, error) {
				keys := []string{pick(alt, "a", "b")}
				return e.mfa.UntagMFADevice(ctx, &iamv1.UntagMFADeviceRequest{Name: target, TagKeys: keys, RequestId: rid})
			},
			state: mfaState,
		},
		keyCase("UpdateAccessKey", ""),
		keyCase("UpdateAccessKeyExpectedUserARN", "arn:vws:iam::"+proj+":user/alice"),
	}
}

// deleteOperations removes every operation record, as a crash after the
// change and before done recorded it would leave the store.
func deleteOperations(t *testing.T, b store.Backend) {
	t.Helper()
	es, err := b.List(t.Context(), iam.KindOperation)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if err := b.Delete(t.Context(), iam.KindOperation, e.Key, ""); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRequestIDAppliesOnceMemstore runs every update RPC that takes a
// request_id at once from many callers with one request_id, across two
// replicas on one in-memory backend: the change is applied once and every
// caller gets the same operation (#50).
func TestRequestIDAppliesOnceMemstore(t *testing.T) {
	testRequestIDAppliesOnce(t, func(*testing.T) store.Backend { return memstore.New() })
}

func TestRequestIDAppliesOnceEtcd(t *testing.T) {
	testRequestIDAppliesOnce(t, etcdBackend)
}

func testRequestIDAppliesOnce(t *testing.T, backend func(*testing.T) store.Backend) {
	for _, c := range onceCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Run("Concurrent", func(t *testing.T) { onceConcurrent(t, c, backend(t)) })
			t.Run("CrashBeforeRecord", func(t *testing.T) { onceCrashBeforeRecord(t, c, backend(t)) })
			t.Run("OtherRequestSameID", func(t *testing.T) { onceOtherRequest(t, c, backend(t)) })
		})
	}
}

func onceConcurrent(t *testing.T, c onceCase, b store.Backend) {
	const n = 8
	a, rb, _, _ := replicas(t, b)
	target := c.setup(t, a)
	gen0, count0 := c.state(t, b, target)
	ctx := t.Context()
	ops := make([]op, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		e := a
		if i%2 == 1 {
			e = rb
		}
		wg.Go(func() { ops[i], errs[i] = c.send(ctx, e, target, "0b6e7c1a-5d2f-4e8a-9b3c-concurrent00", false) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if !proto.Equal(ops[i], ops[0]) {
			t.Fatalf("call %d answered %v, call 0 %v", i, ops[i], ops[0])
		}
	}
	gen, count := c.state(t, b, target)
	if gen != gen0+1 {
		t.Fatalf("generation %d after %d deliveries of one request, want %d", gen, n, gen0+1)
	}
	again, err := c.send(ctx, rb, target, "0b6e7c1a-5d2f-4e8a-9b3c-concurrent00", false)
	if err != nil || !proto.Equal(again, ops[0]) {
		t.Fatalf("replay answered %v, %v; want %v", again, err, ops[0])
	}
	if g, n := c.state(t, b, target); g != gen || n != count {
		t.Fatalf("replay changed the object: generation %d count %d, want %d %d", g, n, gen, count)
	}
	if count == count0 {
		t.Fatalf("count %d unchanged: the request was not applied", count)
	}
}

// onceCrashBeforeRecord applies a request, loses its operation record and
// retries it on a new replica: the object records the request, so the
// retry succeeds and changes nothing.
func onceCrashBeforeRecord(t *testing.T, c onceCase, b store.Backend) {
	a, _, _, _ := replicas(t, b)
	target := c.setup(t, a)
	ctx := t.Context()
	const rid = "crash-before-record"
	if _, err := c.send(ctx, a, target, rid, false); err != nil {
		t.Fatal(err)
	}
	gen, count := c.state(t, b, target)
	deleteOperations(t, b)
	now := *a.now
	restarted := newEnvOn(t, b, &now)
	if _, err := c.send(ctx, restarted, target, rid, false); err != nil {
		t.Fatalf("retry after a lost record: %v", err)
	}
	if g, n := c.state(t, b, target); g != gen || n != count {
		t.Fatalf("retry applied again: generation %d count %d, want %d %d", g, n, gen, count)
	}
}

// onceOtherRequest sends another request under a request_id whose record
// was lost: it is IdempotentParameterMismatch and changes nothing.
func onceOtherRequest(t *testing.T, c onceCase, b store.Backend) {
	a, _, _, _ := replicas(t, b)
	target := c.setup(t, a)
	ctx := t.Context()
	const rid = "other-request"
	if _, err := c.send(ctx, a, target, rid, false); err != nil {
		t.Fatal(err)
	}
	gen, count := c.state(t, b, target)
	deleteOperations(t, b)
	_, err := c.send(ctx, a, target, rid, true)
	wantErr(t, err, codes.Aborted, "IDEMPOTENCY_CONFLICT", "IdempotentParameterMismatch")
	if g, n := c.state(t, b, target); g != gen || n != count {
		t.Fatalf("mismatched request applied: generation %d count %d, want %d %d", g, n, gen, count)
	}
}

// TestRequestTokensAreBounded applies more distinct request_ids than an
// object keeps: the oldest tokens are dropped and the object stays valid.
func TestRequestTokensAreBounded(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	pol := e.createPolicy(t, ctx, "p1", onceDoc)
	for i := range iam.MaxRequests + 3 {
		req := &iamv1.TagPolicyRequest{
			Name: pol.GetName(), Tags: []*iamv1.Tag{tag("n", fmt.Sprint(i))}, RequestId: fmt.Sprintf("rid-%d", i),
		}
		if _, err := e.policies.TagPolicy(ctx, req); err != nil {
			t.Fatalf("tag %d: %v", i, err)
		}
	}
	v, err := store.Get[iam.Policy](ctx, store.Scoped(b, proj), "p1")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Object.Requests) != iam.MaxRequests {
		t.Fatalf("%d request tokens, want %d", len(v.Object.Requests), iam.MaxRequests)
	}
	for _, tok := range v.Object.Requests {
		if strings.Contains(tok, "rid-") {
			t.Fatalf("token %q carries the request_id", tok)
		}
	}
}

// barrier holds every Update of kind until n have arrived, so n racing
// requests all read before any of them writes.
type barrier struct {
	store.Backend
	kind  iam.Kind
	n     int
	mu    sync.Mutex
	ready chan struct{}
}

func (b *barrier) Update(ctx context.Context, kind iam.Kind, key string, spec []byte, version string) (string, error) {
	if kind == b.kind {
		b.mu.Lock()
		if b.n--; b.n == 0 {
			close(b.ready)
		}
		b.mu.Unlock()
		select {
		case <-b.ready:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	return b.Backend.Update(ctx, kind, key, spec, version)
}

// TestRequestIDDuplicatesWithEtag: two deliveries of one request with an
// etag both read before either writes. The loser's write conflicts; it
// reads again, finds the winner's token and answers with its operation,
// not ETAG_MISMATCH.
func TestRequestIDDuplicatesWithEtag(t *testing.T) {
	b := &barrier{Backend: memstore.New(), kind: iam.KindUser, n: 2, ready: make(chan struct{})}
	a, rb, _, _ := replicas(t, b)
	ctx := t.Context()
	u, err := a.users.GetUser(ctx, &iamv1.GetUserRequest{Name: parentName + "/users/alice"})
	if err != nil {
		t.Fatal(err)
	}
	req := &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: u.GetName(), Etag: u.GetEtag(), Labels: labelsFor(false)},
		UpdateMask: labelsMask(), RequestId: "with-etag",
	}
	var ops [2]op
	var errs [2]error
	var wg sync.WaitGroup
	wg.Go(func() { ops[0], errs[0] = a.users.UpdateUser(ctx, req) })
	wg.Go(func() { ops[1], errs[1] = rb.users.UpdateUser(ctx, req) })
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || !proto.Equal(ops[0], ops[1]) {
		t.Fatalf("duplicates answered %v, %v; want one operation twice", errs, ops)
	}
	gen, _ := stored("alice", func(u iam.User) int64 { return u.Generation }, func(iam.User) int { return 0 })(t, b, "")
	if gen != u.GetGeneration()+1 {
		t.Fatalf("generation %d, want %d", gen, u.GetGeneration()+1)
	}
	stale := &iamv1.UpdateUserRequest{User: req.GetUser(), UpdateMask: labelsMask(), RequestId: "other"}
	_, err = a.users.UpdateUser(ctx, stale)
	wantErr(t, err, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
}

// TestRequestIDGroupUpsert: an UpdateGroup with allow_missing that creates
// the group records its token in that create, with or without members, so
// a retry after a lost operation record changes nothing.
func TestRequestIDGroupUpsert(t *testing.T) {
	for _, members := range [][]string{nil, {parentName + "/users/alice"}} {
		t.Run(fmt.Sprintf("members=%d", len(members)), func(t *testing.T) {
			b := memstore.New()
			a, _, _, _ := replicas(t, b)
			ctx := t.Context()
			req := &iamv1.UpdateGroupRequest{
				Group: &iamv1.Group{
					Name: groupName("g2"), Labels: labelsFor(false), Spec: &iamv1.GroupSpec{Members: members},
				},
				UpdateMask:   &fieldmaskpb.FieldMask{Paths: []string{"labels", "spec.members"}},
				AllowMissing: true, RequestId: "upsert",
			}
			state := stored("g2", func(g iam.Group) int64 { return g.Generation },
				func(g iam.Group) int { return len(g.Members) })
			if _, err := a.groups.UpdateGroup(ctx, req); err != nil {
				t.Fatal(err)
			}
			gen, n := state(t, b, "")
			if n != len(members) {
				t.Fatalf("%d members, want %d", n, len(members))
			}
			deleteOperations(t, b)
			if _, err := a.groups.UpdateGroup(ctx, req); err != nil {
				t.Fatalf("retry after a lost record: %v", err)
			}
			if g, m := state(t, b, ""); g != gen || m != n {
				t.Fatalf("retry applied again: generation %d members %d, want %d %d", g, m, gen, n)
			}
		})
	}
}
