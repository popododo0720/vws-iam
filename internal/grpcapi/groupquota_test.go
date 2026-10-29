package grpcapi_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

var membersMask = &fieldmaskpb.FieldMask{Paths: []string{"spec.members"}}

func userName(n string) string { return parentName + "/users/" + n }

func groupName(n string) string { return parentName + "/groups/" + n }

func (e *env) createGroupWith(t *testing.T, id string, members ...string) {
	t.Helper()
	if err := e.newGroup(t.Context(), id, false, members...); err != nil {
		t.Fatal(err)
	}
}

func (e *env) newGroup(ctx context.Context, id string, validateOnly bool, members ...string) error {
	_, err := e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{
		Parent: parentName, GroupId: id, ValidateOnly: validateOnly,
		Group: &iamv1.Group{Spec: &iamv1.GroupSpec{Members: members}},
	})
	return err
}

func (e *env) setMembers(ctx context.Context, id string, etag string, validateOnly bool, members ...string) error {
	_, err := e.groups.UpdateGroup(ctx, &iamv1.UpdateGroupRequest{
		Group:      &iamv1.Group{Name: groupName(id), Etag: etag, Spec: &iamv1.GroupSpec{Members: members}},
		UpdateMask: membersMask, ValidateOnly: validateOnly,
	})
	return err
}

// groupsOf counts the stored groups that list user.
func groupsOf(t *testing.T, b store.Backend, user string) int {
	t.Helper()
	all, err := store.List[iam.Group](t.Context(), store.Scoped(b, proj))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, g := range all {
		for _, m := range g.Object.Members {
			if store.Fold(m) == store.Fold(user) {
				n++
			}
		}
	}
	return n
}

func wantGroupsPerUser(t *testing.T, err error) {
	t.Helper()
	wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded")
	if got, want := status.Convert(err).Message(), "Cannot exceed quota for GroupsPerUser: 10"; got != want {
		t.Fatalf("message %q, want %q", got, want)
	}
}

// TestGroupsPerUserQuota: a user is in at most 10 groups (AWS
// GroupsPerUser); the 11th is refused on every write path and nothing of
// the refused request is stored (#136).
func TestGroupsPerUserQuota(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	e.createUser(t, ctx, "alice")
	e.createUser(t, ctx, "bob")
	// A lock left by a crashed writer is taken over once its lease ends.
	stale := iam.MembershipLock{
		Name: iam.MembershipLockKey, Epoch: 7, Holder: strings.Repeat("a", 64), Expires: now.Add(-time.Second),
	}
	if _, err := store.Create(ctx, store.Scoped(b, proj), stale); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		e.createGroupWith(t, fmt.Sprintf("c%d", i), userName("alice"))
	}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("u%d", i)
		e.createGroupWith(t, id)
		if err := e.setMembers(ctx, id, "", false, userName("alice")); err != nil {
			t.Fatal(err)
		}
	}
	if n := groupsOf(t, b, "alice"); n != iam.MaxGroupsPerUser {
		t.Fatalf("alice in %d groups, want 10", n)
	}

	e.createGroupWith(t, "eleven", userName("bob"))
	before, err := e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName("eleven")})
	if err != nil {
		t.Fatal(err)
	}
	wantGroupsPerUser(t, e.setMembers(ctx, "eleven", "", false, userName("bob"), userName("alice")))
	wantGroupsPerUser(t, e.setMembers(ctx, "eleven", before.GetEtag(), false, userName("bob"), userName("alice")))
	wantGroupsPerUser(t, e.setMembers(ctx, "eleven", "", true, userName("bob"), userName("alice")))
	after, err := e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName("eleven")})
	if err != nil || after.GetEtag() != before.GetEtag() || len(after.GetSpec().GetMembers()) != 1 {
		t.Fatalf("refused update changed the group: %v %v", after, err)
	}

	wantGroupsPerUser(t, e.newGroup(ctx, "twelve", false, userName("alice")))
	wantGroupsPerUser(t, e.newGroup(ctx, "twelve", true, userName("alice")))
	_, err = e.groups.UpdateGroup(ctx, &iamv1.UpdateGroupRequest{
		Group:      &iamv1.Group{Name: groupName("twelve"), Spec: &iamv1.GroupSpec{Members: []string{userName("alice")}}},
		UpdateMask: membersMask, AllowMissing: true,
	})
	wantGroupsPerUser(t, err)
	_, err = e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName("twelve")})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")

	// Rewriting a group alice is already in adds nothing and passes.
	if err := e.setMembers(ctx, "c1", "", false, userName("alice"), userName("bob")); err != nil {
		t.Fatal(err)
	}
	// Leaving one group frees one slot.
	if err := e.setMembers(ctx, "c2", "", false); err != nil {
		t.Fatal(err)
	}
	if err := e.setMembers(ctx, "eleven", "", false, userName("bob"), userName("alice")); err != nil {
		t.Fatal(err)
	}
	if n := groupsOf(t, b, "alice"); n != iam.MaxGroupsPerUser {
		t.Fatalf("alice in %d groups, want 10", n)
	}
}

// TestConcurrentGroupsPerUserMemstore races adds of one user to 16
// groups across two replicas on one in-memory backend.
func TestConcurrentGroupsPerUserMemstore(t *testing.T) {
	testConcurrentGroupsPerUser(t, func(*testing.T) store.Backend { return memstore.New() })
}

// TestConcurrentGroupsPerUserOnAPIServer runs it on kubestore against a
// real kube-apiserver. It skips without KUBEBUILDER_ASSETS.
func TestConcurrentGroupsPerUserOnAPIServer(t *testing.T) {
	testConcurrentGroupsPerUser(t, apiServerBackends(t))
}

func testConcurrentGroupsPerUser(t *testing.T, backend func(*testing.T) store.Backend) {
	const updates, creates = 12, 6
	b := backend(t)
	a, rb, _, _ := replicas(t, b)
	ctx := t.Context()
	for i := range updates {
		a.createGroupWith(t, fmt.Sprintf("g%02d", i))
	}
	var wg sync.WaitGroup
	errs := make(chan error, updates+creates)
	for i := range updates + creates {
		e := a
		if i%2 == 1 {
			e = rb
		}
		wg.Go(func() {
			if i < updates {
				errs <- e.setMembers(ctx, fmt.Sprintf("g%02d", i), "", false, userName("alice"))
				return
			}
			errs <- e.newGroup(ctx, fmt.Sprintf("n%02d", i), false, userName("alice"))
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
			wantGroupsPerUser(t, err)
			refused++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != iam.MaxGroupsPerUser || refused != updates+creates-iam.MaxGroupsPerUser {
		t.Fatalf("%d accepted and %d refused, want 10 and %d", ok, refused, updates+creates-iam.MaxGroupsPerUser)
	}
	if n := groupsOf(t, b, "alice"); n != iam.MaxGroupsPerUser {
		t.Fatalf("alice in %d groups after concurrent adds, want 10", n)
	}
}
