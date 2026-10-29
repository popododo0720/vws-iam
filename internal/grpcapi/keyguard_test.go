package grpcapi_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// The mismatch codes of the access key preconditions (vws-proto v0.7.0):
// a precondition that does not hold when it is read is FAILED_PRECONDITION;
// one that stops holding before the write commits is ABORTED. Both carry
// the AWS code ConcurrentModification.
const (
	mismatchCode = codes.FailedPrecondition
	movedCode    = codes.Aborted
)

func TestAccessKeyExpectedUserPath(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	other := e.createUser(t, ctx, "bob")
	created, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	name := created.GetAccessKey().GetName()
	update := func(state iamv1.AccessKeyState, expected string, validateOnly bool) (*longrunningpb.Operation, error) {
		return e.keys.UpdateAccessKey(ctx, &iamv1.UpdateAccessKeyRequest{
			AccessKey:        &iamv1.AccessKey{Name: name, Spec: &iamv1.AccessKeySpec{State: state}},
			ExpectedUserPath: expected,
			ValidateOnly:     validateOnly,
		})
	}
	unchanged := func() {
		t.Helper()
		got, err := e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: name})
		if err != nil {
			t.Fatal(err)
		}
		if got.GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE || got.GetGeneration() != 1 {
			t.Fatalf("key changed after a refused write: %v", got)
		}
	}

	// A caller authorized on another user or project must not change the key.
	for _, expected := range []string{other.GetName(), "projects/other/users/alice"} {
		_, err := update(iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE, expected, false)
		wantErr(t, err, mismatchCode, "GENERATION_CONFLICT", "ConcurrentModification")
		unchanged()
	}
	_, err = update(iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE, other.GetName(), true)
	wantErr(t, err, mismatchCode, "GENERATION_CONFLICT", "ConcurrentModification")
	unchanged()
	_, err = update(iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE, "alice", false)
	wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
	unchanged()

	// The key's own parent user name succeeds even in another case,
	// because IAM names fold. Omitting the field keeps the old behavior.
	op, err := update(iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE, parentName+"/users/ALICE", false)
	if err != nil {
		t.Fatal(err)
	}
	k := unpack(t, op, &iamv1.AccessKey{})
	if k.GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE || k.GetGeneration() != 2 {
		t.Fatalf("matched update: %v", k)
	}
	if _, err := update(iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE, "", false); err != nil {
		t.Fatalf("update without expected_user_path: %v", err)
	}

	// Delete applies the same precondition and deletes nothing on a mismatch.
	_, err = e.keys.DeleteAccessKey(ctx, &iamv1.DeleteAccessKeyRequest{Name: name, ExpectedUserPath: other.GetName()})
	wantErr(t, err, mismatchCode, "GENERATION_CONFLICT", "ConcurrentModification")
	if _, err := e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: name}); err != nil {
		t.Fatalf("mismatch deleted the key: %v", err)
	}
	del := &iamv1.DeleteAccessKeyRequest{Name: name, ExpectedUserPath: u.GetName()}
	if _, err := e.keys.DeleteAccessKey(ctx, del); err != nil {
		t.Fatal(err)
	}
	_, err = e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: name})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
}

// arnFixture is a user carol at /allowed/ with one access key, the
// authorized ARN, and helpers on the key.
type arnFixture struct {
	e          *env
	user       *iamv1.User
	key        string
	authorized string
}

func newARNFixture(t *testing.T, e *env) arnFixture {
	t.Helper()
	ctx := t.Context()
	op, err := e.users.CreateUser(ctx, &iamv1.CreateUserRequest{
		Parent: parentName, UserId: "carol", User: &iamv1.User{Spec: &iamv1.UserSpec{Path: "/allowed/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	u := unpack(t, op, &iamv1.User{})
	if want := "arn:vws:iam::" + proj + ":user/allowed/carol"; u.GetStatus().GetArn() != want {
		t.Fatalf("user ARN %q, want %q", u.GetStatus().GetArn(), want)
	}
	created, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	return arnFixture{e: e, user: u, key: created.GetAccessKey().GetName(), authorized: u.GetStatus().GetArn()}
}

// move is UpdateUser changing carol's path, which changes her ARN.
func (f arnFixture) move(ctx context.Context, path string) (string, error) {
	op, err := f.e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: f.user.GetName(), Spec: &iamv1.UserSpec{Path: path}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.path"}},
	})
	if err != nil {
		return "", err
	}
	u := &iamv1.User{}
	if err := op.GetResponse().UnmarshalTo(u); err != nil {
		return "", err
	}
	return u.GetStatus().GetArn(), nil
}

func (f arnFixture) deactivate(
	ctx context.Context, arn, path string, validateOnly bool,
) (*longrunningpb.Operation, error) {
	spec := &iamv1.AccessKeySpec{State: iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE}
	return f.e.keys.UpdateAccessKey(ctx, &iamv1.UpdateAccessKeyRequest{
		AccessKey:        &iamv1.AccessKey{Name: f.key, Spec: spec},
		UpdateMask:       &fieldmaskpb.FieldMask{Paths: []string{"spec.state"}},
		ExpectedUserArn:  arn,
		ExpectedUserPath: path,
		ValidateOnly:     validateOnly,
	})
}

func (f arnFixture) remove(ctx context.Context, arn string) (*longrunningpb.Operation, error) {
	return f.e.keys.DeleteAccessKey(ctx, &iamv1.DeleteAccessKeyRequest{Name: f.key, ExpectedUserArn: arn})
}

// unchanged fails unless the key is still active at generation 1.
func (f arnFixture) unchanged(t *testing.T) {
	t.Helper()
	got, err := f.e.keys.GetAccessKey(t.Context(), &iamv1.GetAccessKeyRequest{Name: f.key})
	if err != nil {
		t.Fatalf("key gone after a refused write: %v", err)
	}
	if got.GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE || got.GetGeneration() != 1 {
		t.Fatalf("key changed after a refused write: %v", got)
	}
}

// TestAccessKeyExpectedUserARN is the sequential case of the console
// TOCTOU (vws-console-api#385): the caller authorized against the user's
// ARN at /allowed/, then UpdateUser moved the user to /denied/. The AIP-122
// name in expected_user_path did not change, but the ARN did, so the write
// is refused and the key stays as it was.
func TestAccessKeyExpectedUserARN(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	f := newARNFixture(t, e)
	current, err := f.move(ctx, "/denied/")
	if err != nil {
		t.Fatal(err)
	}
	if want := "arn:vws:iam::" + proj + ":user/denied/carol"; current != want {
		t.Fatalf("moved user ARN %q, want %q", current, want)
	}

	// The stale ARN is refused even when expected_user_path still matches,
	// the bypass the name-only check left open.
	_, err = f.deactivate(ctx, f.authorized, f.user.GetName(), false)
	wantErr(t, err, mismatchCode, "GENERATION_CONFLICT", "ConcurrentModification")
	f.unchanged(t)
	_, err = f.deactivate(ctx, f.authorized, "", true)
	wantErr(t, err, mismatchCode, "GENERATION_CONFLICT", "ConcurrentModification")
	f.unchanged(t)
	_, err = f.remove(ctx, f.authorized)
	wantErr(t, err, mismatchCode, "GENERATION_CONFLICT", "ConcurrentModification")
	f.unchanged(t)

	// Another user or project at the current path does not match either.
	for _, expected := range []string{
		"arn:vws:iam::" + proj + ":user/denied/bob",
		"arn:vws:iam::other:user/denied/carol",
	} {
		_, err = f.deactivate(ctx, expected, "", false)
		wantErr(t, err, mismatchCode, "GENERATION_CONFLICT", "ConcurrentModification")
		_, err = f.remove(ctx, expected)
		wantErr(t, err, mismatchCode, "GENERATION_CONFLICT", "ConcurrentModification")
		f.unchanged(t)
	}

	// A malformed ARN is rejected before any read, also on a missing key.
	missingKey := f.user.GetName() + "/accessKeys/AKIAMISSINGMISSING22"
	for _, bad := range []string{
		"carol", f.user.GetName(),
		"arn:vws:iam::" + proj + ":role/denied/carol",
		"arn:vws:iam::" + proj + ":user/denied/",
	} {
		_, err = f.deactivate(ctx, bad, "", false)
		wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
		_, err = f.remove(ctx, bad)
		wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
		missing := &iamv1.DeleteAccessKeyRequest{Name: missingKey, ExpectedUserArn: bad, AllowMissing: true}
		_, err = e.keys.DeleteAccessKey(ctx, missing)
		wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
		f.unchanged(t)
	}
	missing := &iamv1.DeleteAccessKeyRequest{Name: missingKey, ExpectedUserArn: current, AllowMissing: true}
	if _, err := e.keys.DeleteAccessKey(ctx, missing); err != nil {
		t.Fatalf("allow_missing delete with a well-formed ARN: %v", err)
	}

	// The current ARN, with a case-folded user name, succeeds.
	op, err := f.deactivate(ctx, "arn:vws:iam::"+proj+":user/denied/CAROL", f.user.GetName(), false)
	if err != nil {
		t.Fatalf("update with the current ARN: %v", err)
	}
	k := unpack(t, op, &iamv1.AccessKey{})
	if k.GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE || k.GetGeneration() != 2 {
		t.Fatalf("matched update: %v", k)
	}
	if _, err := f.remove(ctx, current); err != nil {
		t.Fatalf("delete with the current ARN: %v", err)
	}
	_, err = e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: f.key})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
}

// trap runs a function once, at the moment a conditional access key write
// is about to commit: after the server read the user and matched its ARN.
type trap struct {
	mu sync.Mutex
	fn func()
}

func (p *trap) arm(fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fn = fn
}

func (p *trap) spring() {
	p.mu.Lock()
	fn := p.fn
	p.fn = nil
	p.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// trapped springs p as UpdateIf or DeleteIf is entered, on a backend
// where that call is one atomic step (memstore).
type trapped struct {
	store.Backend
	p *trap
}

func (b trapped) UpdateIf(
	ctx context.Context, kind iam.Kind, key string, spec []byte, version string, pre store.Pre,
) (string, error) {
	b.p.spring()
	return b.Backend.UpdateIf(ctx, kind, key, spec, version, pre)
}

func (b trapped) DeleteIf(ctx context.Context, kind iam.Kind, key, version string, pre store.Pre) error {
	b.p.spring()
	return b.Backend.DeleteIf(ctx, kind, key, version, pre)
}

// trappedKube is kubestore on a fake API server that springs p inside
// the conditional write: after kubestore fenced the user and just before
// the key write reaches the API server.
func trappedKube(p *trap) store.Backend {
	s := runtime.NewScheme()
	for _, k := range iam.Kinds {
		gvk := kubestore.GVK(k)
		s.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		gvk.Kind += "List"
		s.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
	}
	isKey := func(obj client.Object) bool {
		return obj.GetObjectKind().GroupVersionKind().Kind == string(iam.KindAccessKey)
	}
	// voids reports whether obj is the bump that voids a fence: it sets a
	// new voided-fence annotation and changes nothing else that matters.
	voids := func(ctx context.Context, c client.WithWatch, obj client.Object) bool {
		const ann = kubestore.Group + "/voided-fence"
		cur := &unstructured.Unstructured{}
		cur.SetGroupVersionKind(obj.GetObjectKind().GroupVersionKind())
		if err := c.Get(ctx, client.ObjectKeyFromObject(obj), cur); err != nil {
			return false
		}
		return obj.GetAnnotations()[ann] != cur.GetAnnotations()[ann]
	}
	c := fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if isKey(obj) && !voids(ctx, c, obj) {
				p.spring()
			}
			return c.Update(ctx, obj, opts...)
		},
		Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
			if isKey(obj) {
				p.spring()
			}
			return c.Delete(ctx, obj, opts...)
		},
	}).Build()
	return kubestore.New(c, "vws-iam")
}

// TestAccessKeyARNMoveBeforeCommit is the concurrent case: UpdateUser
// moves the user after the server matched expected_user_arn and before the
// key write commits. The store's conditional write must refuse the key
// write (ABORTED, ConcurrentModification) and change nothing, on both
// backends.
func TestAccessKeyARNMoveBeforeCommit(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(p *trap) store.Backend
	}{
		{"memstore", func(p *trap) store.Backend { return trapped{Backend: memstore.New(), p: p} }},
		{"kubestore", trappedKube},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &trap{}
			now := time.Now().UTC()
			e := newEnvOn(t, tc.open(p), &now)
			ctx := t.Context()
			f := newARNFixture(t, e)
			var moved string
			moveTo := func(path string) func() {
				return func() {
					arn, err := f.move(ctx, path)
					if err != nil {
						t.Errorf("UpdateUser inside the write: %v", err)
					}
					moved = arn
				}
			}

			p.arm(moveTo("/denied/"))
			_, err := f.deactivate(ctx, f.authorized, f.user.GetName(), false)
			wantErr(t, err, movedCode, "GENERATION_CONFLICT", "ConcurrentModification")
			if moved != "arn:vws:iam::"+proj+":user/denied/carol" {
				t.Fatalf("the move did not run inside the write: ARN %q", moved)
			}
			f.unchanged(t)

			p.arm(moveTo("/allowed/"))
			_, err = f.remove(ctx, moved)
			wantErr(t, err, movedCode, "GENERATION_CONFLICT", "ConcurrentModification")
			if moved != f.authorized {
				t.Fatalf("the move did not run inside the delete: ARN %q", moved)
			}
			f.unchanged(t)

			// With nothing moving, the current ARN updates and deletes.
			op, err := f.deactivate(ctx, f.authorized, "", false)
			if err != nil {
				t.Fatalf("update with the current ARN: %v", err)
			}
			if k := unpack(t, op, &iamv1.AccessKey{}); k.GetSpec().GetState() != iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE {
				t.Fatalf("matched update: %v", k)
			}
			if _, err := f.remove(ctx, f.authorized); err != nil {
				t.Fatalf("delete with the current ARN: %v", err)
			}
			_, err = e.keys.GetAccessKey(ctx, &iamv1.GetAccessKeyRequest{Name: f.key})
			wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")
		})
	}
}
