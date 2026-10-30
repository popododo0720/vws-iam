package grpcapi_test

import (
	"context"
	"errors"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// fakeKube is kubestore on a fake API server.
func fakeKube() store.Backend {
	s := runtime.NewScheme()
	for _, k := range iam.Kinds {
		gvk := kubestore.GVK(k)
		s.AddKnownTypeWithName(gvk, &unstructured.Unstructured{})
		gvk.Kind += "List"
		s.AddKnownTypeWithName(gvk, &unstructured.UnstructuredList{})
	}
	return kubestore.New(fake.NewClientBuilder().WithScheme(s).Build(), "vws-iam")
}

var renameBackends = []struct {
	name string
	open func() store.Backend
}{
	{"memstore", func() store.Backend { return memstore.New() }},
	{"kubestore", fakeKube},
}

// membershipLease outlasts grpcapi.membershipLease (10s), the lease of
// a member-lock holder that died.
const membershipLease = 11 * time.Second

var errCrash = errors.New("injected crash")

// crashing is a backend whose process dies at the n-th write: that write
// fails (or, with lost, commits and its reply is lost) and every later
// write fails, until revive. Reads always work.
type crashing struct {
	store.Backend
	mu         sync.Mutex
	n, writes  int
	lost, dead bool
}

func (c *crashing) arm(n int, lost bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n, c.writes, c.lost, c.dead = n, 0, lost, false
}

// revive disarms c and reports whether it crashed.
func (c *crashing) revive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	crashed := c.dead
	c.n, c.dead = 0, false
	return crashed
}

// write runs w unless the process is dead.
func (c *crashing) write(w func() error) error {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return errCrash
	}
	crash := false
	if c.n > 0 {
		c.writes++
		crash = c.writes == c.n
	}
	if crash {
		c.dead = true
	}
	lost := c.lost
	c.mu.Unlock()
	if !crash {
		return w()
	}
	if lost {
		_ = w() //nolint:errcheck // the reply is lost
	}
	return errCrash
}

func (c *crashing) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (v string, err error) {
	err = c.write(func() (e error) { v, e = c.Backend.Create(ctx, k, key, spec); return e })
	return v, err
}

func (c *crashing) Update(
	ctx context.Context, k iam.Kind, key string, spec []byte, version string,
) (v string, err error) {
	err = c.write(func() (e error) { v, e = c.Backend.Update(ctx, k, key, spec, version); return e })
	return v, err
}

func (c *crashing) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	return c.write(func() error { return c.Backend.Delete(ctx, k, key, version) })
}

func (c *crashing) UpdateIf(
	ctx context.Context, k iam.Kind, key string, spec []byte, version string, pre store.Pre,
) (v string, err error) {
	err = c.write(func() (e error) { v, e = c.Backend.UpdateIf(ctx, k, key, spec, version, pre); return e })
	return v, err
}

func (c *crashing) DeleteIf(ctx context.Context, k iam.Kind, key, version string, pre store.Pre) error {
	return c.write(func() error { return c.Backend.DeleteIf(ctx, k, key, version, pre) })
}

// wantAWS checks the gRPC code and the AWS code of err.
func wantAWS(t *testing.T, err error, code codes.Code, aws string) {
	t.Helper()
	st := status.Convert(err)
	if st.Code() != code {
		t.Fatalf("code %v, want %v (%v)", st.Code(), code, err)
	}
	for _, d := range st.Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok && ei.GetMetadata()[grpcapi.AWSCodeKey] == aws {
			return
		}
	}
	t.Fatalf("%v: want AWS code %s", err, aws)
}

func renameUserReq(name, etag, requestID string) *iamv1.UpdateUserRequest {
	return &iamv1.UpdateUserRequest{User: &iamv1.User{Name: userName(name), Etag: etag}, RequestId: requestID}
}

func renameGroupReq(name, etag, requestID string) *iamv1.UpdateGroupRequest {
	return &iamv1.UpdateGroupRequest{Group: &iamv1.Group{Name: groupName(name), Etag: etag}, RequestId: requestID}
}

func (e *env) getUser(t *testing.T, n string) *iamv1.User {
	t.Helper()
	u, err := e.users.GetUser(t.Context(), &iamv1.GetUserRequest{Name: userName(n)})
	if err != nil {
		t.Fatalf("get user %s: %v", n, err)
	}
	return u
}

func (e *env) getGroup(t *testing.T, n string) *iamv1.Group {
	t.Helper()
	g, err := e.groups.GetGroup(t.Context(), &iamv1.GetGroupRequest{Name: groupName(n)})
	if err != nil {
		t.Fatalf("get group %s: %v", n, err)
	}
	return g
}

// noMarks fails if any stored user or group of the project still carries
// a rename marker.
func noMarks(t *testing.T, b store.Backend) {
	t.Helper()
	pb := store.Scoped(b, proj)
	us, err := store.List[iam.User](t.Context(), pb)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range us {
		if u.Object.RenameTo != "" || u.Object.RenamedFrom != "" {
			t.Errorf("user %s keeps rename marks %+v", u.Object.Name, u.Object.RenameState)
		}
	}
	gs, err := store.List[iam.Group](t.Context(), pb)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gs {
		if g.Object.RenameTo != "" || g.Object.RenamedFrom != "" {
			t.Errorf("group %s keeps rename marks %+v", g.Object.Name, g.Object.RenameState)
		}
	}
}

// renameFixture is alice with an access key, a FIDO key and membership
// of devs.
type renameFixture struct {
	uid, uniqueID, keyID, etag string
}

func seedRename(t *testing.T, e *env, b store.Backend) renameFixture {
	t.Helper()
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	e.createGroupWith(t, "devs", userName("alice"))
	k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: userName("alice")})
	if err != nil {
		t.Fatal(err)
	}
	fido := mfa.New(store.Scoped(b, proj), nil, proj, nil)
	cred := mfa.FidoCredential{ID: []byte("alice-credential-1"), PublicKey: []byte{0xa5}}
	if _, err := fido.RegisterFido(ctx, "alice", "yubikey", cred); err != nil {
		t.Fatal(err)
	}
	cur := e.getUser(t, "alice")
	return renameFixture{
		uid: u.GetUid(), uniqueID: u.GetStatus().GetUniqueId(),
		keyID: path.Base(k.GetAccessKey().GetName()), etag: cur.GetEtag(),
	}
}

// wantRenamed checks that alice is now bob with everything she owned.
func wantRenamed(t *testing.T, e *env, b store.Backend, f renameFixture) {
	t.Helper()
	ctx := t.Context()
	_, err := e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: userName("alice")})
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	u := e.getUser(t, "bob")
	if u.GetUid() != f.uid || u.GetStatus().GetUniqueId() != f.uniqueID {
		t.Errorf("bob uid %q id %q, want %q %q", u.GetUid(), u.GetStatus().GetUniqueId(), f.uid, f.uniqueID)
	}
	if got := u.GetStatus().GetGroups(); !slices.Equal(got, []string{groupName("devs")}) {
		t.Errorf("bob groups %v", got)
	}
	if got := e.getGroup(t, "devs").GetSpec().GetMembers(); !slices.Equal(got, []string{userName("bob")}) {
		t.Errorf("devs members %v", got)
	}
	pb := store.Scoped(b, proj)
	k, err := store.Get[iam.AccessKey](ctx, pb, f.keyID)
	if err != nil || k.Object.UserName != "bob" {
		t.Errorf("access key %+v %v", k.Object, err)
	}
	devs, err := store.List[iam.FidoDevice](ctx, pb)
	if err != nil || len(devs) != 1 || devs[0].Object.UserName != "bob" {
		t.Errorf("fido devices %+v %v", devs, err)
	}
	l, err := e.users.ListUsers(ctx, &iamv1.ListUsersRequest{Parent: parentName})
	if err != nil || len(l.GetUsers()) != 1 {
		t.Errorf("list users %v %v", l, err)
	}
	noMarks(t, b)
}

// TestRenameUser: a rename keeps the user's ids, keys, MFA devices, FIDO
// keys, groups and console sessions, all under the new name.
func TestRenameUser(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			b := bc.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			withCheapPassword(t, e, b, "alice")
			e.createGroupWith(t, "devs", userName("alice"))
			e.createGroupWith(t, "ops", userName("alice"))
			k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: userName("alice")})
			if err != nil {
				t.Fatal(err)
			}
			pair := strings.SplitN(enableMFA(t, e, ctx, "alice"), "|", 2)
			seed, serial := pair[0], pair[1]
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{
				Project: proj, UserName: "alice", Password: goodPW, TotpCode: code(t, e, seed),
			})
			if err != nil {
				t.Fatal(err)
			}
			before := e.getUser(t, "alice")

			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", before.GetEtag(), ""), "bob"); err != nil {
				t.Fatal(err)
			}
			u := e.getUser(t, "bob")
			if u.GetUid() != before.GetUid() || u.GetStatus().GetUniqueId() != before.GetStatus().GetUniqueId() ||
				u.GetStatus().GetArn() == before.GetStatus().GetArn() {
				t.Errorf("bob %v, alice was %v", u, before)
			}
			if got := u.GetStatus().GetGroups(); !slices.Equal(got, []string{groupName("devs"), groupName("ops")}) {
				t.Errorf("bob groups %v", got)
			}
			if got := u.GetStatus().GetMfaDevices(); len(got) != 1 {
				t.Errorf("bob mfa devices %v", got)
			}
			for _, g := range []string{"devs", "ops"} {
				if got := e.getGroup(t, g).GetSpec().GetMembers(); !slices.Equal(got, []string{userName("bob")}) {
					t.Errorf("%s members %v", g, got)
				}
			}
			keys, err := e.keys.ListAccessKeys(ctx, &iamv1.ListAccessKeysRequest{Parent: userName("bob")})
			kid := path.Base(k.GetAccessKey().GetName())
			if err != nil || len(keys.GetAccessKeys()) != 1 || path.Base(keys.GetAccessKeys()[0].GetName()) != kid {
				t.Errorf("bob keys %v %v", keys, err)
			}
			// The key still signs: its sealed secret is bound to the key id.
			a, err := e.auth.Authenticate(ctx, e.sign(kid, k.GetSecretAccessKey(), ""))
			if err != nil || !strings.HasSuffix(a.GetPrincipal().GetArn(), ":user/bob") {
				t.Errorf("authenticate %v %v", a, err)
			}
			v, err := e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()})
			if err != nil || !strings.HasSuffix(v.GetPrincipal().GetArn(), ":user/bob") {
				t.Errorf("session %v %v", v, err)
			}
			// The MFA device signs bob in; its seed is bound to the device.
			*e.now = e.now.Add(30 * time.Second)
			if _, err := e.auth.Login(ctx, &iamv1.LoginRequest{
				Project: proj, UserName: "bob", Password: goodPW, TotpCode: code(t, e, seed),
			}); err != nil {
				t.Errorf("bob login: %v", err)
			}
			d, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: parentName + "/mfaDevices/alice-phone"})
			if err != nil || d.GetStatus().GetUser() != userName("bob") || d.GetStatus().GetSerialNumber() != serial {
				t.Errorf("mfa device %v %v", d, err)
			}
			_, err = e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: userName("alice")})
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			noMarks(t, b)

			// A case-only rename keeps everything too.
			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("bob", "", ""), "Bob"); err != nil {
				t.Fatal(err)
			}
			if u := e.getUser(t, "bob"); u.GetName() != userName("Bob") || u.GetUid() != before.GetUid() {
				t.Errorf("after case rename %v", u)
			}
			if got := e.getGroup(t, "devs").GetSpec().GetMembers(); !slices.Equal(got, []string{userName("Bob")}) {
				t.Errorf("devs members after case rename %v", got)
			}
		})
	}
}

// TestRenameUserErrors: AWS errors for a taken name (case folded), a
// missing user, a stale etag and a bad name, and none of them changes or
// freezes the user.
func TestRenameUserErrors(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			b := bc.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			f := seedRename(t, e, b)
			e.createUser(t, ctx, "Carol")

			_, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), "CAROL")
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			_, err = e.api.UpdateUserRename(ctx, renameUserReq("nobody", "", ""), "dave")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			_, err = e.api.UpdateUserRename(ctx, renameUserReq("alice", `W/"stale"`, ""), "bob")
			wantErr(t, err, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
			for _, bad := range []string{strings.Repeat("a", 65), "bad name", "bad/name", "bád"} {
				_, err = e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), bad)
				wantAWS(t, err, codes.InvalidArgument, "ValidationError")
			}
			_, err = e.api.UpdateUserRename(ctx, &iamv1.UpdateUserRequest{
				User:       &iamv1.User{Name: userName("alice"), Spec: &iamv1.UserSpec{AttachedPolicies: []string{"x"}}},
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
			}, "bob")
			wantAWS(t, err, codes.InvalidArgument, "ValidationError")

			if got := e.getUser(t, "alice"); got.GetEtag() != f.etag {
				t.Errorf("alice changed: etag %s, was %s", got.GetEtag(), f.etag)
			}
			noMarks(t, b)
			// Not frozen: an ordinary update still works.
			e.updateUserPath(t, userName("alice"), "/team/")
			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), strings.Repeat("b", 64)); err != nil {
				t.Errorf("64-char name: %v", err)
			}
		})
	}
}

// TestRenameUserPath: UpdateUser with NewPath and NewUserName together.
func TestRenameUserPath(t *testing.T) {
	now := time.Now().UTC()
	e := newEnvOn(t, memstore.New(), &now)
	e.createUser(t, t.Context(), "alice")
	_, err := e.api.UpdateUserRename(t.Context(), &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: userName("alice"), Spec: &iamv1.UserSpec{Path: "/eng/"}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.path"}},
	}, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if u := e.getUser(t, "bob"); u.GetSpec().GetPath() != "/eng/" {
		t.Errorf("bob path %q", u.GetSpec().GetPath())
	}
}

// TestRenameUserRequestID: a repeated request_id is answered from the
// first call, also after the old name was taken again, and a different
// rename under the same id is refused.
func TestRenameUserRequestID(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			b := bc.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			f := seedRename(t, e, b)
			req := renameUserReq("alice", f.etag, "rename-alice-1")
			first, err := e.api.UpdateUserRename(ctx, req, "bob")
			if err != nil {
				t.Fatal(err)
			}
			again, err := e.api.UpdateUserRename(ctx, req, "bob")
			if err != nil || again.GetName() != first.GetName() {
				t.Fatalf("repeat %v %v, first %v", again, err, first)
			}
			wantRenamed(t, e, b, f)
			e.createUser(t, ctx, "alice")
			if _, err := e.api.UpdateUserRename(ctx, req, "bob"); err != nil {
				t.Errorf("repeat after alice was recreated: %v", err)
			}
			if u := e.getUser(t, "alice"); u.GetUid() == f.uid {
				t.Errorf("new alice took the old uid")
			}
		})
	}
}

// TestRenameUserFrozen: while a rename is in flight (here: its process
// died after marking the user) the user refuses every other write with
// ConcurrentModification, and reads show it once under its old name.
func TestRenameUserFrozen(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			c := &crashing{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, c, &now)
			ctx := t.Context()
			f := seedRename(t, e, c)
			e.createGroupWith(t, "ops")
			c.arm(2, true) // mark commits, then the process dies
			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", f.etag, ""), "bob"); err == nil {
				t.Fatal("rename survived the crash")
			}
			if !c.revive() {
				t.Fatal("no crash")
			}
			*e.now = e.now.Add(membershipLease) // the dead process's lock expires
			u, err := store.Get[iam.User](ctx, store.Scoped(c, proj), "alice")
			if err != nil || u.Object.RenameTo != "bob" {
				t.Fatalf("alice not marked: %+v %v", u.Object.RenameState, err)
			}
			const aws = "ConcurrentModification"
			_, err = e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
				User:       &iamv1.User{Name: userName("alice"), Spec: &iamv1.UserSpec{Path: "/x/"}},
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.path"}},
			})
			wantAWS(t, err, codes.Aborted, aws)
			_, err = e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: userName("alice")})
			wantAWS(t, err, codes.Aborted, aws)
			_, err = e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: userName("alice")})
			wantAWS(t, err, codes.Aborted, aws)
			err = e.setMembers(ctx, "ops", "", false, userName("alice"))
			wantAWS(t, err, codes.Aborted, aws)
			_, err = e.mfa.CreateVirtualMfaDevice(ctx, &iamv1.CreateVirtualMfaDeviceRequest{
				Parent: parentName, MfaDeviceId: "phone", MfaDevice: &iamv1.MfaDevice{},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = e.mfa.EnableMfaDevice(ctx, &iamv1.EnableMfaDeviceRequest{
				Name: parentName + "/mfaDevices/phone", User: userName("alice"),
				AuthenticationCode_1: "000000", AuthenticationCode_2: "000001",
			})
			if status.Code(err) != codes.Aborted {
				t.Errorf("enable mfa on a renaming user: %v", err)
			}
			e.getUser(t, "alice")
			_, err = e.users.GetUser(ctx, &iamv1.GetUserRequest{Name: userName("bob")})
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			l, err := e.users.ListUsers(ctx, &iamv1.ListUsersRequest{Parent: parentName})
			if err != nil || len(l.GetUsers()) != 1 || l.GetUsers()[0].GetName() != userName("alice") {
				t.Errorf("list users %v %v", l, err)
			}

			// The sweep leaves a fresh rename alone and finishes it
			// after renameGrace.
			if n, err := e.api.ResumeRenames(ctx); err != nil || n != 0 {
				t.Errorf("early sweep %d %v", n, err)
			}
			*e.now = e.now.Add(2 * time.Minute)
			if n, err := e.api.ResumeRenames(ctx); err != nil || n != 1 {
				t.Errorf("sweep %d %v", n, err)
			}
			wantRenamed(t, e, c, f)
		})
	}
}

// TestRenameTakenInFlight: the new name is created after the rename
// marked the old user and before it copied it; the rename backs out with
// EntityAlreadyExists and the old user is writable again.
func TestRenameTakenInFlight(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			c := &crashing{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, c, &now)
			ctx := t.Context()
			f := seedRename(t, e, c)
			c.arm(2, true)
			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", f.etag, "r1"), "bob"); err == nil {
				t.Fatal("rename survived the crash")
			}
			c.revive()
			*e.now = e.now.Add(membershipLease)
			other := e.createUser(t, ctx, "BOB")
			_, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", f.etag, "r1"), "bob")
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			noMarks(t, c)
			if u := e.getUser(t, "bob"); u.GetUid() != other.GetUid() {
				t.Errorf("bob is %v, want the new user", u)
			}
			if got := e.getGroup(t, "devs").GetSpec().GetMembers(); !slices.Equal(got, []string{userName("alice")}) {
				t.Errorf("devs members %v", got)
			}
			e.updateUserPath(t, userName("alice"), "/team/")
		})
	}
}

// TestRenameUserCrash crashes the process at every write of a rename, with
// the write lost or committed, and checks that a retry with the same
// request (or else the sweep) converges to the renamed user.
func TestRenameUserCrash(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			for n := 1; ; n++ {
				crashed := false
				for _, lost := range []bool{false, true} {
					c := &crashing{Backend: bc.open()}
					now := time.Now().UTC()
					e := newEnvOn(t, c, &now)
					ctx := t.Context()
					f := seedRename(t, e, c)
					req := renameUserReq("alice", f.etag, "rename-1")
					c.arm(n, lost)
					_, err := e.api.UpdateUserRename(ctx, req, "bob")
					if !c.revive() {
						if err != nil {
							t.Fatalf("write %d: %v", n, err)
						}
						wantRenamed(t, e, c, f)
						continue
					}
					crashed = true
					*e.now = e.now.Add(2 * time.Minute) // leases of the dead process expire
					if n%2 == 0 {
						if _, err := e.api.ResumeRenames(ctx); err != nil {
							t.Fatalf("write %d lost=%v: sweep: %v", n, lost, err)
						}
					}
					if _, err := e.api.UpdateUserRename(ctx, req, "bob"); err != nil {
						t.Fatalf("write %d lost=%v: retry: %v", n, lost, err)
					}
					wantRenamed(t, e, c, f)
					if t.Failed() {
						t.Fatalf("write %d lost=%v did not converge", n, lost)
					}
				}
				if !crashed {
					if n < 6 {
						t.Fatalf("rename finished in %d writes; the crash points are not exercised", n-1)
					}
					t.Logf("crashed at each of the %d writes of a rename", n-1)
					return
				}
			}
		})
	}
}

// TestRenameUserRacesMembership adds alice to groups while she is renamed:
// no group may end up naming alice.
func TestRenameUserRacesMembership(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			b := bc.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			const n = 4
			for i := range n {
				e.createGroupWith(t, "g"+string(rune('a'+i)))
			}
			var wg sync.WaitGroup
			for i := range n {
				wg.Go(func() {
					err := e.setMembers(ctx, "g"+string(rune('a'+i)), "", false, userName("alice"))
					if c := status.Code(err); c != codes.OK && c != codes.Aborted && c != codes.NotFound {
						t.Errorf("add: %v", err)
					}
				})
			}
			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), "bob"); err != nil {
				t.Errorf("rename: %v", err)
			}
			wg.Wait()
			want := 0
			for i := range n {
				for _, m := range e.getGroup(t, "g"+string(rune('a'+i))).GetSpec().GetMembers() {
					if m != userName("bob") {
						t.Errorf("group g%c lists %s", 'a'+i, m)
					}
					want++
				}
			}
			if got := e.getUser(t, "bob").GetStatus().GetGroups(); len(got) != want {
				t.Errorf("bob groups %v, want %d", got, want)
			}
			noMarks(t, b)
		})
	}
}

// TestRenameGroup: a group rename keeps its id, members and policies;
// members list the new name; errors match AWS; a crash converges.
func TestRenameGroup(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			c := &crashing{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, c, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			e.createGroupWith(t, "devs", userName("alice"))
			e.createGroupWith(t, "Ops")
			g := e.getGroup(t, "devs")

			_, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "OPS")
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			_, err = e.api.UpdateGroupRename(ctx, renameGroupReq("nope", "", ""), "x")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			_, err = e.api.UpdateGroupRename(ctx, renameGroupReq("devs", `W/"stale"`, ""), "x")
			wantErr(t, err, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
			_, err = e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), strings.Repeat("g", 129))
			wantAWS(t, err, codes.InvalidArgument, "ValidationError")

			c.arm(3, true)
			_, err = e.api.UpdateGroupRename(ctx, renameGroupReq("devs", g.GetEtag(), "rg-1"), "builders")
			if !c.revive() || err == nil {
				t.Fatalf("no crash: %v", err)
			}
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", g.GetEtag(), "rg-1"), "builders"); err != nil {
				t.Fatalf("retry: %v", err)
			}
			got := e.getGroup(t, "builders")
			if got.GetUid() != g.GetUid() || got.GetStatus().GetUniqueId() != g.GetStatus().GetUniqueId() ||
				!slices.Equal(got.GetSpec().GetMembers(), []string{userName("alice")}) {
				t.Errorf("builders %v, devs was %v", got, g)
			}
			_, err = e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName("devs")})
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if got := e.getUser(t, "alice").GetStatus().GetGroups(); !slices.Equal(got, []string{groupName("builders")}) {
				t.Errorf("alice groups %v", got)
			}
			long := strings.Repeat("g", 128)
			if _, err := e.api.UpdateGroupRename(ctx, renameGroupReq("builders", "", ""), long); err != nil {
				t.Errorf("128-char group name: %v", err)
			}
			noMarks(t, c)
		})
	}
}
