package grpcapi_test

import (
	"context"
	"encoding/base32"
	"path"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/totp"
)

// hooked is a backend that runs a hook once, just before the first write
// that matches it. A hook that returns an error fails that write without
// running it.
type hooked struct {
	store.Backend
	mu   sync.Mutex
	op   string
	kind iam.Kind
	key  string // suffix of the stored key; "" matches any key
	run  func() error
}

// at arms the hook for the next op ("create", "update", "delete" or
// "list") of kind on key.
func (h *hooked) at(op string, kind iam.Kind, key string, run func() error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.op, h.kind, h.key, h.run = op, kind, key, run
}

func (h *hooked) fire(op string, kind iam.Kind, key string) error {
	h.mu.Lock()
	run := h.run
	match := run != nil && h.op == op && h.kind == kind &&
		(h.key == "" || store.Fold(key) == store.Fold(h.key) || strings.HasSuffix(store.Fold(key), "/"+store.Fold(h.key)))
	if match {
		h.run = nil
	}
	h.mu.Unlock()
	if !match {
		return nil
	}
	return run()
}

func (h *hooked) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	if err := h.fire("create", k, key); err != nil {
		return "", err
	}
	return h.Backend.Create(ctx, k, key, spec)
}

func (h *hooked) Update(ctx context.Context, k iam.Kind, key string, spec []byte, version string) (string, error) {
	if err := h.fire("update", k, key); err != nil {
		return "", err
	}
	return h.Backend.Update(ctx, k, key, spec, version)
}

func (h *hooked) UpdateIf(
	ctx context.Context, k iam.Kind, key string, spec []byte, version string, pre store.Pre,
) (string, error) {
	if err := h.fire("update", k, key); err != nil {
		return "", err
	}
	return h.Backend.UpdateIf(ctx, k, key, spec, version, pre)
}

func (h *hooked) List(ctx context.Context, k iam.Kind) ([]store.Entry, error) {
	if err := h.fire("list", k, ""); err != nil {
		return nil, err
	}
	return h.Backend.List(ctx, k)
}

func (h *hooked) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if err := h.fire("delete", k, key); err != nil {
		return err
	}
	return h.Backend.Delete(ctx, k, key, version)
}

func (h *hooked) DeleteIf(ctx context.Context, k iam.Kind, key, version string, pre store.Pre) error {
	if err := h.fire("delete", k, key); err != nil {
		return err
	}
	return h.Backend.DeleteIf(ctx, k, key, version, pre)
}

const testPassword = "correct horse battery"

func (e *env) setPassword(t *testing.T, ctx context.Context, user, pw string) {
	t.Helper()
	req := &iamv1.SetLoginProfileRequest{Name: userName(user), Password: pw}
	if _, err := e.users.SetLoginProfile(ctx, req); err != nil {
		t.Fatal(err)
	}
}

// markRename stores the state of a rename of user from to "to" that
// stopped after the copy: from carries RenameTo, to carries RenamedFrom.
func markRename(t *testing.T, b store.Backend, from, to string, at time.Time) {
	t.Helper()
	ctx := t.Context()
	pb := store.Scoped(b, proj)
	u, err := store.Get[iam.User](ctx, pb, from)
	if err != nil {
		t.Fatal(err)
	}
	u.Object.RenameTo, u.Object.RenameStarted = to, at
	if _, err := store.UpdateMarked(ctx, pb, u.Object, u.Version); err != nil {
		t.Fatal(err)
	}
	cp := u.Object
	cp.Name, cp.RenameTo, cp.RenamedFrom = to, "", from
	if _, err := store.CreateMarked(ctx, pb, cp); err != nil {
		t.Fatal(err)
	}
}

// TestLoginRefusedWhileRenaming: while a user rename is in flight, the
// old name and the new copy refuse console sign-in, before and after the
// MFA devices moved, so neither side signs in with the password alone.
func TestLoginRefusedWhileRenaming(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			b := bc.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			e.setPassword(t, ctx, "alice", testPassword)
			seed := strings.SplitN(enableMFA(t, e, ctx, "alice"), "|", 2)[0]
			markRename(t, b, "alice", "bob", now)

			login := func(user, totpCode string) error {
				t.Helper()
				l, err := e.auth.Login(ctx, &iamv1.LoginRequest{
					Project: proj, UserName: user, Password: testPassword, TotpCode: totpCode,
				})
				if err == nil {
					t.Errorf("login %s during the rename issued a session (mfa=%v)", user, l.GetPrincipal().GetMfaAuthenticated())
				}
				return err
			}
			// Devices still name alice: the copy bob has none.
			wantAWS(t, login("bob", ""), codes.Aborted, "ConcurrentModification")
			wantAWS(t, login("alice", ""), codes.Aborted, "ConcurrentModification")
			// Devices moved to bob: alice has none.
			pb := store.Scoped(b, proj)
			d, err := store.Get[iam.MfaDevice](ctx, pb, "alice-phone")
			if err != nil {
				t.Fatal(err)
			}
			d.Object.UserName = "bob"
			if _, err := store.Update(ctx, pb, d.Object, d.Version); err != nil {
				t.Fatal(err)
			}
			wantAWS(t, login("alice", ""), codes.Aborted, "ConcurrentModification")
			wantAWS(t, login("bob", ""), codes.Aborted, "ConcurrentModification")

			// Once the rename finished, bob signs in with the MFA code only.
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.ResumeRenames(ctx); err != nil {
				t.Fatal(err)
			}
			_, err = e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "bob", Password: testPassword})
			wantAWS(t, err, codes.Unauthenticated, "MultiFactorAuthenticationRequired")
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{
				Project: proj, UserName: "bob", Password: testPassword, TotpCode: code(t, e, seed),
			})
			if err != nil || !l.GetPrincipal().GetMfaAuthenticated() {
				t.Fatalf("login bob after the rename: %v %v", l, err)
			}
		})
	}
}

// TestEnableMFARacingRename: EnableMfaDevice reads alice, then alice is
// renamed to bob and a new alice is created before the device write. The
// device must not end up enabled for either user.
func TestEnableMFARacingRename(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			h := &hooked{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			d, err := e.mfa.CreateVirtualMfaDevice(ctx, &iamv1.CreateVirtualMfaDeviceRequest{
				Parent: parentName, MfaDeviceId: "phone", MfaDevice: &iamv1.MfaDevice{},
			})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(d.GetBase32StringSeed())
			if err != nil {
				t.Fatal(err)
			}
			var other *iamv1.User
			h.at("update", iam.KindMfaDevice, "phone", func() error {
				if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), "bob"); err != nil {
					t.Errorf("rename: %v", err)
				}
				other = e.createUser(t, ctx, "alice")
				return nil
			})
			step := totp.Step(*e.now)
			_, err = e.mfa.EnableMfaDevice(ctx, &iamv1.EnableMfaDeviceRequest{
				Name: d.GetMfaDevice().GetName(), User: userName("alice"),
				AuthenticationCode_1: totp.Code(seed, step-1, totp.Digits),
				AuthenticationCode_2: totp.Code(seed, step, totp.Digits),
			})
			if err == nil {
				t.Error("enable committed after its user was renamed away")
			}
			if other == nil {
				t.Fatal("the hook did not run")
			}
			got, err := store.Get[iam.MfaDevice](ctx, store.Scoped(h, proj), "phone")
			if err != nil {
				t.Fatal(err)
			}
			if got.Object.Enabled || got.Object.UserName != "" {
				t.Errorf("device %q enabled=%v: the new alice or bob inherited it", got.Object.UserName, got.Object.Enabled)
			}
			for _, n := range []string{"alice", "bob"} {
				if m := e.getUser(t, n).GetStatus().GetMfaDevices(); len(m) != 0 {
					t.Errorf("%s has MFA devices %v", n, m)
				}
			}
		})
	}
}

// TestLoginSessionRacingRename: Login reads alice, then alice is renamed
// to bob and a new alice is created before the session is stored. The
// session must not authenticate as the new alice.
func TestLoginSessionRacingRename(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			h := &hooked{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			e.setPassword(t, ctx, "alice", testPassword)
			var other *iamv1.User
			h.at("create", iam.KindSession, "", func() error {
				if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), "bob"); err != nil {
					t.Errorf("rename: %v", err)
				}
				other = e.createUser(t, ctx, "alice")
				e.setPassword(t, ctx, "alice", "another long password")
				return nil
			})
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: testPassword})
			if other == nil {
				t.Fatal("the hook did not run")
			}
			if err != nil {
				return // refusing the login is fine too
			}
			v, err := e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()})
			if err == nil {
				t.Fatalf("a session of the renamed alice authenticates as %s (new alice %s)",
					v.GetPrincipal().GetUniqueId(), other.GetStatus().GetUniqueId())
			}
			wantAWS(t, err, codes.Unauthenticated, "InvalidClientTokenId")
		})
	}
}

// TestRenameSweepLeavesRecreatedName: a user rename crashed after it
// deleted alice and before it cleared bob's marker. While the sweep
// finishes it, a new alice is created with a key and a group; they must
// stay the new alice's.
func TestRenameSweepLeavesRecreatedName(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			h := &hooked{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			e.createGroupWith(t, "ops")
			if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), "bob"); err != nil {
				t.Fatal(err)
			}
			pb := store.Scoped(h, proj)
			bob, err := store.Get[iam.User](ctx, pb, "bob")
			if err != nil {
				t.Fatal(err)
			}
			bob.Object.RenamedFrom, bob.Object.RenameStarted, bob.Object.RenameConfirmed = "alice", now, true
			if _, err := store.UpdateMarked(ctx, pb, bob.Object, bob.Version); err != nil {
				t.Fatal(err)
			}

			var keyID string
			h.at("list", iam.KindGroup, "", func() error {
				e.createUser(t, ctx, "alice")
				k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: userName("alice")})
				if err != nil {
					t.Fatal(err)
				}
				keyID = path.Base(k.GetAccessKey().GetName())
				if err := e.setMembers(ctx, "ops", "", false, userName("alice")); err != nil {
					t.Fatal(err)
				}
				return nil
			})
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.ResumeRenames(ctx); err != nil {
				t.Fatal(err)
			}
			if keyID == "" {
				t.Fatal("the hook did not run")
			}
			got, err := store.Get[iam.AccessKey](ctx, pb, keyID)
			if err != nil || got.Object.UserName != "alice" {
				t.Errorf("the new alice's key belongs to %q (%v)", got.Object.UserName, err)
			}
			if m := e.getGroup(t, "ops").GetSpec().GetMembers(); !slices.Equal(m, []string{userName("alice")}) {
				t.Errorf("ops members %v", m)
			}
			noMarks(t, h)
		})
	}
}

// TestGroupRenameStaleCoordinator: coordinator A reads devs, then a user
// rename moves its member alice to carol and coordinator B copies devs to
// builders, deletes devs and dies before clearing the marker. A must not
// overwrite builders with its stale copy.
func TestGroupRenameStaleCoordinator(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			c := &crashing{Backend: bc.open()}
			h := &hooked{Backend: c}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			e.createGroupWith(t, "devs", userName("alice"))
			h.at("create", iam.KindGroup, "builders", func() error {
				if _, err := e.api.UpdateUserRename(ctx, renameUserReq("alice", "", ""), "carol"); err != nil {
					t.Errorf("user rename: %v", err)
				}
				// B: copy, delete devs, then die at the marker clear.
				h.at("update", iam.KindGroup, "builders", func() error { return errCrash })
				if _, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders"); err == nil {
					t.Error("coordinator B survived its crash")
				}
				return nil
			})
			_, _ = e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders") //nolint:errcheck // A may lose
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.ResumeRenames(ctx); err != nil {
				t.Fatal(err)
			}
			if m := e.getGroup(t, "builders").GetSpec().GetMembers(); !slices.Equal(m, []string{userName("carol")}) {
				t.Errorf("builders members %v, want carol", m)
			}
			if g := e.getUser(t, "carol").GetStatus().GetGroups(); !slices.Equal(g, []string{groupName("builders")}) {
				t.Errorf("carol groups %v", g)
			}
			noMarks(t, h)
		})
	}
}

// TestGroupRenameStaleCoordinatorAfterDelete: coordinator A marks devs,
// then coordinator B finishes the rename and builders is deleted before A
// copies. A must not bring builders back.
func TestGroupRenameStaleCoordinatorAfterDelete(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			h := &hooked{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createGroupWith(t, "devs")
			h.at("create", iam.KindGroup, "builders", func() error {
				if _, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders"); err != nil {
					t.Errorf("coordinator B: %v", err)
				}
				if _, err := e.groups.DeleteGroup(ctx, &iamv1.DeleteGroupRequest{Name: groupName("builders")}); err != nil {
					t.Errorf("delete builders: %v", err)
				}
				return nil
			})
			_, err := e.api.UpdateGroupRename(ctx, renameGroupReq("devs", "", ""), "builders")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			*e.now = e.now.Add(2 * time.Minute)
			if _, err := e.api.ResumeRenames(ctx); err != nil {
				t.Fatal(err)
			}
			for _, n := range []string{"devs", "builders"} {
				_, err := e.groups.GetGroup(ctx, &iamv1.GetGroupRequest{Name: groupName(n)})
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
		})
	}
}
