package grpcapi_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

const rootPW = "Root-Console-9"

// cheapRoot stores a cheapPHC of pw as proj's root login, so a test can
// sign in many times without production-cost argon2id (see
// withCheapPassword).
func cheapRoot(t *testing.T, b store.Backend, pw string) iam.RootLogin {
	t.Helper()
	r := iam.RootLogin{
		Meta:         iam.Meta{UID: iam.NewUID(), Generation: 1},
		PasswordHash: cheapPHC(t, pw),
		Changed:      time.Now().UTC(),
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, proj), r); err != nil {
		t.Fatal(err)
	}
	return r
}

func storedRoot(t *testing.T, b store.Backend) store.Versioned[iam.RootLogin] {
	t.Helper()
	r, err := store.Get[iam.RootLogin](t.Context(), store.Scoped(b, proj), iam.RootLoginKey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rootLogin(t *testing.T, e *env, pw string) (*iamv1.LoginResponse, error) {
	t.Helper()
	ctx, cancel := slowRPC(t.Context())
	defer cancel()
	return e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "root", Password: pw, SourceIp: "192.0.2.10"})
}

func consoleGST(tok string, seconds int32) *iamv1.GetSessionTokenRequest {
	return &iamv1.GetSessionTokenRequest{
		DurationSeconds: seconds,
		Authentication:  &iamv1.GetSessionTokenRequest_ConsoleSessionToken{ConsoleSessionToken: tok},
	}
}

func wantRootPrincipal(t *testing.T, p *iamv1.Principal) {
	t.Helper()
	if p.GetType() != iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT || p.GetArn() != "arn:vws:iam::acme:root" ||
		p.GetProject() != proj || p.GetUniqueId() != proj || p.GetMfaAuthenticated() || p.GetResource() != "" {
		t.Fatalf("root principal %v", p)
	}
}

// TestRootLogin: the user name "root" (any case) signs in the account
// root user with the root console password; the session is a root
// principal on every replica and after a restart, it passes the Authorize
// recheck, and GetSessionToken accepts it (one hour at most, as AWS caps a
// root session), while an IAM user's console session stays refused.
func TestRootLogin(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			_, err := rootLogin(t, e, rootPW)
			wantBadLogin(t, err) // no root login stored yet
			cheapRoot(t, b, rootPW)
			_, err = rootLogin(t, e, "Wrong-Password-1")
			wantBadLogin(t, err)
			for _, name := range []string{"Root", "ROOT"} {
				if _, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: name, Password: rootPW}); err != nil {
					t.Fatalf("login as %q: %v", name, err)
				}
			}
			_, err = e.auth.Login(ctx, &iamv1.LoginRequest{Project: "other", UserName: "root", Password: rootPW})
			wantBadLogin(t, err) // another project's root has no login

			l, err := rootLogin(t, e, rootPW)
			if err != nil {
				t.Fatal(err)
			}
			wantRootPrincipal(t, l.GetPrincipal())
			if !l.GetPrincipal().GetAuthTime().AsTime().Equal(now) ||
				!l.GetExpireTime().AsTime().Equal(now.Add(grpcapi.LoginSessionTTL)) ||
				l.GetPasswordResetRequired() {
				t.Fatalf("login %v", l)
			}
			restarted := newEnvOn(t, b, &now)
			for _, api := range []*env{e, other, restarted} {
				v, err := api.auth.ValidateSession(
					ctx,
					&iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()},
				)
				if err != nil {
					t.Fatal(err)
				}
				wantRootPrincipal(t, v.GetPrincipal())
			}
			r, err := e.auth.Authorize(
				ctx,
				&iamv1.AuthorizeRequest{Principal: l.GetPrincipal(), Action: "iam:ListUsers"},
			)
			if err != nil || r.GetDecision() != iamv1.Decision_DECISION_ALLOW {
				t.Fatalf("authorize root session principal %v %v", r, err)
			}

			for _, tc := range []struct {
				seconds int32
				want    time.Duration
			}{{0, time.Hour}, {900, 15 * time.Minute}, {129600, time.Hour}} {
				st, err := other.token.GetSessionToken(ctx, consoleGST(l.GetSessionToken(), tc.seconds))
				if err != nil {
					t.Fatalf("root console GetSessionToken(%d): %v", tc.seconds, err)
				}
				if got := st.GetCredentials().GetExpireTime().AsTime().Sub(now); got != tc.want {
					t.Fatalf("root session of %ds lasts %v, want %v", tc.seconds, got, tc.want)
				}
				a, err := e.auth.Authenticate(
					ctx,
					e.sign(
						st.GetCredentials().GetAccessKeyId(),
						st.GetCredentials().GetSecretAccessKey(),
						st.GetCredentials().GetSessionToken(),
					),
				)
				if err != nil || !a.GetIsRoot() || a.GetArn() != "arn:vws:iam::acme:root" {
					t.Fatalf("authenticate root session %v %v", a, err)
				}
			}
			_, err = e.token.GetSessionToken(ctx, consoleGST(l.GetSessionToken(), 899))
			wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")

			withCheapPassword(t, e, b, "alice")
			ul, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: goodPW})
			if err != nil {
				t.Fatal(err)
			}
			_, err = e.token.GetSessionToken(ctx, consoleGST(ul.GetSessionToken(), 0))
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			_, err = e.token.GetSessionToken(ctx, consoleGST("not-a-session", 0))
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")

			if _, err := other.auth.Logout(ctx, &iamv1.LogoutRequest{SessionToken: l.GetSessionToken()}); err != nil {
				t.Fatal(err)
			}
			_, err = e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()})
			wantBadLogin(t, err)
			_, err = e.token.GetSessionToken(ctx, consoleGST(l.GetSessionToken(), 0))
			wantBadLogin(t, err)

			now = now.Add(grpcapi.LoginSessionTTL)
			l2, err := rootLogin(t, e, rootPW)
			if err != nil {
				t.Fatal(err)
			}
			now = now.Add(grpcapi.LoginSessionTTL)
			_, err = e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: l2.GetSessionToken()})
			wantErr(t, err, codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken")
		})
	}
}

// TestRootLoginIsNotAnIAMUser: an IAM user named root (any case) never
// signs in as itself or as the root user, and the root user's failed
// sign-ins are counted apart from every IAM user's.
func TestRootLoginIsNotAnIAMUser(t *testing.T) {
	b := renameBackends[0].open()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	withCheapPassword(t, e, b, "Root", "alice")
	_, err := rootLogin(t, e, goodPW)
	wantBadLogin(t, err)
	cheapRoot(t, b, rootPW)
	_, err = rootLogin(t, e, goodPW)
	wantBadLogin(t, err)
	l, err := rootLogin(t, e, rootPW)
	if err != nil {
		t.Fatal(err)
	}
	wantRootPrincipal(t, l.GetPrincipal())

	for range grpcapi.UserAttemptLimit - 2 { // two failures above
		_, err := rootLogin(t, e, "Wrong-Password-1")
		wantBadLogin(t, err)
	}
	_, err = rootLogin(t, e, rootPW)
	wantThrottled(t, err)
	if err := login(t.Context(), e, "alice", goodPW, "198.51.100.7"); err != nil {
		t.Fatalf("alice is throttled by root's failures: %v", err)
	}
	now = now.Add(grpcapi.AttemptLockout + time.Second)
	if _, err := rootLogin(t, e, rootPW); err != nil {
		t.Fatalf("root after the lockout: %v", err)
	}
}

// TestSetRootPassword: the bootstrap call stores only an argon2id hash; a
// rerun with the same password writes nothing and keeps sessions; a new
// password ends every earlier root session on every replica and refuses
// the old password.
func TestSetRootPassword(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			changed, err := grpcapi.SetRootPassword(ctx, b, proj, rootPW, now)
			if err != nil || !changed {
				t.Fatalf("first set: %v %v", changed, err)
			}
			first := storedRoot(t, b)
			if !strings.HasPrefix(first.Object.PasswordHash, "$argon2id$") ||
				strings.Contains(first.Object.PasswordHash, rootPW) {
				t.Fatal("root password not stored as an argon2id hash")
			}
			l, err := rootLogin(t, e, rootPW)
			if err != nil {
				t.Fatal(err)
			}
			changed, err = grpcapi.SetRootPassword(ctx, b, proj, rootPW, now)
			if err != nil || changed || storedRoot(t, b).Version != first.Version {
				t.Fatalf("rerun wrote: %v %v", changed, err)
			}
			kept := &iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()}
			if _, err := other.auth.ValidateSession(ctx, kept); err != nil {
				t.Fatalf("rerun ended the session: %v", err)
			}

			const next = "Rotated-Root-77"
			changed, err = grpcapi.SetRootPassword(ctx, b, proj, next, now)
			if err != nil || !changed {
				t.Fatalf("rotate: %v %v", changed, err)
			}
			if r := storedRoot(t, b); r.Object.UID == first.Object.UID ||
				r.Object.Generation != first.Object.Generation+1 {
				t.Fatalf("rotation kept uid %q generation %d", r.Object.UID, r.Object.Generation)
			}
			for _, api := range []*env{e, other} {
				_, err := api.auth.ValidateSession(
					ctx,
					&iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()},
				)
				wantBadLogin(t, err)
				_, err = api.token.GetSessionToken(ctx, consoleGST(l.GetSessionToken(), 0))
				wantBadLogin(t, err)
			}
			_, err = rootLogin(t, e, rootPW)
			wantBadLogin(t, err)
			if _, err := rootLogin(t, other, next); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestSetRootPasswordRejectsHostileInput: a password outside the AWS root
// rules or a bad project stores nothing, and no error carries the
// password.
func TestSetRootPasswordRejectsHostileInput(t *testing.T) {
	b := renameBackends[0].open()
	ctx := t.Context()
	for _, tc := range []struct{ project, pw string }{
		{proj, "Ab1-xyz"},                         // 7 characters
		{proj, "Ab1-" + strings.Repeat("x", 125)}, // 129 characters
		{proj, "alllowercase-only"},               // two classes
		{proj, "ALLUPPER12345"},                   // two classes
		{proj, ""},
		{"Bad_Project", rootPW},
	} {
		_, err := grpcapi.SetRootPassword(ctx, b, tc.project, tc.pw, time.Now())
		if err == nil {
			t.Fatalf("SetRootPassword(%q, %q) accepted", tc.project, tc.pw)
		}
		if tc.pw != "" && strings.Contains(err.Error(), tc.pw) {
			t.Fatalf("error carries the password: %v", err)
		}
	}
	if _, err := store.Get[iam.RootLogin](ctx, store.Scoped(b, proj), iam.RootLoginKey); !errors.Is(
		err,
		store.ErrNotFound,
	) {
		t.Fatalf("a rejected password was stored: %v", err)
	}
	for _, pw := range []string{"Ab1-xyzw", "Ab1-" + strings.Repeat("x", 124), "lower-and-123"} {
		if _, err := grpcapi.SetRootPassword(ctx, b, proj, pw, time.Now()); err != nil {
			t.Fatalf("SetRootPassword(%q): %v", pw, err)
		}
	}
}

// TestSetRootPasswordStoreFailure: a failed write leaves the old password
// in force, and a canceled context writes nothing.
func TestSetRootPasswordStoreFailure(t *testing.T) {
	m := renameBackends[0].open()
	now := time.Now().UTC()
	cheapRoot(t, m, rootPW)
	boom := errors.New("boom")
	failing := failingUpdate{m, iam.KindRootLogin, boom}
	if _, err := grpcapi.SetRootPassword(t.Context(), failing, proj, "Rotated-Root-77", now); !errors.Is(err, boom) {
		t.Fatalf("store failure: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := grpcapi.SetRootPassword(canceled, m, proj, "Rotated-Root-77", now); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	e := newEnvOn(t, m, &now)
	if _, err := rootLogin(t, e, rootPW); err != nil {
		t.Fatalf("old password after failed rotations: %v", err)
	}
}
