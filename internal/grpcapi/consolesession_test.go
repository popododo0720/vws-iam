package grpcapi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func consoleSpec(tok, user string, expires time.Time) grpcapi.ConsoleSessionSpec {
	d := sha256.Sum256([]byte(tok))
	return grpcapi.ConsoleSessionSpec{
		ID: "web-" + tok, UserName: user, TokenDigest: d[:], Expires: expires, SourceIP: "192.0.2.7", MFA: true,
	}
}

// TestConsoleSession: a session created on one replica is valid on
// another and after a restart, moves LastActive at most once a minute, ends
// after its idle timeout or expiry (ExpiredToken), and GCConsoleSessions
// removes exactly the ended ones. On both store backends.
func TestConsoleSession(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			e.setPassword(t, ctx, "alice", testPassword)

			idle := consoleSpec("idle", "Alice", now.Add(12*time.Hour))
			idle.IdleTimeout = 10 * time.Minute
			for _, spec := range []grpcapi.ConsoleSessionSpec{
				idle, consoleSpec("short", "alice", now.Add(time.Hour)), consoleSpec("long", "alice", now.Add(12*time.Hour)),
			} {
				if _, err := e.api.CreateConsoleSession(ctx, proj, spec); err != nil {
					t.Fatal(err)
				}
			}
			other := newEnvOn(t, b, &now)
			sess, err := other.api.CheckConsoleSession(ctx, "idle")
			if err != nil {
				t.Fatalf("on another replica: %v", err)
			}
			if sess.UserName != "alice" || !sess.MFA || sess.SourceIP != "192.0.2.7" || sess.Project != proj {
				t.Fatalf("session %+v", sess)
			}

			now = now.Add(9 * time.Minute)
			if _, err := newEnvOn(t, b, &now).api.CheckConsoleSession(ctx, "idle"); err != nil {
				t.Fatalf("after a restart: %v", err)
			}
			v, err := store.Get[iam.ConsoleSession](ctx, b, sess.Hash)
			if err != nil || !v.Object.LastActive.Equal(now) {
				t.Fatalf("last active %v (%v), want %v", v.Object.LastActive, err, now)
			}
			now = now.Add(30 * time.Second)
			if _, err := e.api.CheckConsoleSession(ctx, "idle"); err != nil {
				t.Fatal(err)
			}
			if again, err := store.Get[iam.ConsoleSession](ctx, b, sess.Hash); err != nil || again.Version != v.Version {
				t.Fatalf("a check within a minute of the last one wrote the session (%v)", err)
			}

			now = now.Add(10 * time.Minute)
			wantAWS(t, ignore(e.api.CheckConsoleSession(ctx, "idle")), codes.Unauthenticated, "ExpiredToken")
			if _, err := e.api.CheckConsoleSession(ctx, "short"); err != nil {
				t.Fatalf("a session in use: %v", err)
			}
			now = now.Add(time.Hour)
			wantAWS(t, ignore(e.api.CheckConsoleSession(ctx, "short")), codes.Unauthenticated, "ExpiredToken")

			n, err := e.api.GCConsoleSessions(ctx)
			if err != nil || n != 2 {
				t.Fatalf("gc removed %d (%v), want the idle and the expired session", n, err)
			}
			if _, err := e.api.CheckConsoleSession(ctx, "long"); err != nil {
				t.Fatalf("gc removed a live session: %v", err)
			}
			wantAWS(t, ignore(e.api.CheckConsoleSession(ctx, "short")), codes.Unauthenticated, "InvalidClientTokenId")
			if n, err := other.api.GCConsoleSessions(ctx); err != nil || n != 0 {
				t.Fatalf("second gc removed %d (%v), want 0", n, err)
			}
		})
	}
}

// TestConsoleSessionRevocation: Logout, RevokeUserSessions, removing the
// console password and recreating the user each end a user's console
// sessions on every replica; a new root password ends root's.
func TestConsoleSessionRevocation(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			other := newEnvOn(t, b, &now)
			ctx := t.Context()
			later := now.Add(time.Hour)
			open := func(tok, user string) {
				t.Helper()
				if _, err := e.api.CreateConsoleSession(ctx, proj, consoleSpec(tok, user, later)); err != nil {
					t.Fatal(err)
				}
				if _, err := other.api.CheckConsoleSession(ctx, tok); err != nil {
					t.Fatal(err)
				}
			}
			revoked := func(tok string) {
				t.Helper()
				wantAWS(t, ignore(other.api.CheckConsoleSession(ctx, tok)), codes.Unauthenticated, "InvalidClientTokenId")
			}
			e.createUser(t, ctx, "alice")
			e.setPassword(t, ctx, "alice", testPassword)

			open("logout", "alice")
			if err := e.api.RevokeConsoleSession(ctx, "logout"); err != nil {
				t.Fatal(err)
			}
			revoked("logout")
			first := consoleSessionAt(t, b, "logout").Revoked
			now = now.Add(time.Minute)
			if err := other.api.RevokeConsoleSession(ctx, "logout"); err != nil {
				t.Fatalf("repeat logout: %v", err)
			}
			if again := consoleSessionAt(t, b, "logout").Revoked; !again.Equal(first) {
				t.Fatalf("repeat moved the revoke time to %v, want %v", again, first)
			}
			if err := e.api.RevokeConsoleSession(ctx, "never-issued"); err != nil {
				t.Fatalf("unknown token: %v", err)
			}

			open("revoke", "alice")
			if _, err := e.users.RevokeUserSessions(ctx, &iamv1.RevokeUserSessionsRequest{Name: userName("alice")}); err != nil {
				t.Fatal(err)
			}
			revoked("revoke")
			open("after-revoke", "alice")

			if _, err := e.users.DeleteLoginProfile(ctx, &iamv1.DeleteLoginProfileRequest{Name: userName("alice")}); err != nil {
				t.Fatal(err)
			}
			revoked("after-revoke")
			_, err := e.api.CreateConsoleSession(ctx, proj, consoleSpec("no-password", "alice", later))
			wantAWS(t, err, codes.Unauthenticated, "InvalidClientTokenId")

			e.setPassword(t, ctx, "alice", testPassword)
			open("recreated", "alice")
			if _, err := e.users.DeleteLoginProfile(ctx, &iamv1.DeleteLoginProfileRequest{Name: userName("alice")}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.users.DeleteUser(ctx, &iamv1.DeleteUserRequest{Name: userName("alice")}); err != nil {
				t.Fatal(err)
			}
			e.createUser(t, ctx, "alice")
			e.setPassword(t, ctx, "alice", testPassword)
			revoked("recreated")

			if _, err := grpcapi.SetRootPassword(ctx, b, proj, rootPW, now); err != nil {
				t.Fatal(err)
			}
			open("root", "")
			if _, err := grpcapi.SetRootPassword(ctx, b, proj, rootPW+"2", now); err != nil {
				t.Fatal(err)
			}
			revoked("root")
		})
	}
}

// TestConsoleSessionStoredHashed: the stored record holds neither the token
// nor the digest console-api sent, in any common encoding.
func TestConsoleSessionStoredHashed(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	e.createUser(t, ctx, "alice")
	e.setPassword(t, ctx, "alice", testPassword)
	tok := "c2Vzc2lvbi10b2tlbi1vZi1hbGljZQ"
	spec := consoleSpec(tok, "alice", now.Add(time.Hour))
	spec.ID = "web-hashed"
	sess, err := e.api.CreateConsoleSession(ctx, proj, spec)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Get(ctx, iam.KindConsoleSession, sess.Hash)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		tok, string(spec.TokenDigest), hex.EncodeToString(spec.TokenDigest),
		base64.StdEncoding.EncodeToString(spec.TokenDigest), base64.RawURLEncoding.EncodeToString(spec.TokenDigest),
	} {
		if bytes.Contains(raw.Spec, []byte(secret)) || bytes.Contains([]byte(raw.Key), []byte(secret)) {
			t.Fatalf("stored record %s (key %s) holds %q", raw.Spec, raw.Key, secret)
		}
	}
}

// TestCreateConsoleSessionErrors: request faults are ValidationError before
// any store access, an unknown user NoSuchEntity, and a repeat with the
// same digest returns the stored session unless its spec differs.
func TestCreateConsoleSessionErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	later := now.Add(time.Hour)
	for name, edit := range map[string]func(*grpcapi.ConsoleSessionSpec){
		"bad id":           func(s *grpcapi.ConsoleSessionSpec) { s.ID = "Web/1" },
		"bad user":         func(s *grpcapi.ConsoleSessionSpec) { s.UserName = "a b" },
		"short digest":     func(s *grpcapi.ConsoleSessionSpec) { s.TokenDigest = s.TokenDigest[:31] },
		"plaintext token":  func(s *grpcapi.ConsoleSessionSpec) { s.TokenDigest = []byte("token") },
		"expired":          func(s *grpcapi.ConsoleSessionSpec) { s.Expires = now },
		"negative idle":    func(s *grpcapi.ConsoleSessionSpec) { s.IdleTimeout = -time.Second },
		"source not an ip": func(s *grpcapi.ConsoleSessionSpec) { s.SourceIP = "<script>" },
	} {
		spec := consoleSpec("tok", "alice", later)
		edit(&spec)
		_, err := e.api.CreateConsoleSession(ctx, proj, spec)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
		if t.Failed() {
			t.Fatalf("%s", name)
		}
	}
	_, err := e.api.CreateConsoleSession(ctx, "Bad_Project", consoleSpec("tok", "alice", later))
	wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	_, err = e.api.CreateConsoleSession(ctx, proj, consoleSpec("tok", "nobody", later))
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	_, err = e.api.CreateConsoleSession(ctx, proj, consoleSpec("tok", "", later))
	wantAWS(t, err, codes.Unauthenticated, "InvalidClientTokenId")
	if es, err := b.List(ctx, iam.KindConsoleSession); err != nil || len(es) != 0 {
		t.Fatalf("refused creates stored %d sessions (%v)", len(es), err)
	}

	e.createUser(t, ctx, "alice")
	e.setPassword(t, ctx, "alice", testPassword)
	spec := consoleSpec("tok", "alice", later)
	first, err := e.api.CreateConsoleSession(ctx, proj, spec)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	again, err := newEnvOn(t, b, &now).api.CreateConsoleSession(ctx, proj, spec)
	if err != nil || again != first {
		t.Fatalf("repeat after a restart: %+v (%v), want %+v", again, err, first)
	}
	spec.MFA = false
	_, err = e.api.CreateConsoleSession(ctx, proj, spec)
	wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
}

func consoleSessionAt(t *testing.T, b store.Backend, tok string) iam.ConsoleSession {
	t.Helper()
	d := sha256.Sum256([]byte(tok))
	h := sha256.Sum256(d[:])
	v, err := store.Get[iam.ConsoleSession](t.Context(), b, hex.EncodeToString(h[:]))
	if err != nil {
		t.Fatal(err)
	}
	return v.Object
}

func ignore[T any](_ T, err error) error { return err }
