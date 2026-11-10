package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// consoleSessionTouch bounds LastActive writes: a check moves it at most
// once per interval, so an idle timeout holds to within it.
const consoleSessionTouch = time.Minute

// consoleSessionSpec is vws.iam.v1 ConsoleSessionSpec with the user as a
// name ("" for the account root user).
type consoleSessionSpec struct {
	ID          string
	UserName    string
	TokenDigest []byte
	Expires     time.Time
	IdleTimeout time.Duration
	SourceIP    string
	MFA         bool
}

// consoleSessionKey is the store key of a session: the hex SHA-256 of the
// token digest console-api sends, so the stored record holds neither.
func consoleSessionKey(digest []byte) string {
	h := sha256.Sum256(digest)
	return hex.EncodeToString(h[:])
}

func consoleTokenKey(tok string) string {
	d := sha256.Sum256([]byte(tok))
	return consoleSessionKey(d[:])
}

// createConsoleSession stores a console session of project pid for a user
// that still has a console password (or for root while a root login
// exists), bound to its UID and its revocation generation. Request faults
// are ValidationError before any store access; an unknown user is
// NoSuchEntity, one without a console password or being renamed
// InvalidClientTokenId. A repeat with the same digest and spec (a retry
// after a lost response, on any replica) returns the stored session; the
// same digest with another spec is EntityAlreadyExists.
//
// TODO(#454): serve this as ConsoleSessionService.CreateConsoleSession
// once a vws-proto release carries it.
func (s *Server) createConsoleSession(
	ctx context.Context, pid string, spec consoleSessionSpec,
) (iam.ConsoleSession, error) {
	now := s.now().UTC()
	switch {
	case !iam.ValidProject(pid):
		return iam.ConsoleSession{}, invalidID("project " + quote(pid) + " is not a project id")
	case !iam.ValidConsoleSessionID(spec.ID):
		return iam.ConsoleSession{}, invalidID("console session id must be 1 to 63 of [a-z0-9-], starting with a letter")
	case spec.UserName != "" && !iam.ValidName(spec.UserName):
		return iam.ConsoleSession{}, invalidSpec("user must be 1 to 64 characters of [\\w+=,.@-]")
	case len(spec.TokenDigest) != sha256.Size:
		return iam.ConsoleSession{}, invalidSpec("token digest must be a SHA-256 digest of 32 bytes")
	case !spec.Expires.After(now):
		return iam.ConsoleSession{}, invalidSpec("expire time must be after the request time")
	case spec.IdleTimeout < 0:
		return iam.ConsoleSession{}, invalidSpec("idle timeout must not be negative")
	}
	if spec.SourceIP != "" {
		if _, err := netip.ParseAddr(spec.SourceIP); err != nil {
			return iam.ConsoleSession{}, invalidSpec("source ip must be an IP address")
		}
	}
	sess := iam.ConsoleSession{
		Hash: consoleSessionKey(spec.TokenDigest), Project: pid, ID: spec.ID, UserName: spec.UserName,
		MFA: spec.MFA, SourceIP: spec.SourceIP, Created: now, Expires: spec.Expires.UTC(), IdleTimeout: spec.IdleTimeout,
	}
	if err := s.bindConsoleSession(ctx, &sess); err != nil {
		return iam.ConsoleSession{}, err
	}
	_, err := store.Create(ctx, s.b, sess)
	if errors.Is(err, store.ErrExists) {
		v, gerr := store.Get[iam.ConsoleSession](ctx, s.b, sess.Hash)
		if gerr != nil {
			return iam.ConsoleSession{}, toStatus(ctx, fmt.Errorf("console session %s: %w", sess.ID, gerr))
		}
		if !sameConsoleSession(v.Object, sess) {
			return iam.ConsoleSession{}, fail(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists",
				"a console session with this token already exists")
		}
		return v.Object, nil
	}
	if err != nil {
		return iam.ConsoleSession{}, toStatus(ctx, fmt.Errorf("create console session %s: %w", sess.ID, err))
	}
	return sess, nil
}

// bindConsoleSession sets the UID and revocation generation of the user
// (or root login) a new session belongs to.
func (s *Server) bindConsoleSession(ctx context.Context, sess *iam.ConsoleSession) error {
	b := s.project(sess.Project).b
	if sess.UserName == "" {
		r, err := store.Get[iam.RootLogin](ctx, b, iam.RootLoginKey)
		if errors.Is(err, store.ErrNotFound) {
			return badCredentials()
		}
		if err != nil {
			return toStatus(ctx, fmt.Errorf("root login: %w", err))
		}
		sess.UserUID = r.Object.UID
		return nil
	}
	u, err := store.Get[iam.User](ctx, b, sess.UserName)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return notFound("The user with name " + sess.UserName + " cannot be found.")
	case err != nil:
		return toStatus(ctx, fmt.Errorf("get user %q: %w", sess.UserName, err))
	case u.Object.PasswordHash == "" || u.Object.Renaming():
		return badCredentials()
	}
	sess.UserName, sess.UserUID, sess.RevokeGeneration = u.Object.Name, u.Object.UID, u.Object.SessionsRevokeGeneration
	return nil
}

func sameConsoleSession(a, b iam.ConsoleSession) bool {
	return a.Project == b.Project && a.ID == b.ID && a.UserName == b.UserName && a.UserUID == b.UserUID &&
		a.MFA == b.MFA && a.SourceIP == b.SourceIP && a.Expires.Equal(b.Expires) && a.IdleTimeout == b.IdleTimeout
}

// checkConsoleSession returns the live console session of token. Unknown,
// revoked and orphaned sessions are InvalidClientTokenId: the user (or root
// login) must still exist with the UID it had at create, a console
// password, and the revocation generation it had (RevokeUserSessions bumps
// it). A session past its expiry or idle for its idle timeout is
// ExpiredToken; neither is deleted here (GCConsoleSessions removes it).
// A live session's LastActive moves at most once per consoleSessionTouch;
// losing that write to another replica is not an error.
//
// TODO(#454): serve ValidateSession through this once a vws-proto release
// carries ConsoleSessionService.
func (s *Server) checkConsoleSession(ctx context.Context, tok string) (iam.ConsoleSession, error) {
	if tok == "" {
		return iam.ConsoleSession{}, badCredentials()
	}
	v, err := store.Get[iam.ConsoleSession](ctx, s.b, consoleTokenKey(tok))
	if errors.Is(err, store.ErrNotFound) {
		return iam.ConsoleSession{}, badCredentials()
	}
	if err != nil {
		return iam.ConsoleSession{}, toStatus(ctx, fmt.Errorf("console session: %w", err))
	}
	sess, now := v.Object, s.now()
	if !sess.Revoked.IsZero() {
		return iam.ConsoleSession{}, badCredentials()
	}
	if consoleSessionEnded(sess, now) {
		return iam.ConsoleSession{}, fail(codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken", "the session has expired")
	}
	if err := s.consoleSessionOwner(ctx, sess); err != nil {
		return iam.ConsoleSession{}, err
	}
	if now.Sub(lastActive(sess)) < consoleSessionTouch {
		return sess, nil
	}
	sess.LastActive = now.UTC()
	_, err = store.Update(ctx, s.b, sess, v.Version)
	if err != nil && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
		return iam.ConsoleSession{}, toStatus(ctx, fmt.Errorf("console session %s: %w", sess.ID, err))
	}
	return sess, nil
}

func (s *Server) consoleSessionOwner(ctx context.Context, sess iam.ConsoleSession) error {
	ref := iam.Session{Project: sess.Project, UserName: sess.UserName, UserUID: sess.UserUID}
	if sess.UserName == "" {
		if err := s.sessionRoot(ctx, ref); err != nil {
			return toStatus(ctx, err)
		}
		return nil
	}
	u, err := s.sessionUser(ctx, ref)
	if err != nil {
		return err
	}
	if u.Object.SessionsRevokeGeneration != sess.RevokeGeneration {
		return badCredentials()
	}
	return nil
}

func lastActive(sess iam.ConsoleSession) time.Time {
	if sess.LastActive.IsZero() {
		return sess.Created
	}
	return sess.LastActive
}

// consoleSessionEnded reports whether sess is past its expiry or idle
// timeout at now.
func consoleSessionEnded(sess iam.ConsoleSession, now time.Time) bool {
	return !now.Before(sess.Expires) || (sess.IdleTimeout > 0 && !now.Before(lastActive(sess).Add(sess.IdleTimeout)))
}

// revokeConsoleSession ends the console session of token at once (Logout).
// An unknown token, and a session already revoked (which keeps its first
// revoke time), succeed without a write.
//
// TODO(#454): serve Logout and RevokeConsoleSession through this once a
// vws-proto release carries ConsoleSessionService.
func (s *Server) revokeConsoleSession(ctx context.Context, tok string) error {
	if tok == "" {
		return nil
	}
	_, err := store.Mutate(ctx, s.b, consoleTokenKey(tok), func(sess *iam.ConsoleSession) error {
		if !sess.Revoked.IsZero() {
			return errNoop
		}
		sess.Revoked = s.now().UTC()
		return nil
	})
	switch {
	case err == nil, errors.Is(err, errNoop), errors.Is(err, store.ErrNotFound):
		return nil
	default:
		return toStatus(ctx, fmt.Errorf("revoke console session: %w", err))
	}
}

// GCConsoleSessions deletes console sessions past their expiry or idle
// timeout, revoked ones included, and returns how many it removed. Every
// replica may run it; a lost race is not an error.
func (s *Server) GCConsoleSessions(ctx context.Context) (int, error) {
	now := s.now()
	return gcPaged(ctx, s, func(sess iam.ConsoleSession) bool { return consoleSessionEnded(sess, now) })
}
