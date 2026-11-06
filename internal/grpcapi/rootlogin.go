package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/password"
	"github.com/popododo0720/vws-iam/internal/store"
)

// Root password bounds, as AWS sets them for the root user (and at least
// three of uppercase, lowercase, digits and symbols), and the bounded
// retries of SetRootPassword when another writer changes the root login.
const (
	minRootPassword, maxRootPassword = 8, 128
	setRootPasswordAttempts          = 5
)

// ErrRootPassword is a root password outside the AWS rules. Its message
// never carries the password.
var ErrRootPassword = errors.New(
	"root password must be 8 to 128 characters with at least three of uppercase, lowercase, digits and symbols")

func validRootPassword(pw string) bool {
	n := len([]rune(pw))
	if n < minRootPassword || n > maxRootPassword {
		return false
	}
	seen := map[string]bool{}
	for _, r := range pw {
		switch {
		case unicode.IsUpper(r):
			seen["upper"] = true
		case unicode.IsLower(r):
			seen["lower"] = true
		case unicode.IsDigit(r):
			seen["digit"] = true
		case unicode.IsPrint(r) && !unicode.IsSpace(r):
			seen["symbol"] = true
		}
	}
	return len(seen) >= 3
}

// SetRootPassword stores the argon2id hash of the root console password
// of project (the bootstrap Job, #34). A password the stored hash already
// verifies writes nothing, so a rerun changes nothing; another password
// replaces the hash under a new UID, which ends every earlier root
// console session. It reports whether it wrote.
func SetRootPassword(ctx context.Context, b store.Backend, project, pw string, now time.Time) (bool, error) {
	if !iam.ValidProject(project) {
		return false, fmt.Errorf("set root password: invalid project %q", project)
	}
	if !validRootPassword(pw) {
		return false, ErrRootPassword
	}
	pb := store.Scoped(b, project)
	for range setRootPasswordAttempts {
		if err := ctx.Err(); err != nil {
			return false, fmt.Errorf("set root password: %w", err)
		}
		cur, err := store.Get[iam.RootLogin](ctx, pb, iam.RootLoginKey)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return false, fmt.Errorf("set root password: read: %w", err)
		}
		found := err == nil
		if found && password.Verify(pw, cur.Object.PasswordHash) == nil {
			return false, nil
		}
		h, err := password.Hash(pw)
		if err != nil {
			return false, fmt.Errorf("set root password: %w", err)
		}
		next := iam.RootLogin{Meta: iam.Meta{UID: iam.NewUID()}, PasswordHash: h, Changed: now.UTC()}
		if found {
			next.Generation = cur.Object.Generation + 1
			_, err = store.Update(ctx, pb, next, cur.Version)
		} else {
			next.Generation = 1
			_, err = store.Create(ctx, pb, next)
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("set root password: write: %w", err)
		}
		return true, nil
	}
	return false, fmt.Errorf("set root password: %w", store.ErrConflict)
}

// isRootLogin reports whether a LoginRequest user name names the account
// root user. IAM names are case-insensitive, so every case of "root" is
// the root user and never an IAM user of that name.
func isRootLogin(userName string) bool { return strings.EqualFold(userName, iam.RootUserName) }

// rootSubject counts the root user's failed sign-ins. ':' is not in the
// IAM name alphabet, so it never shares a counter with an IAM user.
func rootSubject(project string) subject {
	return subject{iam.AttemptUser, project + ":" + iam.RootUserName}
}

func rootPrincipal(project string, mfa bool, authTime time.Time) *iamv1.Principal {
	return &iamv1.Principal{
		Type: iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT, Arn: rootARN(project), Project: project, UniqueId: project,
		MfaAuthenticated: mfa, AuthTime: timestamppb.New(authTime),
	}
}

// loginRoot checks the root console password and starts a root console
// session bound to the root login's UID. The root user has no MFA device
// in VWS, so the session never carries MFA and a TOTP code is not read.
func (s *Server) loginRoot(ctx context.Context, req *iamv1.LoginRequest) (*iamv1.LoginResponse, error) {
	pid := req.GetProject()
	p := s.project(pid)
	var r store.Versioned[iam.RootLogin]
	err := s.limitedVerify(ctx, loginCallers(rootSubject(pid), req.GetSourceIp()), func() error {
		var err error
		r, err = store.Get[iam.RootLogin](ctx, p.b, iam.RootLoginKey)
		if errors.Is(err, store.ErrNotFound) {
			burn(req.GetPassword())
			return badCredentials()
		}
		if err != nil {
			return fmt.Errorf("root login: %w", err)
		}
		if password.Verify(req.GetPassword(), r.Object.PasswordHash) != nil {
			return badCredentials()
		}
		return nil
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, toStatus(ctx, fmt.Errorf("root login: %w", err))
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now().UTC()
	sess := iam.Session{
		Hash: hashToken(tok), Project: pid, UserUID: r.Object.UID,
		AuthTime: now, Expires: now.Add(LoginSessionTTL), SourceIP: req.GetSourceIp(),
	}
	if _, err := store.Create(ctx, s.b, sess); err != nil {
		return nil, toStatus(ctx, fmt.Errorf("root login: %w", err))
	}
	return &iamv1.LoginResponse{
		SessionToken: tok, ExpireTime: timestamppb.New(sess.Expires), Principal: rootPrincipal(pid, false, now),
	}, nil
}

// sessionRoot checks that a root console session still matches the
// project's root login: one stored after the password changed (a new
// UID) or with no root login left is refused.
func (s *Server) sessionRoot(ctx context.Context, sess iam.Session) error {
	r, err := store.Get[iam.RootLogin](ctx, s.project(sess.Project).b, iam.RootLoginKey)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (sess.UserUID == "" || r.Object.UID != sess.UserUID)) {
		return badCredentials()
	}
	if err != nil {
		return fmt.Errorf("root session: %w", err)
	}
	return nil
}
