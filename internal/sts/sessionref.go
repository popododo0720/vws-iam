package sts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
)

// A session reference lets Authorize ask whether the STS session behind a
// gateway Principal is still valid (#20). It is what the gateway can carry
// without the session's secret: the session's identity and the revocation
// generation it was issued at, sealed under the KEK keyring. The wire field
// that carries it waits for vws-proto (TODO(#20) in grpcapi).
const (
	refAAD = "sts/session-ref"
	// maxRefLen bounds a reference before it is decoded. A real one is a
	// few hundred characters.
	maxRefLen = 4096
)

// refPayload is the sealed plaintext of a reference: the identity and
// revocation fields of a session and nothing that signs or opens a request.
type refPayload struct {
	Kind        int       `json:"kind"`
	Name        string    `json:"name"`
	ARN         string    `json:"arn,omitempty"`
	PrincipalID string    `json:"pid"`
	RoleID      string    `json:"rid,omitempty"`
	SessionName string    `json:"sname,omitempty"`
	MFA         bool      `json:"mfa,omitempty"`
	Federated   bool      `json:"fed,omitempty"`
	AuthTime    time.Time `json:"auth"`
	IssuedAt    time.Time `json:"iat"`
	Expires     time.Time `json:"exp"`
	// RevokeGen is copied from the session as issued (nil for a token from
	// before #46), never read again when the reference is minted, so a
	// revocation between issue and mint still refuses the reference.
	RevokeGen *uint64 `json:"rg,omitempty"`
	Project   string  `json:"project"`
}

// SessionRef is a session as a checked reference describes it. It holds no
// secret.
type SessionRef struct {
	Project string
	// Principal is the session's principal as Validate reports it, without
	// session policies.
	Principal   authz.Principal
	PrincipalID string
	// RoleID and SessionName are set for an assumed role.
	RoleID      string
	SessionName string
	MFA         bool
	AuthTime    time.Time
	Expires     time.Time
	federated   bool
}

// UniqueID is the unique id the gateway reports for the session's
// principal: the project for root, the user's id, or "<role id>:<session
// name>" for an assumed role. A federated session has none (the gateway
// does not describe it yet, #107), so it describes no gateway principal.
func (r SessionRef) UniqueID() string {
	switch {
	case r.federated:
		return ""
	case r.Principal.Kind == authz.Root:
		return r.Project
	case r.Principal.Kind == authz.Role:
		return r.RoleID + ":" + r.SessionName
	}
	return r.PrincipalID
}

func (p refPayload) session() session {
	return session{
		Kind: p.Kind, Name: p.Name, ARN: p.ARN, MFA: p.MFA, Expires: p.Expires, PrincipalID: p.PrincipalID,
		IssuedAt: p.IssuedAt, RevokeGen: p.RevokeGen, Project: p.Project, AuthTime: p.AuthTime,
		RoleID: p.RoleID, SessionName: p.SessionName, Federated: p.Federated,
	}
}

// MintSessionRef returns the reference of the session token presented with
// accessKeyID. The caller has already validated the token (Validate); this
// only opens it, so it reads no store and a revocation that landed since
// shows when the reference is checked. A token that does not open is
// ErrInvalidToken, an expired one ErrExpired.
func (s *Service) MintSessionRef(accessKeyID, token string) (string, error) {
	sess, err := s.open(accessKeyID, token)
	if err != nil {
		return "", err
	}
	if sess.Project != s.account {
		return "", ErrInvalidToken
	}
	b, err := json.Marshal(refPayload{
		Kind: sess.Kind, Name: sess.Name, ARN: sess.ARN, PrincipalID: sess.PrincipalID, RoleID: sess.RoleID,
		SessionName: sess.SessionName, MFA: sess.MFA, Federated: sess.Federated, AuthTime: sess.AuthTime,
		IssuedAt: sess.IssuedAt, Expires: sess.Expires, RevokeGen: sess.RevokeGen, Project: sess.Project,
	})
	if err != nil {
		return "", fmt.Errorf("session reference: %w", err)
	}
	sealed, err := s.keys.Seal(b, refAAD+"/"+s.account)
	if err != nil {
		return "", fmt.Errorf("session reference: %w", err)
	}
	return sealed.KeyID + "." + base64.RawURLEncoding.EncodeToString(sealed.Ciphertext), nil
}

// CheckSessionRef reports whether the session ref describes is still
// valid: not expired, its user or role still exists with the id it was
// issued for, and no revocation has landed since it was issued (the same
// check as Validate, generation based and clock free). A malformed,
// tampered, other-project or unknown-KEK reference, a revoked or expired
// session, and a principal that no longer exists are refusals
// (ErrInvalidToken, ErrExpired); a store failure is returned as an error.
// It only reads, so checking a reference twice gives the same answer.
func (s *Service) CheckSessionRef(ctx context.Context, ref string) (_ SessionRef, err error) {
	ctx, end := start(ctx, "CheckSessionRef")
	defer end(&err)
	defer wrapOperationError("CheckSessionRef", &err)
	p, err := s.openRef(ref)
	if err != nil {
		return SessionRef{}, err
	}
	if !s.now().Before(p.Expires) {
		return SessionRef{}, ErrExpired
	}
	sess := p.session()
	if err := s.checkPrincipal(ctx, sess); err != nil {
		return SessionRef{}, err
	}
	return SessionRef{
		Project: p.Project, Principal: sess.principal(), PrincipalID: p.PrincipalID, RoleID: p.RoleID,
		SessionName: p.SessionName, MFA: p.MFA, AuthTime: p.AuthTime, Expires: p.Expires, federated: p.Federated,
	}, nil
}

func (s *Service) openRef(ref string) (refPayload, error) {
	i := strings.LastIndexByte(ref, '.')
	if len(ref) > maxRefLen || i <= 0 {
		return refPayload{}, ErrInvalidToken
	}
	ct, err := base64.RawURLEncoding.Strict().DecodeString(ref[i+1:])
	if err != nil {
		return refPayload{}, ErrInvalidToken
	}
	plain, err := s.keys.Open(iam.Sealed{KeyID: ref[:i], Ciphertext: ct}, refAAD+"/"+s.account)
	if err != nil {
		return refPayload{}, ErrInvalidToken
	}
	var p refPayload
	if err := json.Unmarshal(plain, &p); err != nil || p.Project != s.account {
		return refPayload{}, ErrInvalidToken
	}
	return p, nil
}
