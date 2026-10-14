// Package sts issues temporary credentials: AssumeRole and GetSessionToken.
//
// A session token is the session itself (principal, temporary secret,
// expiry, MFA flag, session policies) sealed with AES-256-GCM under the KEK
// keyring, so it is opaque, tamper-evident and needs no storage. Validate
// opens it, binds it to its access key id, and rejects it after expiry.
package sts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
)

// Errors.
var (
	ErrAccessDenied   = errors.New("AccessDenied")
	ErrExpired        = errors.New("ExpiredToken")
	ErrInvalidToken   = errors.New("InvalidClientTokenId")
	ErrInvalidRequest = errors.New("ValidationError")
)

// Duration limits.
const (
	MinDuration             = 15 * time.Minute
	DefaultAssumeDuration   = time.Hour
	ChainedMaxDuration      = time.Hour
	DefaultSessionDuration  = 12 * time.Hour
	MaxSessionTokenDuration = 36 * time.Hour
	tokenAAD                = "sts/session"
)

var sessionNameRE = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

// Caller is the authenticated principal asking for credentials. Its
// fields are unexported: only Resolve (from what the caller signed with)
// and Session.Caller build one, so MFA and temporary-credential status are
// derived server-side and never taken from a client-filled struct.
type Caller struct {
	principal   authz.Principal
	principalID string
	mfa         bool
	temporary   bool
}

// Principal is the caller's principal.
func (c Caller) Principal() authz.Principal { return c.principal }

// MFA reports whether the caller authenticated with MFA.
func (c Caller) MFA() bool { return c.mfa }

// Temporary reports whether the caller signed with STS credentials.
func (c Caller) Temporary() bool { return c.temporary }

// Credential is what a request was signed with. Resolve must only be given
// a credential whose SigV4 signature the caller has already verified
// (grpcapi Authenticate); the session token itself is verified here.
type Credential struct {
	AccessKeyID  string
	SessionToken string
}

// MFA is an MFA device serial number and a current code from it.
type MFA struct {
	SerialNumber string
	TokenCode    string
}

// MFAVerifier checks a code of user's device; it must reject replays.
type MFAVerifier interface {
	VerifyMFA(ctx context.Context, user, serialNumber, code string) error
}

// Credentials are temporary credentials. Never log them.
type Credentials struct {
	AccessKeyID  string
	Secret       string
	SessionToken string
	Expiration   time.Time
	// AssumedRoleARN is set by AssumeRole.
	AssumedRoleARN string
}

// String hides the secret and token.
func (c Credentials) String() string {
	return "Credentials{" + c.AccessKeyID + " expires=" + c.Expiration.Format(time.RFC3339) + " secret=REDACTED}"
}

// session is the sealed token payload.
type session struct {
	AccessKeyID string    `json:"k"`
	Secret      string    `json:"s"`
	Kind        int       `json:"t"`
	Name        string    `json:"n"`
	ARN         string    `json:"a"`
	MFA         bool      `json:"m,omitempty"`
	Expires     time.Time `json:"e"`
	Policies    []string  `json:"p,omitempty"`
	Chained     bool      `json:"c,omitempty"`
	// PrincipalID binds the session to the user or role it was issued for:
	// a deleted and recreated principal of the same name does not inherit it.
	PrincipalID string `json:"pid"`
	// IssuedAt is compared with the principal's SessionsRevokedBefore.
	IssuedAt time.Time `json:"iat"`
}

// Session is a validated temporary session.
type Session struct {
	AccessKeyID string
	Secret      string
	Principal   authz.Principal
	PrincipalID string
	MFA         bool
	IssuedAt    time.Time
	Expires     time.Time
}

// String hides the secret.
func (s Session) String() string { return "Session{" + s.AccessKeyID + " " + s.Principal.ARN + "}" }

// Caller returns the session as the caller of a further request.
func (s Session) Caller() Caller {
	return Caller{principal: s.Principal, principalID: s.PrincipalID, mfa: s.MFA, temporary: true}
}

// Context returns the request context keys a session carries.
func (s Session) Context() map[string][]string {
	return map[string][]string{"aws:MultiFactorAuthPresent": {fmt.Sprint(s.MFA)}}
}

// Service issues and validates temporary credentials.
type Service struct {
	b       store.Backend
	keys    *secret.Keyring
	authz   *authz.Authorizer
	mfa     MFAVerifier
	account string
	now     func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithMFA sets the verifier of SerialNumber and TokenCode. Without one,
// any request carrying an MFA code is refused.
func WithMFA(v MFAVerifier) Option { return func(s *Service) { s.mfa = v } }

// New returns a Service. now may be nil.
func New(b store.Backend, keys *secret.Keyring, a *authz.Authorizer, account string, now func() time.Time, opts ...Option) *Service {
	if now == nil {
		now = time.Now
	}
	s := &Service{b: b, keys: keys, authz: a, account: account, now: now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// serverKeys are context keys only the server sets.
var serverKeys = map[string]bool{
	"aws:multifactorauthpresent": true, "aws:multifactorauthage": true, "aws:principalarn": true,
	"aws:username": true, "aws:userid": true, "aws:currenttime": true, "aws:tokenissuetime": true,
	"aws:principalaccount": true, "aws:principaltype": true,
}

// callerContext copies request keys (aws:SourceIp, sts:ExternalId, ...),
// drops any server key a client tried to set, and adds the server's own.
func callerContext(c Caller, reqCtx map[string][]string) map[string][]string {
	m := map[string][]string{}
	for k, v := range reqCtx {
		if !serverKeys[strings.ToLower(k)] {
			m[k] = v
		}
	}
	m["aws:MultiFactorAuthPresent"] = []string{fmt.Sprint(c.mfa)}
	return m
}

// Resolve derives the caller from its credential: a session token is
// opened and checked here; a long-term key must exist and be active.
func (s *Service) Resolve(ctx context.Context, cred Credential) (Caller, error) {
	if cred.SessionToken != "" {
		sess, err := s.Validate(ctx, cred.AccessKeyID, cred.SessionToken)
		if err != nil {
			return Caller{}, err
		}
		return sess.Caller(), nil
	}
	if !strings.HasPrefix(cred.AccessKeyID, "AKIA") {
		return Caller{}, ErrInvalidToken
	}
	k, err := store.Get[iam.AccessKey](ctx, s.b, cred.AccessKeyID)
	if errors.Is(err, store.ErrNotFound) {
		return Caller{}, ErrInvalidToken
	}
	if err != nil {
		return Caller{}, fmt.Errorf("resolve access key: %w", err)
	}
	if k.Object.Status != iam.KeyActive {
		return Caller{}, ErrInvalidToken
	}
	u, err := store.Get[iam.User](ctx, s.b, k.Object.UserName)
	if errors.Is(err, store.ErrNotFound) {
		return Caller{}, ErrInvalidToken
	}
	if err != nil {
		return Caller{}, fmt.Errorf("resolve user: %w", err)
	}
	return Caller{principal: authz.Principal{Kind: authz.User, Name: u.Object.Name}, principalID: u.Object.ID}, nil
}

// verifyMFA checks an MFA code for a long-term or session user caller.
// It returns whether the new session carries MFA.
func (s *Service) verifyMFA(ctx context.Context, c Caller, m MFA) (bool, error) {
	switch {
	case m.SerialNumber == "" && m.TokenCode == "":
		return c.mfa, nil
	case m.SerialNumber == "" || m.TokenCode == "":
		return false, fmt.Errorf("%w: SerialNumber and TokenCode go together", ErrInvalidRequest)
	case c.principal.Kind != authz.User:
		return false, fmt.Errorf("%w: only an IAM user can present an MFA code", ErrAccessDenied)
	case s.mfa == nil:
		return false, fmt.Errorf("%w: MFA is not available", ErrAccessDenied)
	}
	if err := s.mfa.VerifyMFA(ctx, c.principal.Name, m.SerialNumber, m.TokenCode); err != nil {
		return false, fmt.Errorf("%w: invalid MFA code: %w", ErrAccessDenied, err)
	}
	return true, nil
}

// RevokeSessions invalidates every session issued so far for a user
// (GetSessionToken) or a role (AssumeRole), like the AWS console's
// "Revoke active sessions". Later sessions are unaffected.
func (s *Service) RevokeSessions(ctx context.Context, kind authz.PrincipalKind, name string) error {
	now := s.now().UTC()
	var err error
	switch kind {
	case authz.User:
		_, err = store.Mutate(ctx, s.b, name, func(u *iam.User) error {
			u.SessionsRevokedBefore = now
			return nil
		})
	case authz.Role:
		_, err = store.Mutate(ctx, s.b, name, func(r *iam.Role) error {
			r.SessionsRevokedBefore = now
			return nil
		})
	default:
		return fmt.Errorf("%w: principal kind %d", ErrInvalidRequest, kind)
	}
	if err != nil {
		return fmt.Errorf("revoke sessions of %s: %w", name, err)
	}
	return nil
}

// AssumeRole returns credentials for roleARN if the role's trust policy
// trusts the caller and the caller's own policies allow sts:AssumeRole on
// it. sessionPolicy, if set, narrows the session.
func (s *Service) AssumeRole(ctx context.Context, c Caller, reqCtx map[string][]string, roleARN, sessionName string, duration time.Duration, sessionPolicy string, m MFA) (Credentials, error) {
	if c.principalID == "" {
		return Credentials{}, fmt.Errorf("%w: unresolved caller", ErrAccessDenied)
	}
	if !sessionNameRE.MatchString(sessionName) {
		return Credentials{}, fmt.Errorf("%w: RoleSessionName %q", ErrInvalidRequest, sessionName)
	}
	prefix := "arn:vws:iam::" + s.account + ":role/"
	i := strings.LastIndex(roleARN, "/")
	if !strings.HasPrefix(roleARN, prefix) || i < 0 {
		return Credentials{}, fmt.Errorf("%w: not authorized to assume %s", ErrAccessDenied, roleARN)
	}
	r, err := store.Get[iam.Role](ctx, s.b, roleARN[i+1:])
	if errors.Is(err, store.ErrNotFound) || (err == nil && iam.RoleARN(s.account, r.Object) != roleARN) {
		return Credentials{}, fmt.Errorf("%w: not authorized to assume %s", ErrAccessDenied, roleARN)
	}
	if err != nil {
		return Credentials{}, err
	}
	mfa, err := s.verifyMFA(ctx, c, m)
	if err != nil {
		return Credentials{}, err
	}
	c.mfa = mfa
	chained := c.temporary
	maxDur := r.Object.MaxSessionDuration
	if maxDur == 0 {
		maxDur = time.Hour
	}
	if chained {
		maxDur = min(maxDur, ChainedMaxDuration)
	}
	if duration == 0 {
		duration = min(DefaultAssumeDuration, maxDur)
	}
	if duration < MinDuration || duration > maxDur {
		return Credentials{}, fmt.Errorf("%w: DurationSeconds %d outside [%d, %d]", ErrInvalidRequest, int(duration.Seconds()), int(MinDuration.Seconds()), int(maxDur.Seconds()))
	}
	var policies []string
	if sessionPolicy != "" {
		if _, err := policy.ParseIdentity(sessionPolicy); err != nil {
			return Credentials{}, err
		}
		policies = []string{sessionPolicy}
	}

	// The caller's own permissions must allow sts:AssumeRole on the role.
	d, err := s.authz.Authorize(ctx, c.principal, "sts:AssumeRole", roleARN, callerContext(c, reqCtx))
	if err != nil {
		return Credentials{}, err
	}
	if !d.Allowed {
		return Credentials{}, fmt.Errorf("%w: %s", ErrAccessDenied, d.Reason)
	}
	// The role's trust policy must trust the caller.
	trust, err := policy.ParseTrust(r.Object.AssumeRolePolicy)
	if err != nil {
		return Credentials{}, fmt.Errorf("trust policy of %s: %w", roleARN, err)
	}
	callerARN := c.principal.ARN
	if callerARN == "" {
		_, callerARN, err = s.authz.IdentityPolicies(ctx, c.principal)
		if err != nil {
			return Credentials{}, err
		}
	}
	tctx := callerContext(c, reqCtx)
	tctx["aws:PrincipalArn"] = []string{callerARN}
	td := policy.Evaluate(policy.Request{Principal: callerARN, Account: s.account, Action: "sts:AssumeRole", Resource: roleARN, Context: tctx}, []policy.Named{{Name: roleARN + " trust policy", Doc: trust}}, nil)
	if !td.Allowed {
		return Credentials{}, fmt.Errorf("%w: %s does not trust %s", ErrAccessDenied, roleARN, callerARN)
	}
	arn := iam.ARN("sts", "", s.account, "assumed-role/"+r.Object.Name+"/"+sessionName)
	creds, err := s.issue(session{Kind: int(authz.Role), Name: r.Object.Name, ARN: arn, MFA: c.mfa, Policies: policies, Chained: chained, PrincipalID: r.Object.ID}, duration)
	creds.AssumedRoleARN = arn
	return creds, err
}

// GetSessionToken returns credentials for a user, typically to carry MFA.
// SerialNumber and TokenCode, when given, are verified here; only then does
// the session carry MFA.
func (s *Service) GetSessionToken(ctx context.Context, c Caller, duration time.Duration, m MFA) (Credentials, error) {
	if c.principal.Kind != authz.User || c.temporary || c.principalID == "" {
		return Credentials{}, fmt.Errorf("%w: GetSessionToken needs long-term user credentials", ErrAccessDenied)
	}
	if duration == 0 {
		duration = DefaultSessionDuration
	}
	if duration < MinDuration || duration > MaxSessionTokenDuration {
		return Credentials{}, fmt.Errorf("%w: DurationSeconds %d", ErrInvalidRequest, int(duration.Seconds()))
	}
	mfa, err := s.verifyMFA(ctx, c, m)
	if err != nil {
		return Credentials{}, err
	}
	_, arn, err := s.authz.IdentityPolicies(ctx, c.principal)
	if err != nil {
		return Credentials{}, err
	}
	return s.issue(session{Kind: int(authz.User), Name: c.principal.Name, ARN: arn, MFA: mfa, PrincipalID: c.principalID}, duration)
}

func (s *Service) issue(sess session, d time.Duration) (Credentials, error) {
	id, err := accesskey.NewKeyID("ASIA")
	if err != nil {
		return Credentials{}, err
	}
	sec, err := accesskey.NewSecret()
	if err != nil {
		return Credentials{}, err
	}
	sess.AccessKeyID, sess.Secret, sess.IssuedAt = id, sec, s.now().UTC()
	sess.Expires = s.now().UTC().Add(d).Truncate(time.Second)
	b, err := json.Marshal(sess)
	if err != nil {
		return Credentials{}, fmt.Errorf("session: %w", err)
	}
	sealed, err := s.keys.Seal(b, tokenAAD+"/"+id)
	if err != nil {
		return Credentials{}, err
	}
	token := sealed.KeyID + "." + base64.RawURLEncoding.EncodeToString(sealed.Ciphertext)
	return Credentials{AccessKeyID: id, Secret: sec, SessionToken: token, Expiration: sess.Expires}, nil
}

// Validate opens a session token presented with accessKeyID. A tampered,
// foreign, mismatched, expired or revoked token is rejected, as is one
// whose user or role was deleted or recreated.
func (s *Service) Validate(ctx context.Context, accessKeyID, token string) (Session, error) {
	sess, err := s.open(accessKeyID, token)
	if err != nil {
		return Session{}, err
	}
	var id string
	var revoked time.Time
	switch authz.PrincipalKind(sess.Kind) {
	case authz.User:
		u, err := store.Get[iam.User](ctx, s.b, sess.Name)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return Session{}, fmt.Errorf("session principal: %w", err)
		}
		id, revoked = u.Object.ID, u.Object.SessionsRevokedBefore
	case authz.Role:
		r, err := store.Get[iam.Role](ctx, s.b, sess.Name)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return Session{}, fmt.Errorf("session principal: %w", err)
		}
		id, revoked = r.Object.ID, r.Object.SessionsRevokedBefore
	}
	if id == "" || id != sess.PrincipalID {
		return Session{}, fmt.Errorf("%w: principal no longer exists", ErrInvalidToken)
	}
	if !sess.IssuedAt.After(revoked) && !revoked.IsZero() {
		return Session{}, fmt.Errorf("%w: session revoked", ErrInvalidToken)
	}
	p := authz.Principal{Kind: authz.PrincipalKind(sess.Kind), Name: sess.Name, ARN: sess.ARN, SessionPolicies: sess.Policies}
	if p.Kind == authz.User {
		p.ARN = "" // a GetSessionToken session acts as the user itself
	}
	return Session{AccessKeyID: sess.AccessKeyID, Secret: sess.Secret, Principal: p, PrincipalID: sess.PrincipalID, MFA: sess.MFA, IssuedAt: sess.IssuedAt, Expires: sess.Expires}, nil
}

func (s *Service) open(accessKeyID, token string) (session, error) {
	kid, body, ok := strings.Cut(token, ".")
	if !ok || !strings.HasPrefix(accessKeyID, "ASIA") {
		return session{}, ErrInvalidToken
	}
	ct, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return session{}, ErrInvalidToken
	}
	plain, err := s.keys.Open(iam.Sealed{KeyID: kid, Ciphertext: ct}, tokenAAD+"/"+accessKeyID)
	if err != nil {
		return session{}, ErrInvalidToken
	}
	var sess session
	if err := json.Unmarshal(plain, &sess); err != nil || sess.AccessKeyID != accessKeyID {
		return session{}, ErrInvalidToken
	}
	if !s.now().Before(sess.Expires) {
		return session{}, ErrExpired
	}
	return sess, nil
}
