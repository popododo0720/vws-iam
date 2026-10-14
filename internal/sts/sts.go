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

// Caller is the authenticated principal asking for credentials.
type Caller struct {
	Principal authz.Principal
	// MFA is true when the caller authenticated with MFA (or holds a
	// session that did).
	MFA bool
	// Temporary is true when the caller signed with STS credentials.
	Temporary bool
	// Context carries request keys such as aws:SourceIp.
	Context map[string][]string
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
}

// Session is a validated temporary session.
type Session struct {
	AccessKeyID string
	Secret      string
	Principal   authz.Principal
	MFA         bool
	Expires     time.Time
}

// String hides the secret.
func (s Session) String() string { return "Session{" + s.AccessKeyID + " " + s.Principal.ARN + "}" }

// Caller returns the session as the caller of a further request.
func (s Session) Caller(reqCtx map[string][]string) Caller {
	return Caller{Principal: s.Principal, MFA: s.MFA, Temporary: true, Context: reqCtx}
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
	account string
	now     func() time.Time
}

// New returns a Service. now may be nil.
func New(b store.Backend, keys *secret.Keyring, a *authz.Authorizer, account string, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{b: b, keys: keys, authz: a, account: account, now: now}
}

func callerContext(c Caller) map[string][]string {
	m := map[string][]string{}
	for k, v := range c.Context {
		m[k] = v
	}
	m["aws:MultiFactorAuthPresent"] = []string{fmt.Sprint(c.MFA)}
	return m
}

// AssumeRole returns credentials for roleARN if the role's trust policy
// trusts the caller and the caller's own policies allow sts:AssumeRole on
// it. sessionPolicy, if set, narrows the session.
func (s *Service) AssumeRole(ctx context.Context, c Caller, roleARN, sessionName string, duration time.Duration, sessionPolicy string) (Credentials, error) {
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
	chained := c.Temporary
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
	d, err := s.authz.Authorize(ctx, c.Principal, "sts:AssumeRole", roleARN, callerContext(c))
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
	callerARN := c.Principal.ARN
	if callerARN == "" {
		_, callerARN, err = s.authz.IdentityPolicies(ctx, c.Principal)
		if err != nil {
			return Credentials{}, err
		}
	}
	tctx := callerContext(c)
	tctx["aws:PrincipalArn"] = []string{callerARN}
	td := policy.Evaluate(policy.Request{Principal: callerARN, Account: s.account, Action: "sts:AssumeRole", Resource: roleARN, Context: tctx}, []policy.Named{{Name: roleARN + " trust policy", Doc: trust}}, nil)
	if !td.Allowed {
		return Credentials{}, fmt.Errorf("%w: %s does not trust %s", ErrAccessDenied, roleARN, callerARN)
	}
	arn := iam.ARN("sts", "", s.account, "assumed-role/"+r.Object.Name+"/"+sessionName)
	creds, err := s.issue(session{Kind: int(authz.Role), Name: r.Object.Name, ARN: arn, MFA: c.MFA, Policies: policies, Chained: chained}, duration)
	creds.AssumedRoleARN = arn
	return creds, err
}

// GetSessionToken returns credentials for a user, typically to carry MFA.
func (s *Service) GetSessionToken(ctx context.Context, c Caller, duration time.Duration) (Credentials, error) {
	if c.Principal.Kind != authz.User || c.Temporary {
		return Credentials{}, fmt.Errorf("%w: GetSessionToken needs long-term user credentials", ErrAccessDenied)
	}
	if duration == 0 {
		duration = DefaultSessionDuration
	}
	if duration < MinDuration || duration > MaxSessionTokenDuration {
		return Credentials{}, fmt.Errorf("%w: DurationSeconds %d", ErrInvalidRequest, int(duration.Seconds()))
	}
	_, arn, err := s.authz.IdentityPolicies(ctx, c.Principal)
	if err != nil {
		return Credentials{}, err
	}
	return s.issue(session{Kind: int(authz.User), Name: c.Principal.Name, ARN: arn, MFA: c.MFA}, duration)
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
	sess.AccessKeyID, sess.Secret = id, sec
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
// foreign, mismatched or expired token is rejected.
func (s *Service) Validate(accessKeyID, token string) (Session, error) {
	kid, body, ok := strings.Cut(token, ".")
	if !ok || !strings.HasPrefix(accessKeyID, "ASIA") {
		return Session{}, ErrInvalidToken
	}
	ct, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Session{}, ErrInvalidToken
	}
	plain, err := s.keys.Open(iam.Sealed{KeyID: kid, Ciphertext: ct}, tokenAAD+"/"+accessKeyID)
	if err != nil {
		return Session{}, ErrInvalidToken
	}
	var sess session
	if err := json.Unmarshal(plain, &sess); err != nil || sess.AccessKeyID != accessKeyID {
		return Session{}, ErrInvalidToken
	}
	if !s.now().Before(sess.Expires) {
		return Session{}, ErrExpired
	}
	p := authz.Principal{Kind: authz.PrincipalKind(sess.Kind), Name: sess.Name, ARN: sess.ARN, SessionPolicies: sess.Policies}
	if p.Kind == authz.User {
		p.ARN = "" // a GetSessionToken session acts as the user itself
	}
	return Session{AccessKeyID: sess.AccessKeyID, Secret: sess.Secret, Principal: p, MFA: sess.MFA, Expires: sess.Expires}, nil
}
