package grpcapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/password"
	"github.com/popododo0720/vws-iam/internal/sigv4"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// Session and freshness limits.
const (
	LoginSessionTTL = 12 * time.Hour
	// MaxAuthAge bounds auth_time of an MFA claim: the longest STS session.
	MaxAuthAge   = sts.MaxSessionTokenDuration
	clockSkew    = 5 * time.Minute
	markInterval = time.Minute
)

func rootARN(project string) string { return iam.ARN("iam", "", project, "root") }

func badCredentials() error {
	return invalidCredentials("InvalidClientTokenId", "the security token included in the request is invalid")
}

// Authenticate verifies a SigV4 signature for the gateway. The gateway
// sends the canonical request and string to sign; the secret never leaves
// vws-iam. Long-term keys (AKIA) are found through the global key index,
// temporary ones (ASIA) are opened from the session token.
func (s *Server) Authenticate(ctx context.Context, req *iamv1.AuthenticateRequest) (resp *iamv1.AuthenticateResponse, err error) {
	defer func() { s.m.add(ctx, s.m.authn, attribute.String("result", result(err))) }()
	return s.authenticate(ctx, req, true)
}

// authenticate verifies req. gateway is set for the gateway's
// Authenticate, whose Principal then goes to Authorize; it is false for an
// STS call that vws-iam serves itself with the session it opened.
func (s *Server) authenticate(
	ctx context.Context, req *iamv1.AuthenticateRequest, gateway bool,
) (*iamv1.AuthenticateResponse, error) {
	sr := sigv4.Request{Date: req.GetDate(), Region: req.GetRegion(), Service: req.GetService(), CanonicalRequest: req.GetCanonicalRequest(), StringToSign: req.GetStringToSign(), Signature: req.GetSignature()}
	id := req.GetAccessKeyId()
	switch {
	case strings.HasPrefix(id, "ASIA"):
		return s.authTemporary(ctx, req, sr, gateway)
	case !accessKeyID.MatchString(id) || req.GetSessionToken() != "":
		return nil, badCredentials()
	}
	pid, err := accesskey.ProjectOf(ctx, s.b, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, badCredentials()
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	p := s.project(pid)
	cred, err := p.keys.GetSigningCredential(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, badCredentials()
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	if err := sigv4.Check([]byte(cred.Secret), sr, s.now()); err != nil {
		return nil, toStatus(ctx, err)
	}
	s.markUsed(ctx, p, id, req.GetService(), req.GetRegion())
	now := timestamppb.New(s.now())
	if cred.Root {
		return &iamv1.AuthenticateResponse{Account: pid, Arn: rootARN(pid), IsRoot: true, Principal: &iamv1.Principal{
			Type: iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT, Arn: rootARN(pid), Project: pid, UniqueId: pid, AuthTime: now,
		}}, nil
	}
	u, err := store.Get[iam.User](ctx, p.b, cred.UserName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, badCredentials()
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	arn := iam.UserARN(pid, u.Object)
	return &iamv1.AuthenticateResponse{Account: pid, Arn: arn, Principal: &iamv1.Principal{
		Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: arn, Project: pid, UniqueId: u.Object.ID, Resource: name(pid, "users", u.Object.Name), AuthTime: now,
	}}, nil
}

func (s *Server) authTemporary(
	ctx context.Context, req *iamv1.AuthenticateRequest, sr sigv4.Request, gateway bool,
) (*iamv1.AuthenticateResponse, error) {
	if req.GetSessionToken() == "" {
		return nil, invalidCredentials("MissingAuthenticationToken", "a session token is required for temporary credentials")
	}
	pid, err := sts.SessionProject(s.keys, req.GetAccessKeyId(), req.GetSessionToken(), s.now)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	sess, err := s.project(pid).sts.Validate(ctx, req.GetAccessKeyId(), req.GetSessionToken())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	if err := sigv4.Check([]byte(sess.Secret), sr, s.now()); err != nil {
		return nil, toStatus(ctx, err)
	}
	if gateway && sess.SAML != nil {
		// TODO(#202): describe a SAML session to the gateway once
		// vws-proto lets Authorize carry its saml:sub, saml:sub_type and
		// saml:namequalifier. Until then a policy conditioned on them
		// could not see them (a Deny on saml:sub would fail open), so the
		// session fails closed here; STS calls vws-iam serves itself
		// restore them from the session token (sts callerContext).
		return nil, badCredentials()
	}
	pr, err := s.sessionPrincipal(ctx, sess)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &iamv1.AuthenticateResponse{Account: sess.Project, Arn: pr.GetArn(), IsRoot: pr.GetType() == iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT, Principal: pr, ExpireTime: timestamppb.New(sess.Expires)}, nil
}

// sessionPrincipal describes an STS session; the user or role must still exist.
func (s *Server) sessionPrincipal(ctx context.Context, sess sts.Session) (*iamv1.Principal, error) {
	pid := sess.Project
	pr := &iamv1.Principal{Project: pid, MfaAuthenticated: sess.MFA, AuthTime: ts(sess.AuthTime)}
	p := s.project(pid)
	if sess.Federated {
		// TODO(#107): describe a federated user session once vws-proto
		// has a federated principal type and Authorize carries session
		// policies. Until then the gateway would authorize it as its IAM
		// user, with the user's full permissions, so it fails closed.
		return nil, badCredentials()
	}
	switch sess.Principal.Kind {
	case authz.Root:
		pr.Type, pr.Arn, pr.UniqueId = iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT, rootARN(pid), pid
	case authz.User:
		u, err := store.Get[iam.User](ctx, p.b, sess.Principal.Name)
		if err != nil {
			return nil, badCredentials()
		}
		pr.Type, pr.Arn, pr.UniqueId, pr.Resource = iamv1.PrincipalType_PRINCIPAL_TYPE_USER, iam.UserARN(pid, u.Object), u.Object.ID, name(pid, "users", u.Object.Name)
	case authz.Role:
		r, err := store.Get[iam.Role](ctx, p.b, sess.Principal.Name)
		if err != nil || r.Object.ID != sess.RoleID {
			return nil, badCredentials()
		}
		pr.Type, pr.Arn, pr.Resource = iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE, sess.Principal.ARN, name(pid, "roles", r.Object.Name)
		pr.UniqueId, pr.SessionName = r.Object.ID+":"+sess.SessionName, sess.SessionName
	default:
		return nil, badCredentials()
	}
	return pr, nil
}

// markUsed records key use at most once a minute per key; failures only
// lose the last-used time, so they are ignored by design.
func (s *Server) markUsed(ctx context.Context, p project, id, service, region string) {
	now := s.now()
	if last, ok := s.marked.Load(id); ok {
		if t, ok := last.(time.Time); ok && now.Sub(t) < markInterval {
			return
		}
	}
	s.marked.Store(id, now)
	if err := p.keys.MarkUsed(ctx, id, service, region); err != nil {
		s.marked.Delete(id)
	}
}

// checked is a principal re-verified against the store.
type checked struct {
	project  project
	az       authz.Principal
	userName string
	mfa      bool
	authTime time.Time
}

// recheck verifies a Principal sent by a caller (the gateway): the entity
// must still exist with the same ARN and unique id, and an MFA claim needs
// a recent auth_time and, for a user, an enabled device.
func (s *Server) recheck(ctx context.Context, pr *iamv1.Principal) (checked, error) {
	deny := func(why string) (checked, error) { return checked{}, accessDenied("principal rejected: " + why) }
	pid := pr.GetProject()
	if !iam.ValidProject(pid) {
		return deny("project")
	}
	p := s.project(pid)
	c := checked{project: p, mfa: pr.GetMfaAuthenticated()}
	if pr.GetAuthTime() != nil {
		c.authTime = pr.GetAuthTime().AsTime()
	}
	switch pr.GetType() {
	case iamv1.PrincipalType_PRINCIPAL_TYPE_ROOT:
		if pr.GetArn() != rootARN(pid) || pr.GetUniqueId() != pid {
			return deny("root identity mismatch")
		}
		c.az = authz.Principal{Kind: authz.Root}
	case iamv1.PrincipalType_PRINCIPAL_TYPE_USER:
		_, id, err := child(pr.GetResource(), "users")
		if err != nil {
			return deny("resource")
		}
		u, err := store.Get[iam.User](ctx, p.b, id)
		if errors.Is(err, store.ErrNotFound) {
			return deny("user no longer exists")
		}
		if err != nil {
			return checked{}, err
		}
		if iam.UserARN(pid, u.Object) != pr.GetArn() || u.Object.ID != pr.GetUniqueId() {
			return deny("user identity mismatch")
		}
		c.az, c.userName = authz.Principal{Kind: authz.User, Name: u.Object.Name}, u.Object.Name
	case iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE:
		_, id, err := child(pr.GetResource(), "roles")
		if err != nil {
			return deny("resource")
		}
		r, err := store.Get[iam.Role](ctx, p.b, id)
		if errors.Is(err, store.ErrNotFound) {
			return deny("role no longer exists")
		}
		if err != nil {
			return checked{}, err
		}
		arn := iam.ARN("sts", "", pid, "assumed-role/"+r.Object.Name+"/"+pr.GetSessionName())
		if pr.GetSessionName() == "" || arn != pr.GetArn() || r.Object.ID+":"+pr.GetSessionName() != pr.GetUniqueId() {
			return deny("role session identity mismatch")
		}
		c.az = authz.Principal{Kind: authz.Role, Name: r.Object.Name, ARN: arn}
	default:
		return deny("type")
	}
	if c.mfa {
		now := s.now()
		switch {
		case c.authTime.IsZero(), c.authTime.After(now.Add(clockSkew)), now.Sub(c.authTime) > MaxAuthAge:
			return deny("MFA claim without a valid auth_time")
		case c.userName != "":
			ok, err := p.mfa.Required(ctx, c.userName)
			if err != nil {
				return checked{}, err
			}
			if !ok {
				return deny("MFA claim but the user has no enabled device")
			}
		}
	}
	return c, nil
}

// serverKeys are context keys only vws-iam may set.
var serverKeys = map[string]bool{
	"aws:multifactorauthpresent": true, "aws:multifactorauthage": true, "aws:principalarn": true,
	"aws:username": true, "aws:userid": true, "aws:currenttime": true, "aws:principalaccount": true,
	"aws:principaltype": true, "aws:tokenissuetime": true,
}

// Authorize evaluates identity policies after rechecking the principal.
// No resources means "*". The decision is ALLOW only if every resource is
// allowed; an explicit deny anywhere wins.
func (s *Server) Authorize(ctx context.Context, req *iamv1.AuthorizeRequest) (*iamv1.AuthorizeResponse, error) {
	// TODO(#109): set resp.EncodedMessage on a deny once vws-proto
	// carries AuthorizeResponse.encoded_message (popododo0720/vws-proto#84).
	resp, _, err := s.authorize(ctx, req, false)
	return resp, err
}

// authorize is Authorize; with encode, a deny decided by policy
// evaluation also returns its encoded authorization message
// (authorizationMessage) for DecodeAuthorizationMessage.
func (s *Server) authorize(
	ctx context.Context, req *iamv1.AuthorizeRequest, encode bool,
) (resp *iamv1.AuthorizeResponse, encoded string, err error) {
	defer func() {
		s.m.add(ctx, s.m.authz, attribute.String("result", result(err)), attribute.String("decision", resp.GetDecision().String()))
	}()
	if req.GetAction() == "" || !strings.Contains(req.GetAction(), ":") {
		return nil, "", invalidSpec("action must look like service:Action")
	}
	c, err := s.recheck(ctx, req.GetPrincipal())
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) {
			return &iamv1.AuthorizeResponse{Decision: iamv1.Decision_DECISION_DENY_IMPLICIT, Reason: ae.msg}, "", nil
		}
		return nil, "", toStatus(ctx, err)
	}
	// saml:* keys come only from a verified assertion or a sealed SAML
	// session, never from the request; Authenticate refuses SAML sessions
	// (#202), so no principal here has them.
	rc := map[string][]string{}
	for k, v := range req.GetContext() {
		if lk := strings.ToLower(k); !serverKeys[lk] && !strings.HasPrefix(lk, "saml:") {
			rc[k] = v.GetValues()
		}
	}
	rc["aws:MultiFactorAuthPresent"] = []string{strconv.FormatBool(c.mfa)}
	if c.mfa {
		rc["aws:MultiFactorAuthAge"] = []string{strconv.FormatInt(int64(max(s.now().Sub(c.authTime), 0)/time.Second), 10)}
	}
	rc["aws:userid"] = []string{req.GetPrincipal().GetUniqueId()}
	rc["aws:PrincipalAccount"] = []string{c.project.id}
	resources := req.GetResources()
	if len(resources) == 0 {
		resources = []string{"*"}
	}
	var allow, denyResp *iamv1.AuthorizeResponse
	var deny denied
	for _, res := range resources {
		d, err := c.project.authz.Authorize(ctx, c.az, req.GetAction(), res, rc)
		if err != nil {
			if errors.Is(err, authz.ErrNoSuchEntity) {
				gone := &iamv1.AuthorizeResponse{
					Decision: iamv1.Decision_DECISION_DENY_IMPLICIT, Reason: "principal no longer exists",
				}
				return gone, "", nil
			}
			return nil, "", toStatus(ctx, err)
		}
		out := &iamv1.AuthorizeResponse{MatchedPolicy: d.Policy, MatchedStatement: d.Statement, Reason: d.Reason}
		switch {
		case d.Explicit:
			out.Decision = iamv1.Decision_DECISION_DENY_EXPLICIT
			denyResp, deny = out, denied{resource: res, d: d, ctx: rc}
		case !d.Allowed && denyResp == nil:
			out.Decision = iamv1.Decision_DECISION_DENY_IMPLICIT
			denyResp, deny = out, denied{resource: res, d: d, ctx: rc}
		case d.Allowed && allow == nil:
			out.Decision = iamv1.Decision_DECISION_ALLOW
			allow = out
		}
		if d.Explicit {
			break
		}
	}
	if denyResp == nil {
		return allow, "", nil
	}
	if encode {
		if encoded, err = authorizationMessage(c, req.GetPrincipal(), req.GetAction(), deny); err != nil {
			return nil, "", toStatus(ctx, err)
		}
	}
	return denyResp, encoded, nil
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// Login checks a console password (and TOTP when a device is enabled) and
// starts a session. Only the token's SHA-256 is stored.
func (s *Server) Login(ctx context.Context, req *iamv1.LoginRequest) (resp *iamv1.LoginResponse, err error) {
	defer func() { s.m.add(ctx, s.m.login, attribute.String("result", result(err))) }()
	pid := req.GetProject()
	if !iam.ValidProject(pid) || !iam.ValidName(req.GetUserName()) {
		return nil, badCredentials()
	}
	p := s.project(pid)
	// The whole password + MFA check is one counted attempt per user and
	// source IP (limit.go); an MFA_REQUIRED answer is not a failure.
	var u store.Versioned[iam.User]
	mfaOK, needMFA, renaming := false, false, false
	err = s.limitedVerify(ctx, callers{userSubject(pid, req.GetUserName())}.withIP(req.GetSourceIp()), func() error {
		var err error
		u, err = store.Get[iam.User](ctx, p.b, req.GetUserName())
		if errors.Is(err, store.ErrNotFound) || (err == nil && u.Object.PasswordHash == "") {
			// Same work as a real check, so timing does not reveal users.
			burn(req.GetPassword())
			return badCredentials()
		}
		if err != nil {
			return err
		}
		if password.Verify(req.GetPassword(), u.Object.PasswordHash) != nil {
			return badCredentials()
		}
		if u.Object.Renaming() {
			// The MFA devices may name either side of the rename
			// (#134): refuse rather than check too few. The password
			// was right, so the attempt is not a failure.
			renaming = true
			return nil
		}
		devices, err := p.mfa.List(ctx, u.Object.Name)
		if err != nil {
			return err
		}
		if len(devices) == 0 {
			return nil
		}
		if req.GetTotpCode() == "" {
			needMFA = true
			return nil
		}
		for _, d := range devices {
			if p.mfa.Verify(ctx, u.Object.Name, d.Name, req.GetTotpCode()) == nil {
				mfaOK = true
				return nil
			}
		}
		return invalidCredentials("InvalidAuthenticationCode", "invalid MFA code")
	})
	renewLoginLock(ctx, p, req.GetUserName(), err)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	if renaming {
		return nil, toStatus(ctx, fmt.Errorf("user %q: %w", u.Object.Name, store.ErrRenaming))
	}
	if needMFA {
		return nil, fail(codes.Unauthenticated, "MFA_REQUIRED", "MultiFactorAuthenticationRequired", "an MFA code is required")
	}
	if err := sameLoginUser(ctx, p, u); err != nil {
		return nil, toStatus(ctx, err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, toStatus(ctx, err)
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	now := s.now().UTC()
	sess := iam.Session{
		Hash: hashToken(tok), Project: pid, UserName: u.Object.Name, UserUID: u.Object.UID, MFA: mfaOK,
		AuthTime: now, Expires: now.Add(LoginSessionTTL), SourceIP: req.GetSourceIp(),
	}
	if _, err := store.Create(ctx, s.b, sess); err != nil {
		return nil, toStatus(ctx, err)
	}
	if _, err := store.Mutate(ctx, p.b, u.Object.Name, func(x *iam.User) error {
		if x.UID != u.Object.UID {
			return store.ErrNotFound // renamed away: not this user
		}
		x.PasswordLastUsed = now.Truncate(time.Second)
		return nil
	}); err != nil {
		s.m.add(ctx, s.m.login, attribute.String("result", "last_used_not_recorded"))
	}
	return &iamv1.LoginResponse{
		SessionToken: tok, ExpireTime: timestamppb.New(sess.Expires), PasswordResetRequired: u.Object.PasswordResetRequired,
		Principal: &iamv1.Principal{
			Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: iam.UserARN(pid, u.Object), Project: pid, UniqueId: u.Object.ID,
			Resource: name(pid, "users", u.Object.Name), MfaAuthenticated: mfaOK, AuthTime: timestamppb.New(now),
		},
	}, nil
}

// sameLoginUser fences a console session on the user Login checked: the
// MFA devices were listed after u was read, so a rename marked since may
// have moved them away and the check saw too few (#134). A rename marks
// the user and bumps its generation, and the mark stays until the old
// object is deleted, so the same UID and generation without a mark mean
// the device list was complete. Anything else is ConcurrentModification.
func sameLoginUser(ctx context.Context, p project, u store.Versioned[iam.User]) error {
	again, err := store.Get[iam.User](ctx, p.b, u.Object.Name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if err != nil || again.Object.UID != u.Object.UID || again.Object.Generation != u.Object.Generation ||
		again.Object.Renaming() {
		return fmt.Errorf("user %q changed during sign-in: %w", u.Object.Name, store.ErrRenaming)
	}
	return nil
}

// ValidateSession returns the principal of a console session.
func (s *Server) ValidateSession(ctx context.Context, req *iamv1.ValidateSessionRequest) (*iamv1.ValidateSessionResponse, error) {
	sess, err := s.consoleSession(ctx, req.GetSessionToken())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	u, err := s.sessionUser(ctx, sess)
	if err != nil {
		return nil, err
	}
	return &iamv1.ValidateSessionResponse{ExpireTime: timestamppb.New(sess.Expires), Principal: &iamv1.Principal{
		Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Arn: iam.UserARN(sess.Project, u.Object), Project: sess.Project, UniqueId: u.Object.ID,
		Resource: name(sess.Project, "users", u.Object.Name), MfaAuthenticated: sess.MFA, AuthTime: timestamppb.New(sess.AuthTime),
	}}, nil
}

// consoleSession looks up an unexpired console session by its token; the
// user must still exist and still have a console password.
func (s *Server) consoleSession(ctx context.Context, tok string) (iam.Session, error) {
	if tok == "" {
		return iam.Session{}, badCredentials()
	}
	v, err := store.Get[iam.Session](ctx, s.b, hashToken(tok))
	if errors.Is(err, store.ErrNotFound) {
		return iam.Session{}, badCredentials()
	}
	if err != nil {
		return iam.Session{}, err
	}
	sess := v.Object
	if !s.now().Before(sess.Expires) {
		if derr := store.Delete[iam.Session](ctx, s.b, sess.Hash, v.Version); derr != nil && !errors.Is(derr, store.ErrNotFound) {
			return iam.Session{}, derr
		}
		return iam.Session{}, fail(codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken", "the session has expired")
	}
	if _, err := s.sessionUser(ctx, sess); err != nil {
		return iam.Session{}, err
	}
	return sess, nil
}

// sessionUser returns the user of a console session: it must still exist
// with a console password and be the same user (UID) that signed in, so
// a session never passes to another user later given its name (#134). A
// session stored before UserUID existed has none and matches by name.
func (s *Server) sessionUser(ctx context.Context, sess iam.Session) (store.Versioned[iam.User], error) {
	u, err := store.Get[iam.User](ctx, s.project(sess.Project).b, sess.UserName)
	if err != nil || u.Object.PasswordHash == "" || (sess.UserUID != "" && u.Object.UID != sess.UserUID) {
		return store.Versioned[iam.User]{}, badCredentials()
	}
	return u, nil
}

// Logout ends a console session. Unknown tokens are fine (idempotent).
func (s *Server) Logout(ctx context.Context, req *iamv1.LogoutRequest) (*iamv1.LogoutResponse, error) {
	if req.GetSessionToken() == "" {
		return &iamv1.LogoutResponse{}, nil
	}
	err := store.Delete[iam.Session](ctx, s.b, hashToken(req.GetSessionToken()), "")
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, toStatus(ctx, err)
	}
	return &iamv1.LogoutResponse{}, nil
}
