package grpcapi

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// Default durations, as in AWS.
const (
	defaultAssumeRole      = time.Hour
	defaultGetSessionToken = 12 * time.Hour
)

func credsProto(c sts.Credentials) *iamv1.Credentials {
	return &iamv1.Credentials{AccessKeyId: c.AccessKeyID, SecretAccessKey: c.Secret, SessionToken: c.SessionToken, ExpireTime: timestamppb.New(c.Expiration)}
}

// authn is how the caller of AssumeRole or GetSessionToken authenticated:
// exactly one of a console session token or a SigV4 request. A console
// session token is accepted by AssumeRole for IAM users; GetSessionToken
// accepts it only for the root user (AWS: long-term credentials only).
type authn struct {
	console string
	sigv4   *iamv1.AuthenticateRequest
}

// authnOf reads the request's authentication oneof (vws-proto v0.3.0). It
// is the only source of the caller; the deprecated caller field is ignored.
func authnOf(sigv4 *iamv1.AuthenticateRequest, console string) (authn, error) {
	switch {
	case sigv4 != nil:
		return authn{sigv4: sigv4}, nil
	case console != "":
		return authn{console: console}, nil
	}
	return authn{}, missingAuthentication()
}

// stsSigv4 checks that a forwarded SigV4 request was signed for this STS
// call, so a request signed for another service or action cannot be
// replayed here, and that the same signature is not used twice while its
// X-Amz-Date is inside the sigv4.MaxSkew window, on any replica
// (claimReplay).
func (s *Server) stsSigv4(ctx context.Context, r *iamv1.AuthenticateRequest, action string) error {
	if r.GetService() != "sts" {
		return accessDenied("the signed request is not an STS call")
	}
	lines := strings.Split(r.GetCanonicalRequest(), "\n")
	if len(lines) < 3 {
		return invalidCredentials("IncompleteSignature", "malformed canonical request")
	}
	q, err := url.ParseQuery(lines[2])
	if err != nil {
		return invalidCredentials("IncompleteSignature", "malformed canonical query")
	}
	if a := q.Get("Action"); a != "" && a != action {
		return accessDenied("the signed request is for " + a + ", not " + action)
	}
	return s.claimReplay(ctx, r)
}

// stsAttempts prepares the per-caller attempt limit of an STS call that
// presents an MFA code: the access key and source IP are counted with the
// user when mfaVerifier checks the code. A locked user, key or IP is
// refused there with Throttling before the code is checked, and the
// device lock is renewed (#44).
func stsAttempts(ctx context.Context, a authn, serial, code string) context.Context {
	if a.sigv4 == nil || (serial == "" && code == "") {
		return ctx
	}
	return withAttempts(ctx, callers{{iam.AttemptKey, a.sigv4.GetAccessKeyId()}}.withIP(a.sigv4.GetSourceIp()))
}

func missingAuthentication() error {
	return invalidCredentials("MissingAuthenticationToken", "the request must carry how the caller authenticated")
}

// authenticatedCaller verifies the caller's credential on the server and
// derives the STS caller from it (sts.Resolve or the stored console
// session). Nothing in the request body names the caller.
func (s *Server) authenticatedCaller(ctx context.Context, a authn, action string) (project, sts.Caller, error) {
	p, c, _, err := s.authenticatedCallerFrom(ctx, a, action)
	return p, c, err
}

// authenticatedCallerFrom is authenticatedCaller that also returns the
// source IP the gateway saw for a SigV4 request. A console session gives
// none: the address stored with it at Login is not the address of the
// current request, so the caller must supply that one itself.
func (s *Server) authenticatedCallerFrom(
	ctx context.Context, a authn, action string,
) (project, sts.Caller, string, error) {
	switch {
	case a.sigv4 != nil:
		resp, err := s.authenticate(ctx, a.sigv4)
		if err != nil {
			return project{}, sts.Caller{}, "", err
		}
		if err := s.stsSigv4(ctx, a.sigv4, action); err != nil {
			return project{}, sts.Caller{}, "", err
		}
		p := s.project(resp.GetAccount())
		c, err := p.sts.Resolve(ctx, sts.Credential{AccessKeyID: a.sigv4.GetAccessKeyId(), SessionToken: a.sigv4.GetSessionToken()})
		return p, c, a.sigv4.GetSourceIp(), err
	case a.console != "":
		v, err := s.consoleSession(ctx, a.console)
		if err != nil {
			return project{}, sts.Caller{}, "", err
		}
		p := s.project(v.Project)
		c, err := p.sts.ConsoleCaller(ctx, v.UserName, v.MFA, v.AuthTime)
		return p, c, "", err
	}
	return project{}, sts.Caller{}, "", missingAuthentication()
}

// AssumeRole issues role credentials to the authenticated caller, of the
// same project, after the caller's permission, trust policy and MFA checks
// in internal/sts.
func (s *Server) AssumeRole(ctx context.Context, req *iamv1.AssumeRoleRequest) (resp *iamv1.AssumeRoleResponse, err error) {
	defer func() {
		s.m.add(ctx, s.m.issued, attribute.String("rpc", "AssumeRole"), attribute.String("result", result(err)))
	}()
	a, err := authnOf(req.GetSigv4(), req.GetConsoleSessionToken())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return s.assumeRole(ctx, req, a)
}

func (s *Server) assumeRole(ctx context.Context, req *iamv1.AssumeRoleRequest, a authn) (*iamv1.AssumeRoleResponse, error) {
	pid, roleName, err := child(req.GetRole(), "roles")
	if err != nil {
		return nil, err
	}
	p, c, err := s.authenticatedCaller(ctx, a, "AssumeRole")
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	ctx = stsAttempts(ctx, a, req.GetSerialNumber(), req.GetTokenCode())
	if p.id != pid {
		return nil, accessDenied("cross-project AssumeRole is not supported")
	}
	d := time.Duration(req.GetDurationSeconds()) * time.Second
	if d == 0 {
		d = defaultAssumeRole
	}
	rc := map[string][]string{}
	if req.GetExternalId() != "" {
		rc["sts:ExternalId"] = []string{req.GetExternalId()}
	}
	role, err := p.roleByName(ctx, roleName)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	m := sts.MFA{SerialNumber: req.GetSerialNumber(), TokenCode: req.GetTokenCode()}
	creds, err := p.sts.AssumeRole(ctx, c, rc, iam.RoleARN(pid, role), req.GetRoleSessionName(), d, "", m)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	sess, err := p.sts.Validate(ctx, creds.AccessKeyID, creds.SessionToken)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &iamv1.AssumeRoleResponse{Credentials: credsProto(creds), AssumedRoleUser: &iamv1.Principal{
		Type: iamv1.PrincipalType_PRINCIPAL_TYPE_ASSUMED_ROLE, Arn: creds.AssumedRoleARN, Project: pid, UniqueId: role.ID + ":" + req.GetRoleSessionName(),
		Resource: name(pid, "roles", role.Name), SessionName: req.GetRoleSessionName(), MfaAuthenticated: sess.MFA, AuthTime: ts(sess.AuthTime),
	}}, nil
}

// GetSessionToken issues session credentials to a user (long-term key) or
// the root user, usually to carry MFA.
func (s *Server) GetSessionToken(ctx context.Context, req *iamv1.GetSessionTokenRequest) (resp *iamv1.GetSessionTokenResponse, err error) {
	defer func() {
		s.m.add(ctx, s.m.issued, attribute.String("rpc", "GetSessionToken"), attribute.String("result", result(err)))
	}()
	a, err := authnOf(req.GetSigv4(), req.GetConsoleSessionToken())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return s.getSessionToken(ctx, req, a)
}

func (s *Server) getSessionToken(ctx context.Context, req *iamv1.GetSessionTokenRequest, a authn) (*iamv1.GetSessionTokenResponse, error) {
	if a.console != "" {
		// As in AWS, GetSessionToken needs long-term credentials; an IAM
		// user's console session is not one. Only the root user may use a
		// console session here, and vws-iam has no root console login yet.
		return nil, toStatus(ctx, fmt.Errorf("%w: GetSessionToken with a console session is root-only", sts.ErrAccessDenied))
	}
	p, c, err := s.authenticatedCaller(ctx, a, "GetSessionToken")
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	ctx = stsAttempts(ctx, a, req.GetSerialNumber(), req.GetTokenCode())
	d := time.Duration(req.GetDurationSeconds()) * time.Second
	if d == 0 {
		d = defaultGetSessionToken
	}
	creds, err := p.sts.GetSessionToken(ctx, c, d, sts.MFA{SerialNumber: req.GetSerialNumber(), TokenCode: req.GetTokenCode()})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &iamv1.GetSessionTokenResponse{Credentials: credsProto(creds)}, nil
}
