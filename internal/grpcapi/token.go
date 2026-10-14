package grpcapi

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
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
// exactly one of a console session token or a SigV4 request.
type authn struct {
	console string
	sigv4   *iamv1.AuthenticateRequest
}

// Metadata keys from which AssumeRole and GetSessionToken derive the
// caller (vws-proto#28). The request's caller field is never trusted.
const (
	// MetadataSessionToken carries a console session token from Login.
	MetadataSessionToken = "x-vws-session-token"
	// MetadataAuthenticate carries the caller's serialized
	// AuthenticateRequest (SigV4 canonical request and signature); the
	// server verifies it itself, so the gateway cannot vouch for anyone.
	MetadataAuthenticate = "x-vws-authenticate-bin"
)

func authnFromMetadata(ctx context.Context) (authn, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	tokens, signed := md.Get(MetadataSessionToken), md.Get(MetadataAuthenticate)
	switch {
	case len(tokens)+len(signed) != 1:
		return authn{}, missingAuthentication()
	case len(tokens) == 1:
		return authn{console: tokens[0]}, nil
	}
	req := &iamv1.AuthenticateRequest{}
	if err := proto.Unmarshal([]byte(signed[0]), req); err != nil {
		return authn{}, invalidCredentials("IncompleteSignature", "malformed "+MetadataAuthenticate)
	}
	return authn{sigv4: req}, nil
}

func missingAuthentication() error {
	return invalidCredentials("MissingAuthenticationToken", "the request must carry how the caller authenticated")
}

// authenticatedCaller verifies the caller's credential on the server and
// derives the STS caller from it (sts.Resolve or the stored console
// session). Nothing in the request body names the caller.
func (s *Server) authenticatedCaller(ctx context.Context, a authn) (project, sts.Caller, error) {
	switch {
	case a.sigv4 != nil:
		resp, err := s.authenticate(ctx, a.sigv4)
		if err != nil {
			return project{}, sts.Caller{}, err
		}
		p := s.project(resp.GetAccount())
		c, err := p.sts.Resolve(ctx, sts.Credential{AccessKeyID: a.sigv4.GetAccessKeyId(), SessionToken: a.sigv4.GetSessionToken()})
		return p, c, err
	case a.console != "":
		v, err := s.consoleSession(ctx, a.console)
		if err != nil {
			return project{}, sts.Caller{}, err
		}
		p := s.project(v.Project)
		c, err := p.sts.ConsoleCaller(ctx, v.UserName, v.MFA, v.AuthTime)
		return p, c, err
	}
	return project{}, sts.Caller{}, missingAuthentication()
}

// AssumeRole issues role credentials to the authenticated caller, of the
// same project, after the caller's permission, trust policy and MFA checks
// in internal/sts.
func (s *Server) AssumeRole(ctx context.Context, req *iamv1.AssumeRoleRequest) (resp *iamv1.AssumeRoleResponse, err error) {
	defer func() {
		s.m.add(ctx, s.m.issued, attribute.String("rpc", "AssumeRole"), attribute.String("result", result(err)))
	}()
	a, err := authnFromMetadata(ctx)
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
	p, c, err := s.authenticatedCaller(ctx, a)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
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
	a, err := authnFromMetadata(ctx)
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
	p, c, err := s.authenticatedCaller(ctx, a)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
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
