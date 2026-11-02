package grpcapi

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"

	"github.com/popododo0720/vws-iam/internal/sts"
)

// assumeRoleWithWebIdentity is STS AssumeRoleWithWebIdentity. It takes no
// caller credentials: the OIDC ID token is the authentication, verified by
// internal/sts against the provider's signing keys. The project is the
// account of RoleArn; a RoleArn that names no project of this service is
// AccessDenied, as an unknown role is. The request carries a bearer token
// and is never logged.
//
// TODO(#105): serve this as TokenService.AssumeRoleWithWebIdentity once
// vws-proto carries the RPC (popododo0720/vws-proto#105), and wire
// WithOIDC to the OIDC provider store once vws-iam has one (#208).
func (s *Server) assumeRoleWithWebIdentity(
	ctx context.Context, req sts.WebIdentityRequest,
) (out sts.WebIdentityRoleSession, err error) {
	defer func() {
		s.m.add(ctx, s.m.issued, attribute.String("rpc", "AssumeRoleWithWebIdentity"),
			attribute.String("result", result(err)))
	}()
	if err := sts.ValidateWebIdentityRequest(req); err != nil {
		return sts.WebIdentityRoleSession{}, toStatus(ctx, err)
	}
	project, ok := roleARNProject(req.RoleARN)
	if !ok {
		err := fmt.Errorf("%w: not authorized to perform %s on %s", sts.ErrAccessDenied, sts.WebIdentityAction, req.RoleARN)
		return sts.WebIdentityRoleSession{}, toStatus(ctx, err)
	}
	out, err = s.project(project).sts.AssumeRoleWithWebIdentity(ctx, req)
	if err != nil {
		return sts.WebIdentityRoleSession{}, toStatus(ctx, err)
	}
	return out, nil
}
