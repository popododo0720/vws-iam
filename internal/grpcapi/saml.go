package grpcapi

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/otel/attribute"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// assumeRoleWithSAML is STS AssumeRoleWithSAML. It takes no caller
// credentials: the SAML response is the authentication, verified by
// internal/sts against the provider's certificates. The project is the
// account of RoleArn; a RoleArn that names no project of this service is
// AccessDenied, as an unknown role is. The request carries a bearer
// assertion and is never logged.
//
// TODO(#106): serve this as TokenService.AssumeRoleWithSAML once
// vws-proto carries the RPC (popododo0720/vws-proto#87), and wire
// WithSAML to the SAML provider store once vws-iam has one (#196).
func (s *Server) assumeRoleWithSAML(ctx context.Context, req sts.SAMLRequest) (out sts.SAMLRoleSession, err error) {
	defer func() {
		s.m.add(ctx, s.m.issued, attribute.String("rpc", "AssumeRoleWithSAML"), attribute.String("result", result(err)))
	}()
	if err := sts.ValidateSAMLRequest(req); err != nil {
		return sts.SAMLRoleSession{}, toStatus(ctx, err)
	}
	project, ok := roleARNProject(req.RoleARN)
	if !ok {
		err := fmt.Errorf("%w: not authorized to perform %s on %s", sts.ErrAccessDenied, sts.SAMLAction, req.RoleARN)
		return sts.SAMLRoleSession{}, toStatus(ctx, err)
	}
	out, err = s.project(project).sts.AssumeRoleWithSAML(ctx, req)
	if err != nil {
		return sts.SAMLRoleSession{}, toStatus(ctx, err)
	}
	return out, nil
}

// roleARNProject is the project (account) of a role ARN
// arn:vws:iam::<project>:role/....
func roleARNProject(arn string) (string, bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != iam.Partition || parts[2] != "iam" || parts[3] != "" ||
		!strings.HasPrefix(parts[5], "role/") || !iam.ValidProject(parts[4]) {
		return "", false
	}
	return parts[4], true
}
