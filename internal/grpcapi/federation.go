package grpcapi

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/sts"
)

// getFederationToken is STS GetFederationToken: the caller is taken only
// from a SigV4 request signed for GetFederationToken (accepted once),
// and internal/sts checks that it is a long-term IAM user or root key
// allowed sts:GetFederationToken on the federated user, with the
// request's aws:SourceIp. A console session is not a long-term
// credential, so it is refused, as for GetSessionToken.
//
// TODO(#107): serve this as TokenService.GetFederationToken once
// vws-proto carries the RPC (popododo0720/vws-proto#86).
func (s *Server) getFederationToken(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console string, req sts.FederationRequest,
) (tok sts.FederationToken, err error) {
	defer func() {
		s.m.add(ctx, s.m.issued, attribute.String("rpc", "GetFederationToken"), attribute.String("result", result(err)))
	}()
	a, err := authnOf(sigv4, console)
	if err != nil {
		return sts.FederationToken{}, toStatus(ctx, err)
	}
	if a.console != "" {
		err = fmt.Errorf("%w: GetFederationToken needs long-term user credentials, not a console session",
			sts.ErrAccessDenied)
		return sts.FederationToken{}, toStatus(ctx, err)
	}
	p, c, ip, err := s.authenticatedCallerFrom(ctx, a, "GetFederationToken")
	if err != nil {
		return sts.FederationToken{}, toStatus(ctx, err)
	}
	tok, err = p.sts.GetFederationToken(ctx, c, sourceIPContext(ip), req)
	if err != nil {
		return sts.FederationToken{}, toStatus(ctx, err)
	}
	return tok, nil
}
