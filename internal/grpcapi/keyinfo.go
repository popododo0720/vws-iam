package grpcapi

import (
	"context"

	"go.opentelemetry.io/otel/attribute"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// getAccessKeyInfo is STS GetAccessKeyInfo: the caller is taken only from
// how it authenticated (a SigV4 request signed for GetAccessKeyInfo, or a
// console session), and internal/sts checks its sts:GetAccessKeyInfo
// permission before it looks the key up in the global key index. The key
// may belong to any project. The permission is evaluated with the
// aws:SourceIp of the current request: the address in the SigV4 request,
// or consoleIP, the address the gateway saw for this console request;
// with neither the key is absent.
//
// TODO(#108): serve this as TokenService.GetAccessKeyInfo once vws-proto
// carries the RPC (popododo0720/vws-proto#85); consoleIP then comes from
// the request's gateway-observed source IP field.
func (s *Server) getAccessKeyInfo(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console, consoleIP, accessKeyID string,
) (account string, err error) {
	defer func() {
		s.m.add(ctx, s.m.keyInfo, attribute.String("result", result(err)))
	}()
	a, err := authnOf(sigv4, console)
	if err != nil {
		return "", toStatus(ctx, err)
	}
	p, c, ip, err := s.authenticatedCallerFrom(ctx, a, "GetAccessKeyInfo")
	if err != nil {
		return "", toStatus(ctx, err)
	}
	if a.sigv4 == nil {
		ip = consoleIP
	}
	account, err = p.sts.GetAccessKeyInfo(ctx, c, sourceIPContext(ip), accessKeyID)
	return account, toStatus(ctx, err)
}
