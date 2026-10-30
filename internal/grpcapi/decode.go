package grpcapi

import (
	"context"

	"go.opentelemetry.io/otel/attribute"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// decodeAuthorizationMessage is STS DecodeAuthorizationMessage: the
// caller is taken only from how it authenticated (a SigV4 request signed
// for DecodeAuthorizationMessage, or a console session), and internal/sts
// checks its sts:DecodeAuthorizationMessage permission before it opens the
// message. Neither the encoded nor the decoded message is logged or
// stored.
//
// The permission is evaluated with the aws:SourceIp of the current
// request: the address in the SigV4 request, or consoleIP, the address
// the gateway saw for this console request. The address stored with the
// console session at Login is never used, so a session token reused from
// another address meets the Deny for that address. With no consoleIP the
// key is absent, as AWS evaluates a missing key: IpAddress conditions do
// not match.
//
// TODO(#109): serve this as TokenService.DecodeAuthorizationMessage once
// vws-proto carries the RPC (popododo0720/vws-proto#84); consoleIP then
// comes from the request's gateway-observed source IP field.
func (s *Server) decodeAuthorizationMessage(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console, consoleIP, encoded string,
) (decoded string, err error) {
	defer func() {
		s.m.add(ctx, s.m.decoded, attribute.String("result", result(err)))
	}()
	a, err := authnOf(sigv4, console)
	if err != nil {
		return "", toStatus(ctx, err)
	}
	p, c, ip, err := s.authenticatedCallerFrom(ctx, a, "DecodeAuthorizationMessage")
	if err != nil {
		return "", toStatus(ctx, err)
	}
	if a.sigv4 == nil {
		ip = consoleIP
	}
	decoded, err = p.sts.DecodeAuthorizationMessage(ctx, c, sourceIPContext(ip), encoded)
	return decoded, toStatus(ctx, err)
}

// sourceIPContext is the trusted request context of an STS call: the
// caller's aws:SourceIp, so an IP-conditioned Deny applies. With no
// recorded address the key is absent, and IpAddress conditions do not
// match (AWS semantics for a missing key).
func sourceIPContext(ip string) map[string][]string {
	if ip == "" {
		return nil
	}
	return map[string][]string{"aws:SourceIp": {ip}}
}

// authorizationMessage encodes the deny decision of an Authorize call
// for DecodeAuthorizationMessage.
// The message names the rechecked principal and carries the evaluated
// context, server keys included.
func authorizationMessage(c checked, pr *iamv1.Principal, action string, deny denied) (string, error) {
	name := c.az.Name
	if c.az.Kind == authz.Root {
		name = "root"
	}
	who := sts.MessagePrincipal{ID: pr.GetUniqueId(), Name: name, ARN: pr.GetArn()}
	m := sts.NewAuthorizationMessage(who, action, deny.resource, deny.d, deny.ctx)
	return c.project.sts.EncodeAuthorizationMessage(m)
}

// denied is the deny decision Authorize answered with, kept to encode it.
type denied struct {
	resource string
	d        policy.Decision
	ctx      map[string][]string
}
