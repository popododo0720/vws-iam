package grpcapi

import (
	"context"

	"go.opentelemetry.io/otel/attribute"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// DecodeAuthorizationMessage is STS DecodeAuthorizationMessage: the
// caller is taken only from how it authenticated (a SigV4 request signed
// for DecodeAuthorizationMessage, or a console session), and internal/sts
// checks its sts:DecodeAuthorizationMessage permission before it opens the
// message. Neither the encoded nor the decoded message is logged or
// stored.
//
// The permission is evaluated with the aws:SourceIp of the current
// request: the address in the SigV4 request, or, for a console session,
// the request's source_ip, the address the gateway saw for this request.
// The address stored with the console session at Login is never used, so
// a session token reused from another address meets the Deny for that
// address. With no source_ip the key is absent, as AWS evaluates a missing
// key: IpAddress conditions do not match.
func (s *Server) DecodeAuthorizationMessage(
	ctx context.Context, req *iamv1.DecodeAuthorizationMessageRequest,
) (resp *iamv1.DecodeAuthorizationMessageResponse, err error) {
	defer func() {
		s.m.add(ctx, s.m.decoded, attribute.String("result", result(err)))
	}()
	a, err := authnOf(req.GetSigv4(), req.GetConsoleSessionToken())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	p, c, o, err := s.authenticatedCallerFrom(ctx, a, "DecodeAuthorizationMessage")
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	decoded, err := p.sts.DecodeAuthorizationMessage(ctx, c, o.requestContext(req.GetSourceIp()), req.GetEncodedMessage())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &iamv1.DecodeAuthorizationMessageResponse{DecodedMessage: decoded}, nil
}

// authorizationMessage encodes the deny decision of an Authorize call
// for DecodeAuthorizationMessage.
// The message names the rechecked principal and carries the context the
// decision evaluated, the keys authz.Authorize sets included.
func authorizationMessage(c checked, pr *iamv1.Principal, action string, deny denied) (string, error) {
	name := c.az.Name
	if c.az.Kind == authz.Root {
		name = "root"
	}
	who := sts.MessagePrincipal{ID: pr.GetUniqueId(), Name: name, ARN: pr.GetArn()}
	m := sts.NewAuthorizationMessage(who, action, deny.resource, deny.d)
	return c.project.sts.EncodeAuthorizationMessage(m)
}

// denied is the deny decision Authorize answered with, kept to encode it.
type denied struct {
	resource string
	d        policy.Decision
}
