package grpcapi

import (
	"context"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// RevokeUserSessions refuses every GetSessionToken session the user got
// so far (sts.RevokeSessions). The time is stored on the user in the
// shared store, so every replica refuses those sessions at once.
//
// Authorization: like every UserService call, the caller is authorized
// by console-api with Authorize(iam:RevokeUserSessions, user ARN) before
// it calls here; this service has no caller of its own.
func (s *Server) RevokeUserSessions(ctx context.Context, req *iamv1.RevokeUserSessionsRequest) (*longrunningpb.Operation, error) {
	const method = "RevokeUserSessions"
	pid, id, err := child(req.GetName(), "users")
	if err != nil {
		return nil, err
	}
	if op, err := s.replay(ctx, pid, method, req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	p := s.project(pid)
	if err := p.sts.RevokeSessionsOnce(ctx, authz.User, id, req.GetRequestId()); err != nil {
		return nil, toStatus(ctx, err)
	}
	v, err := store.Get[iam.User](ctx, p.b, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp, err := s.userOne(ctx, p, v)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	op, err := s.done(ctx, opArgs{
		project: pid, method: method, requestID: req.GetRequestId(), req: req, resource: resp.GetName(),
		verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation, response: resp,
	})
	return op, toStatus(ctx, err)
}

// RevokeRoleSessions refuses every AssumeRole session of the role issued
// so far (sts.RevokeSessions). The time is stored on the role in the
// shared store, so every replica refuses those role sessions at once;
// later AssumeRole calls get new, valid sessions.
//
// Authorization: like every RoleService call, the caller is authorized
// by console-api with Authorize(iam:RevokeRoleSessions, role ARN) before
// it calls here; this service has no caller of its own.
func (s *Server) RevokeRoleSessions(ctx context.Context, req *iamv1.RevokeRoleSessionsRequest) (*longrunningpb.Operation, error) {
	const method = "RevokeRoleSessions"
	pid, id, err := child(req.GetName(), "roles")
	if err != nil {
		return nil, err
	}
	if op, err := s.replay(ctx, pid, method, req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	p := s.project(pid)
	if err := p.sts.RevokeSessionsOnce(ctx, authz.Role, id, req.GetRequestId()); err != nil {
		return nil, toStatus(ctx, err)
	}
	v, err := store.Get[iam.Role](ctx, p.b, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := p.roleProto(v)
	op, err := s.done(ctx, opArgs{
		project: pid, method: method, requestID: req.GetRequestId(), req: req, resource: resp.GetName(),
		verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation, response: resp,
	})
	return op, toStatus(ctx, err)
}
