package grpcapi

import (
	"context"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// AttemptCounterHash is the store key of the attempt counter of scope
// (iam.AttemptUser, Key, IP) and id, for tests that seed a counter: a
// user's "project/name", an access key id, or a source IP as given.
func AttemptCounterHash(scope, id string) string {
	if j, ok := ipSubject(id); ok && scope == j.scope {
		return j.hash()
	}
	return subject{scope, id}.hash()
}

// CreateAccessKeyUserEtag is CreateAccessKey with the user etag that
// vws-proto does not carry yet (#139).
func (s *Server) CreateAccessKeyUserEtag(
	ctx context.Context, req *iamv1.CreateAccessKeyRequest, userEtag string,
) (*iamv1.CreateAccessKeyResponse, error) {
	return s.createAccessKey(ctx, req, userEtag)
}

// DeleteAccessKeyUserEtag is DeleteAccessKey with the user etag that
// vws-proto does not carry yet (#139).
func (s *Server) DeleteAccessKeyUserEtag(
	ctx context.Context, req *iamv1.DeleteAccessKeyRequest, userEtag string,
) (*longrunningpb.Operation, error) {
	return s.deleteAccessKey(ctx, req, userEtag)
}

// UpdateUserRename is UpdateUser with the AWS NewUserName that vws-proto
// does not carry yet (#134).
func (s *Server) UpdateUserRename(
	ctx context.Context, req *iamv1.UpdateUserRequest, newName string,
) (*longrunningpb.Operation, error) {
	return s.updateUser(ctx, req, newName)
}

// UpdateGroupRename is UpdateGroup with the AWS NewGroupName that
// vws-proto does not carry yet (#134).
func (s *Server) UpdateGroupRename(
	ctx context.Context, req *iamv1.UpdateGroupRequest, newName string,
) (*longrunningpb.Operation, error) {
	return s.updateGroup(ctx, req, newName)
}

// AuthorizeEncoded is Authorize that also returns the encoded
// authorization message of a deny, which vws-proto does not carry yet
// (#109).
func (s *Server) AuthorizeEncoded(
	ctx context.Context, req *iamv1.AuthorizeRequest,
) (*iamv1.AuthorizeResponse, string, error) {
	return s.authorize(ctx, req, true)
}

// DecodeAuthorizationMessage is STS DecodeAuthorizationMessage, which
// vws-proto does not carry yet (#109).
func (s *Server) DecodeAuthorizationMessage(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console, encoded string,
) (string, error) {
	return s.decodeAuthorizationMessage(ctx, sigv4, console, "", encoded)
}

// GetAccessKeyInfo is STS GetAccessKeyInfo, which vws-proto does not
// carry yet (#108).
func (s *Server) GetAccessKeyInfo(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console, consoleIP, accessKeyID string,
) (string, error) {
	return s.getAccessKeyInfo(ctx, sigv4, console, consoleIP, accessKeyID)
}

// DecodeAuthorizationMessageFrom is DecodeAuthorizationMessage with the
// gateway-observed source IP of a console request, which vws-proto does
// not carry yet (#109).
func (s *Server) DecodeAuthorizationMessageFrom(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console, consoleIP, encoded string,
) (string, error) {
	return s.decodeAuthorizationMessage(ctx, sigv4, console, consoleIP, encoded)
}
