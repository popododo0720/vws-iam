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
