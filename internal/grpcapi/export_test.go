package grpcapi

import (
	"context"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/sts"
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

// GetFederationToken is STS GetFederationToken, which vws-proto does not
// carry yet (#107).
func (s *Server) GetFederationToken(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console string, req sts.FederationRequest,
) (sts.FederationToken, error) {
	return s.getFederationToken(ctx, sigv4, console, req)
}

// AssumeRoleWithSAML is STS AssumeRoleWithSAML, which vws-proto does not
// carry yet (#106).
func (s *Server) AssumeRoleWithSAML(ctx context.Context, req sts.SAMLRequest) (sts.SAMLRoleSession, error) {
	return s.assumeRoleWithSAML(ctx, req)
}

// DeleteServiceLinkedRole is IAM DeleteServiceLinkedRole, which vws-proto
// does not carry yet (#104).
func (s *Server) DeleteServiceLinkedRole(ctx context.Context, project, roleName string) (string, error) {
	return s.deleteServiceLinkedRole(ctx, project, roleName)
}

// CreateServiceLinkedRole is IAM CreateServiceLinkedRole, which vws-proto
// does not carry yet (#103).
func (s *Server) CreateServiceLinkedRole(
	ctx context.Context, project string, req ServiceLinkedRoleRequest,
) (*iamv1.Role, error) {
	return s.createServiceLinkedRole(ctx, project, req)
}

// ResyncMfaDevice is IAM ResyncMFADevice, which vws-proto does not carry
// yet (#102).
func (s *Server) ResyncMfaDevice(ctx context.Context, project string, req ResyncMFADeviceRequest) error {
	return s.resyncMfaDevice(ctx, project, req)
}

// DeleteRolePermissionsBoundary is IAM DeleteRolePermissionsBoundary,
// which vws-proto does not carry yet (#101).
func (s *Server) DeleteRolePermissionsBoundary(ctx context.Context, project, roleName string) error {
	return s.deleteRolePermissionsBoundary(ctx, project, roleName)
}

// PutRolePermissionsBoundary is IAM PutRolePermissionsBoundary, which
// vws-proto does not carry yet (#100).
func (s *Server) PutRolePermissionsBoundary(ctx context.Context, project, roleName, boundaryARN string) error {
	return s.putRolePermissionsBoundary(ctx, project, roleName, boundaryARN)
}

// DeleteUserPermissionsBoundary is IAM DeleteUserPermissionsBoundary,
// which vws-proto does not carry yet (#99).
func (s *Server) DeleteUserPermissionsBoundary(ctx context.Context, project, userName string) error {
	return s.deleteUserPermissionsBoundary(ctx, project, userName)
}

// PutUserPermissionsBoundary is IAM PutUserPermissionsBoundary, which
// vws-proto does not carry yet (#98).
func (s *Server) PutUserPermissionsBoundary(ctx context.Context, project, userName, boundaryARN string) error {
	return s.putUserPermissionsBoundary(ctx, project, userName, boundaryARN)
}

// RemoveRoleFromInstanceProfile is IAM RemoveRoleFromInstanceProfile,
// which vws-proto does not carry yet (#97).
func (s *Server) RemoveRoleFromInstanceProfile(ctx context.Context, project, profileName, roleName string) error {
	return s.removeRoleFromInstanceProfile(ctx, project, profileName, roleName)
}

// AddRoleToInstanceProfile is IAM AddRoleToInstanceProfile, which
// vws-proto does not carry yet (#96).
func (s *Server) AddRoleToInstanceProfile(ctx context.Context, project, profileName, roleName string) error {
	return s.addRoleToInstanceProfile(ctx, project, profileName, roleName)
}

// InstanceProfilePage is one page of ListInstanceProfilesForRole.
type InstanceProfilePage = instanceProfilePage

// ListInstanceProfilesForRole is IAM ListInstanceProfilesForRole, which
// vws-proto does not carry yet (#95).
func (s *Server) ListInstanceProfilesForRole(
	ctx context.Context, project, roleName, marker string, maxItems int,
) (InstanceProfilePage, error) {
	return s.listInstanceProfilesForRole(ctx, project, roleName, marker, maxItems)
}

// InstanceProfileListing is one page of ListInstanceProfiles.
type InstanceProfileListing = instanceProfileListing

// ListInstanceProfiles is IAM ListInstanceProfiles, which vws-proto does
// not carry yet (#94).
func (s *Server) ListInstanceProfiles(
	ctx context.Context, project, pathPrefix, marker string, maxItems int,
) (InstanceProfileListing, error) {
	return s.listInstanceProfiles(ctx, project, pathPrefix, marker, maxItems)
}

// InstanceProfileView is the result of GetInstanceProfile.
type InstanceProfileView = instanceProfileView

// GetInstanceProfile is IAM GetInstanceProfile, which vws-proto does not
// carry yet (#93).
func (s *Server) GetInstanceProfile(ctx context.Context, project, profileName string) (InstanceProfileView, error) {
	return s.getInstanceProfile(ctx, project, profileName)
}

// DeleteInstanceProfile is IAM DeleteInstanceProfile, which vws-proto
// does not carry yet (#92).
func (s *Server) DeleteInstanceProfile(ctx context.Context, project, profileName string) error {
	return s.deleteInstanceProfile(ctx, project, profileName)
}

// CreateInstanceProfile is IAM CreateInstanceProfile, which vws-proto
// does not carry yet (#91).
func (s *Server) CreateInstanceProfile(ctx context.Context, project, profileName, path string) (InstanceProfileView, error) {
	return s.createInstanceProfile(ctx, project, profileName, path)
}
