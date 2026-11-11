package grpcapi

import (
	"context"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// RPCs vws-proto carries that this server does not serve yet. Each answers
// UNIMPLEMENTED, as before vws-proto had it, and changes nothing.

// PutRolePermissionsBoundary is not served yet.
//
// TODO(#100): serve it through putRolePermissionsBoundary.
func (s *Server) PutRolePermissionsBoundary(
	context.Context, *iamv1.PutRolePermissionsBoundaryRequest,
) (*iamv1.PutRolePermissionsBoundaryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "PutRolePermissionsBoundary is not served yet")
}

// ResyncMfaDevice is not served yet.
//
// TODO(#102): serve it through resyncMfaDevice.
func (s *Server) ResyncMfaDevice(
	context.Context, *iamv1.ResyncMfaDeviceRequest,
) (*iamv1.ResyncMfaDeviceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ResyncMfaDevice is not served yet")
}

// GetAccessKeyInfo is not served yet.
//
// TODO(#108): serve it through getAccessKeyInfo, with the request's
// source_ip as the console-path address.
func (s *Server) GetAccessKeyInfo(
	context.Context, *iamv1.GetAccessKeyInfoRequest,
) (*iamv1.GetAccessKeyInfoResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetAccessKeyInfo is not served yet")
}

// DeleteUserPermissionsBoundary is not served yet.
//
// TODO(#99): serve it through deleteUserPermissionsBoundary.
func (s *Server) DeleteUserPermissionsBoundary(
	context.Context, *iamv1.DeleteUserPermissionsBoundaryRequest,
) (*iamv1.DeleteUserPermissionsBoundaryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "DeleteUserPermissionsBoundary is not served yet")
}

// PutUserPermissionsBoundary is not served yet.
//
// TODO(#98): serve it through putUserPermissionsBoundary.
func (s *Server) PutUserPermissionsBoundary(
	context.Context, *iamv1.PutUserPermissionsBoundaryRequest,
) (*iamv1.PutUserPermissionsBoundaryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "PutUserPermissionsBoundary is not served yet")
}

// DeleteRolePermissionsBoundary is not served yet.
//
// TODO(#101): serve it through deleteRolePermissionsBoundary.
func (s *Server) DeleteRolePermissionsBoundary(
	context.Context, *iamv1.DeleteRolePermissionsBoundaryRequest,
) (*iamv1.DeleteRolePermissionsBoundaryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "DeleteRolePermissionsBoundary is not served yet")
}

// CreateServiceLinkedRole is not served yet.
//
// TODO(#103): serve it through createServiceLinkedRole.
func (s *Server) CreateServiceLinkedRole(
	context.Context, *iamv1.CreateServiceLinkedRoleRequest,
) (*iamv1.CreateServiceLinkedRoleResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CreateServiceLinkedRole is not served yet")
}

// DeleteServiceLinkedRole is not served yet.
//
// TODO(#104): serve it through deleteServiceLinkedRole.
func (s *Server) DeleteServiceLinkedRole(
	context.Context, *iamv1.DeleteServiceLinkedRoleRequest,
) (*iamv1.DeleteServiceLinkedRoleResponse, error) {
	return nil, status.Error(codes.Unimplemented, "DeleteServiceLinkedRole is not served yet")
}

// AssumeRoleWithSAML is not served yet.
//
// TODO(#106): serve it through assumeRoleWithSAML.
func (s *Server) AssumeRoleWithSAML(
	context.Context, *iamv1.AssumeRoleWithSAMLRequest,
) (*iamv1.AssumeRoleWithSAMLResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AssumeRoleWithSAML is not served yet")
}

// GetFederationToken is not served yet.
//
// TODO(#107): serve it through getFederationToken.
func (s *Server) GetFederationToken(
	context.Context, *iamv1.GetFederationTokenRequest,
) (*iamv1.GetFederationTokenResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetFederationToken is not served yet")
}

// AssumeRoleWithWebIdentity is not served yet.
//
// TODO(#105): serve it once the service layer exists.
func (s *Server) AssumeRoleWithWebIdentity(
	context.Context, *iamv1.AssumeRoleWithWebIdentityRequest,
) (*iamv1.AssumeRoleWithWebIdentityResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AssumeRoleWithWebIdentity is not served yet")
}

// AddRoleToInstanceProfile is not served yet.
//
// TODO(#96): serve it through addRoleToInstanceProfile.
func (s *Server) AddRoleToInstanceProfile(
	context.Context, *iamv1.AddRoleToInstanceProfileRequest,
) (*iamv1.AddRoleToInstanceProfileResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AddRoleToInstanceProfile is not served yet")
}

// unservedField answers UNIMPLEMENTED for a request field vws-proto
// carries that this server does not honor yet, so the request is refused
// before any write and never served as if the field were unset.
func unservedField(field string) error {
	return status.Error(codes.Unimplemented, field+" is not served yet")
}

// TODO(#73): serve ListRoleTags through listRoleTags.
func (s *Server) ListRoleTags(
	context.Context, *iamv1.ListRoleTagsRequest,
) (*iamv1.ListRoleTagsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListRoleTags is not served yet")
}

// TODO(#85): serve ListEntitiesForPolicy through listEntitiesForPolicy.
func (s *Server) ListEntitiesForPolicy(
	context.Context, *iamv1.ListEntitiesForPolicyRequest,
) (*iamv1.ListEntitiesForPolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ListEntitiesForPolicy is not served yet")
}

// TODO(#92): serve DeleteInstanceProfile through deleteInstanceProfile.
func (s *Server) DeleteInstanceProfile(
	context.Context, *iamv1.DeleteInstanceProfileRequest,
) (*iamv1.DeleteInstanceProfileResponse, error) {
	return nil, status.Error(codes.Unimplemented, "DeleteInstanceProfile is not served yet")
}

func (s *Server) TagRole(context.Context, *iamv1.TagRoleRequest) (*longrunningpb.Operation, error) {
	return nil, status.Error(codes.Unimplemented, "TagRole is not served yet")
}

func (s *Server) UntagRole(context.Context, *iamv1.UntagRoleRequest) (*longrunningpb.Operation, error) {
	return nil, status.Error(codes.Unimplemented, "UntagRole is not served yet")
}

// TODO(#86): serve SimulatePrincipalPolicy through simulatePrincipalPolicy.
func (s *Server) SimulatePrincipalPolicy(
	context.Context, *iamv1.SimulatePrincipalPolicyRequest,
) (*iamv1.SimulatePrincipalPolicyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "SimulatePrincipalPolicy is not served yet")
}
