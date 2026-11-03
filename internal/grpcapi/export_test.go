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
func (s *Server) CreateInstanceProfile(
	ctx context.Context, project, profileName, path string,
) (InstanceProfileView, error) {
	return s.createInstanceProfile(ctx, project, profileName, path)
}

// AccountAliasPage is one page of ListAccountAliases.
type AccountAliasPage = accountAliasPage

// ListAccountAliases is IAM ListAccountAliases, which vws-proto does not
// carry yet (#90).
func (s *Server) ListAccountAliases(
	ctx context.Context, project, marker string, maxItems int,
) (AccountAliasPage, error) {
	return s.listAccountAliases(ctx, project, marker, maxItems)
}

// DeleteAccountAlias is IAM DeleteAccountAlias, which vws-proto does not
// carry yet (#89).
func (s *Server) DeleteAccountAlias(ctx context.Context, project, alias string) error {
	return s.deleteAccountAlias(ctx, project, alias)
}

// CreateAccountAlias is IAM CreateAccountAlias, which vws-proto does not
// carry yet (#88).
func (s *Server) CreateAccountAlias(ctx context.Context, project, alias string) error {
	return s.createAccountAlias(ctx, project, alias)
}

// DeleteAccountPasswordPolicy is IAM DeleteAccountPasswordPolicy, which
// vws-proto does not carry yet (#84).
func (s *Server) DeleteAccountPasswordPolicy(ctx context.Context, project string) error {
	return s.deleteAccountPasswordPolicy(ctx, project)
}

// SimulateInput, ContextEntry and SimulationPage are the
// SimulatePrincipalPolicy request and result types.
type (
	SimulateInput    = simulateInput
	ContextEntry     = contextEntry
	SimulationPage   = simulationPage
	EvaluationResult = evaluationResult
)

// SimulatePrincipalPolicy is IAM SimulatePrincipalPolicy, which vws-proto
// does not carry yet (#86).
func (s *Server) SimulatePrincipalPolicy(
	ctx context.Context, project string, in SimulateInput,
) (SimulationPage, error) {
	return s.simulatePrincipalPolicy(ctx, project, in)
}

// CustomSimulateInput is the SimulateCustomPolicy request.
type CustomSimulateInput = customSimulateInput

// SimulateCustomPolicy is IAM SimulateCustomPolicy, which vws-proto does
// not carry yet (#87).
func (s *Server) SimulateCustomPolicy(
	ctx context.Context, project string, in CustomSimulateInput,
) (SimulationPage, error) {
	return s.simulateCustomPolicy(ctx, project, in)
}

// EntitiesQuery is the request of ListEntitiesForPolicy.
type EntitiesQuery = entitiesQuery

// PolicyEntities is one page of ListEntitiesForPolicy.
type PolicyEntities = policyEntities

// ListEntitiesForPolicy is IAM ListEntitiesForPolicy, which vws-proto
// does not carry yet (#85).
func (s *Server) ListEntitiesForPolicy(ctx context.Context, project string, q EntitiesQuery) (PolicyEntities, error) {
	return s.listEntitiesForPolicy(ctx, project, q)
}

// PasswordPolicyInput is the UpdateAccountPasswordPolicy request.
type PasswordPolicyInput = passwordPolicyInput

// UpdateAccountPasswordPolicy is IAM UpdateAccountPasswordPolicy, which
// vws-proto does not carry yet (#83).
func (s *Server) UpdateAccountPasswordPolicy(ctx context.Context, project string, in PasswordPolicyInput) error {
	return s.updateAccountPasswordPolicy(ctx, project, in)
}

// AccountPasswordPolicy is the GetAccountPasswordPolicy response.
type AccountPasswordPolicy = accountPasswordPolicy

// GetAccountPasswordPolicy is IAM GetAccountPasswordPolicy, which
// vws-proto does not carry yet (#82).
func (s *Server) GetAccountPasswordPolicy(ctx context.Context, project string) (AccountPasswordPolicy, error) {
	return s.getAccountPasswordPolicy(ctx, project)
}

// AuthorizationDetails is one page of GetAccountAuthorizationDetails.
type AuthorizationDetails = authorizationDetails

// GetAccountAuthorizationDetails is IAM GetAccountAuthorizationDetails,
// which vws-proto does not carry yet (#81).
func (s *Server) GetAccountAuthorizationDetails(
	ctx context.Context, project string, filter []string, marker string, maxItems int,
) (AuthorizationDetails, error) {
	return s.getAccountAuthorizationDetails(ctx, project, filter, marker, maxItems)
}

// GetAccountSummary is IAM GetAccountSummary, which vws-proto does not
// carry yet (#80).
func (s *Server) GetAccountSummary(ctx context.Context, project string) (map[string]int, error) {
	return s.getAccountSummary(ctx, project)
}
