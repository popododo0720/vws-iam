package grpcapi

import (
	"context"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/sts"
)

// AttemptCounterKeys are the store keys, one per KEK, of the attempt
// counter of scope (iam.AttemptUser, Key, IP) and id, for tests that seed
// a counter: a user's "project/name", an access key id, or a source IP as
// given.
func (s *Server) AttemptCounterKeys(scope, id string) []string {
	j := subject{scope, id}
	if ip, ok := ipSubject(id); ok && scope == ip.scope {
		j = ip
	}
	var keys []string
	for _, c := range s.counters(callers{j}) {
		keys = append(keys, c.key)
	}
	return keys
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

// AuthenticateRef is Authenticate that also returns the session reference
// of an STS session, which vws-proto's Principal does not carry yet (#20).
// It is "" for a long-term key.
func (s *Server) AuthenticateRef(
	ctx context.Context, req *iamv1.AuthenticateRequest,
) (*iamv1.AuthenticateResponse, string, error) {
	return s.authenticate(ctx, req, true)
}

// AuthorizeRef is Authorize with the session reference of the STS session
// behind the principal, which vws-proto does not carry yet (#20).
func (s *Server) AuthorizeRef(
	ctx context.Context, req *iamv1.AuthorizeRequest, ref string,
) (*iamv1.AuthorizeResponse, error) {
	return s.authorize(ctx, req, ref)
}

// AccessKeyInfo is STS GetAccessKeyInfo, which this server does not serve
// yet (#108).
func (s *Server) AccessKeyInfo(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console, consoleIP, accessKeyID string,
) (string, error) {
	return s.getAccessKeyInfo(ctx, sigv4, console, consoleIP, accessKeyID)
}

// FederationToken is STS GetFederationToken, which this server does not
// serve over gRPC yet (#107).
func (s *Server) FederationToken(
	ctx context.Context, sigv4 *iamv1.AuthenticateRequest, console string, req sts.FederationRequest,
) (sts.FederationToken, error) {
	return s.getFederationToken(ctx, sigv4, console, req)
}

// AssumeSAMLRole is STS AssumeRoleWithSAML, which this server does not
// serve over gRPC yet (#106).
func (s *Server) AssumeSAMLRole(ctx context.Context, req sts.SAMLRequest) (sts.SAMLRoleSession, error) {
	return s.assumeRoleWithSAML(ctx, req)
}

// DeleteLinkedRole is IAM DeleteServiceLinkedRole, which this server
// does not serve over gRPC yet (#104).
func (s *Server) DeleteLinkedRole(ctx context.Context, project, roleName string) (string, error) {
	return s.deleteServiceLinkedRole(ctx, project, roleName)
}

// CreateLinkedRole is IAM CreateServiceLinkedRole, which this server
// does not serve over gRPC yet (#103).
func (s *Server) CreateLinkedRole(
	ctx context.Context, project string, req ServiceLinkedRoleRequest,
) (*iamv1.Role, error) {
	return s.createServiceLinkedRole(ctx, project, req)
}

// ResyncMFADevice is IAM ResyncMFADevice, which this server does not
// serve over gRPC yet (#102).
func (s *Server) ResyncMFADevice(ctx context.Context, project string, req ResyncMFADeviceRequest) error {
	return s.resyncMfaDevice(ctx, project, req)
}

// DeleteRoleBoundary is IAM DeleteRolePermissionsBoundary, which this
// server does not serve over gRPC yet (#101).
func (s *Server) DeleteRoleBoundary(ctx context.Context, project, roleName string) error {
	return s.deleteRolePermissionsBoundary(ctx, project, roleName)
}

// PutRoleBoundary is IAM PutRolePermissionsBoundary, which this server
// does not serve over gRPC yet (#100).
func (s *Server) PutRoleBoundary(ctx context.Context, project, roleName, boundaryARN string) error {
	return s.putRolePermissionsBoundary(ctx, project, roleName, boundaryARN)
}

// DeleteUserBoundary is IAM DeleteUserPermissionsBoundary, which this
// server does not serve over gRPC yet (#99).
func (s *Server) DeleteUserBoundary(ctx context.Context, project, userName string) error {
	return s.deleteUserPermissionsBoundary(ctx, project, userName)
}

// PutUserBoundary is IAM PutUserPermissionsBoundary, which this server
// does not serve over gRPC yet (#98).
func (s *Server) PutUserBoundary(ctx context.Context, project, userName, boundaryARN string) error {
	return s.putUserPermissionsBoundary(ctx, project, userName, boundaryARN)
}

// RemoveProfileRole is IAM RemoveRoleFromInstanceProfile, which this
// server does not serve over gRPC yet (#97).
func (s *Server) RemoveProfileRole(ctx context.Context, project, profileName, roleName string) error {
	return s.removeRoleFromInstanceProfile(ctx, project, profileName, roleName)
}

// AddProfileRole is IAM AddRoleToInstanceProfile, which this server
// does not serve over gRPC yet (#96).
func (s *Server) AddProfileRole(ctx context.Context, project, profileName, roleName string) error {
	return s.addRoleToInstanceProfile(ctx, project, profileName, roleName)
}

// InstanceProfilePage is one page of ListInstanceProfilesForRole.
type InstanceProfilePage = instanceProfilePage

// ProfilesForRole is IAM ListInstanceProfilesForRole, which this server
// does not serve over gRPC yet (#95).
func (s *Server) ProfilesForRole(
	ctx context.Context, project, roleName, marker string, maxItems int,
) (InstanceProfilePage, error) {
	return s.listInstanceProfilesForRole(ctx, project, roleName, marker, maxItems)
}

// InstanceProfileListing is one page of ListInstanceProfiles.
type InstanceProfileListing = instanceProfileListing

// ListProfiles is IAM ListInstanceProfiles, which this server does not
// serve over gRPC yet (#94).
func (s *Server) ListProfiles(
	ctx context.Context, project, pathPrefix, marker string, maxItems int,
) (InstanceProfileListing, error) {
	return s.listInstanceProfiles(ctx, project, pathPrefix, marker, maxItems)
}

// InstanceProfileView is the result of GetInstanceProfile.
type InstanceProfileView = instanceProfileView

// GetProfile is the service layer of IAM GetInstanceProfile (#93), which
// InstanceProfileService.GetInstanceProfile serves.
func (s *Server) GetProfile(ctx context.Context, project, profileName string) (InstanceProfileView, error) {
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

// TagPage is one page of ListRoleTags, ListSAMLProviderTags or
// ListOpenIDConnectProviderTags.
type TagPage = tagPage

// AWSTag is one tag of a TagPage.
type AWSTag = awsTag

// ListRoleTags is IAM ListRoleTags, which vws-proto does not carry yet
// (#73).
func (s *Server) ListRoleTags(
	ctx context.Context, project, roleName, marker string, maxItems int,
) (TagPage, error) {
	return s.listRoleTags(ctx, project, roleName, marker, maxItems)
}

// SAMLProviderView is a SAML provider with its ARN.
type SAMLProviderView = samlProviderView

// CreateSAMLProvider is IAM CreateSAMLProvider, which vws-proto does not
// carry yet (#196).
func (s *Server) CreateSAMLProvider(
	ctx context.Context, project, name, document string, tags []*iamv1.Tag,
) (SAMLProviderView, error) {
	return s.createSAMLProvider(ctx, project, name, document, tags)
}

// SAMLProviderEntry is one provider of ListSAMLProviders.
type SAMLProviderEntry = samlProviderEntry

// GetSAMLProvider is IAM GetSAMLProvider, which vws-proto does not carry
// yet.
func (s *Server) GetSAMLProvider(ctx context.Context, project, arn string) (SAMLProviderView, error) {
	return s.getSAMLProvider(ctx, project, arn)
}

// ListSAMLProviders is IAM ListSAMLProviders, which vws-proto does not
// carry yet.
func (s *Server) ListSAMLProviders(ctx context.Context, project string) ([]SAMLProviderEntry, error) {
	return s.listSAMLProviders(ctx, project)
}

// UpdateSAMLProvider is IAM UpdateSAMLProvider, which vws-proto does not
// carry yet (#196).
func (s *Server) UpdateSAMLProvider(ctx context.Context, project, arn, document string) (string, error) {
	return s.updateSAMLProvider(ctx, project, arn, document)
}

// TagSAMLProvider is IAM TagSAMLProvider, which vws-proto does not carry
// yet (#196).
func (s *Server) TagSAMLProvider(ctx context.Context, project, arn string, tags []*iamv1.Tag) error {
	return s.tagSAMLProvider(ctx, project, arn, tags)
}

// UntagSAMLProvider is IAM UntagSAMLProvider, which vws-proto does not
// carry yet (#196).
func (s *Server) UntagSAMLProvider(ctx context.Context, project, arn string, keys []string) error {
	return s.untagSAMLProvider(ctx, project, arn, keys)
}

// ListSAMLProviderTags is IAM ListSAMLProviderTags, which vws-proto does
// not carry yet (#196).
func (s *Server) ListSAMLProviderTags(
	ctx context.Context, project, arn, marker string, maxItems int,
) (TagPage, error) {
	return s.listSAMLProviderTags(ctx, project, arn, marker, maxItems)
}

// DeleteSAMLProvider is IAM DeleteSAMLProvider, which vws-proto does not
// carry yet.
func (s *Server) DeleteSAMLProvider(ctx context.Context, project, arn string) error {
	return s.deleteSAMLProvider(ctx, project, arn)
}

// OIDCProviderView is an OpenID Connect provider with its ARN.
type OIDCProviderView = oidcProviderView

// CreateOpenIDConnectProvider is IAM CreateOpenIDConnectProvider, which
// vws-proto does not carry yet (#208).
func (s *Server) CreateOpenIDConnectProvider(
	ctx context.Context, project, url string, clientIDs, thumbprints []string, tags []*iamv1.Tag,
) (OIDCProviderView, error) {
	return s.createOIDCProvider(ctx, project, url, clientIDs, thumbprints, tags)
}

// GetOpenIDConnectProvider is IAM GetOpenIDConnectProvider, which
// vws-proto does not carry yet (#208).
func (s *Server) GetOpenIDConnectProvider(ctx context.Context, project, arn string) (OIDCProviderView, error) {
	return s.getOIDCProvider(ctx, project, arn)
}

// ListOpenIDConnectProviders is IAM ListOpenIDConnectProviders, which
// vws-proto does not carry yet (#208).
func (s *Server) ListOpenIDConnectProviders(ctx context.Context, project string) ([]string, error) {
	return s.listOIDCProviders(ctx, project)
}

// DeleteOpenIDConnectProvider is IAM DeleteOpenIDConnectProvider, which
// vws-proto does not carry yet (#208).
func (s *Server) DeleteOpenIDConnectProvider(ctx context.Context, project, arn string) error {
	return s.deleteOIDCProvider(ctx, project, arn)
}

// UpdateOpenIDConnectProviderThumbprint is IAM
// UpdateOpenIDConnectProviderThumbprint, which vws-proto does not carry
// yet (#208).
func (s *Server) UpdateOpenIDConnectProviderThumbprint(
	ctx context.Context, project, arn string, thumbprints []string,
) error {
	return s.updateOIDCProviderThumbprint(ctx, project, arn, thumbprints)
}

// AddClientIDToOpenIDConnectProvider is IAM AddClientIDToOpenIDConnectProvider,
// which vws-proto does not carry yet (#208).
func (s *Server) AddClientIDToOpenIDConnectProvider(ctx context.Context, project, arn, clientID string) error {
	return s.addClientIDToOIDCProvider(ctx, project, arn, clientID)
}

// RemoveClientIDFromOpenIDConnectProvider is IAM
// RemoveClientIDFromOpenIDConnectProvider, which vws-proto does not carry
// yet (#208).
func (s *Server) RemoveClientIDFromOpenIDConnectProvider(ctx context.Context, project, arn, clientID string) error {
	return s.removeClientIDFromOIDCProvider(ctx, project, arn, clientID)
}

// TagOpenIDConnectProvider is IAM TagOpenIDConnectProvider, which
// vws-proto does not carry yet (#208).
func (s *Server) TagOpenIDConnectProvider(ctx context.Context, project, arn string, tags []*iamv1.Tag) error {
	return s.tagOIDCProvider(ctx, project, arn, tags)
}

// UntagOpenIDConnectProvider is IAM UntagOpenIDConnectProvider, which
// vws-proto does not carry yet (#208).
func (s *Server) UntagOpenIDConnectProvider(ctx context.Context, project, arn string, keys []string) error {
	return s.untagOIDCProvider(ctx, project, arn, keys)
}

// ListOpenIDConnectProviderTags is IAM ListOpenIDConnectProviderTags,
// which vws-proto does not carry yet (#208).
func (s *Server) ListOpenIDConnectProviderTags(
	ctx context.Context, project, arn, marker string, maxItems int,
) (TagPage, error) {
	return s.listOIDCProviderTags(ctx, project, arn, marker, maxItems)
}
