package iam

import (
	"errors"
	"fmt"
	"regexp"
)

// ServiceRolePathPrefix is the path prefix of every service-linked role:
// a role linked to service S has the path /aws-service-role/S/, as in AWS.
// The prefix is an AWS wire string, like the aws: condition keys, so it
// keeps the AWS name.
const ServiceRolePathPrefix = "/aws-service-role/"

// servicePrincipalRE is a service principal such as ec2.vws.internal:
// lowercase DNS labels joined by dots.
var servicePrincipalRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// uidRE is a UID as NewUID makes it: a lowercase UUID.
var uidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidServicePrincipal reports whether s is a service principal name
// that can own a service-linked role.
func ValidServicePrincipal(s string) bool {
	return len(s) <= 253 && servicePrincipalRE.MatchString(s)
}

// ServiceRolePath is the path of a role linked to service.
func ServiceRolePath(service string) string {
	return ServiceRolePathPrefix + service + "/"
}

// ServiceLinked reports whether r is a service-linked role. Only
// CreateServiceLinkedRole (#103) sets LinkedService; a role created with
// CreateRole is never service-linked, whatever its path.
func (r Role) ServiceLinked() bool { return r.LinkedService != "" }

// DeletionTaskID is the AWS DeletionTaskId of the deletion of the
// service-linked role r: task/aws-service-role/<service>/<role>/<uuid>.
// The UUID is the role's UID, so every request to delete the same role
// gets the same id, on every replica and after a restart, and a role
// created again under the same name gets a new one.
func DeletionTaskID(r Role) string {
	return "task" + ServiceRolePath(r.LinkedService) + r.Name + "/" + r.UID
}

// checkServiceLinked validates the service-linked fields of a role.
func checkServiceLinked(r Role) error {
	if r.LinkedService == "" {
		return nil
	}
	if !ValidServicePrincipal(r.LinkedService) {
		return invalid("role %q linked service %q", r.Name, r.LinkedService)
	}
	if r.Path != ServiceRolePath(r.LinkedService) {
		return invalid("service-linked role %q path %q is not %q", r.Name, r.Path, ServiceRolePath(r.LinkedService))
	}
	if !uidRE.MatchString(r.UID) {
		return invalid("service-linked role %q has no uid", r.Name)
	}
	return nil
}

// ServiceRoleNamePrefix starts the name of every service-linked role, as
// in AWS: AWSServiceRoleFor<service role name>[_<custom suffix>]. Like
// ServiceRolePathPrefix it is an AWS wire string and keeps the AWS name.
const ServiceRoleNamePrefix = "AWSServiceRoleFor"

// LinkedService is a service that can own service-linked roles: its
// service principal (the AWS AWSServiceName), the part of the role name
// after ServiceRoleNamePrefix that the service picks, whether
// CreateServiceLinkedRole accepts a CustomSuffix for it, and the role
// description used when the request has none.
type LinkedService struct {
	Principal    string
	RoleName     string
	CustomSuffix bool
	Description  string
}

// Validate reports whether l can name a service-linked role.
func (l LinkedService) Validate() error {
	// AWSServiceName is at most 128 characters.
	if len(l.Principal) > 128 || !ValidServicePrincipal(l.Principal) {
		return invalid("linked service principal %q", l.Principal)
	}
	if l.RoleName == "" || !ValidName(ServiceRoleNamePrefix+l.RoleName) {
		return invalid("linked service %q role name %q", l.Principal, l.RoleName)
	}
	return nil
}

// ServiceLinkedRoleName is the name of the role of l with the custom
// suffix suffix (none when empty): AWSServiceRoleFor<RoleName>[_<suffix>].
// The caller checks that the result is a valid role name.
func (l LinkedService) ServiceLinkedRoleName(suffix string) string {
	if suffix == "" {
		return ServiceRoleNamePrefix + l.RoleName
	}
	return ServiceRoleNamePrefix + l.RoleName + "_" + suffix
}

// ServiceTrustPolicy is the trust policy of a role linked to service:
// only that service principal may assume it.
func ServiceTrustPolicy(service string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"` +
		service + `"},"Action":"sts:AssumeRole"}]}`
}

// ErrProtectedRole marks a mutation only the linked service can perform.
var ErrProtectedRole = errors.New("service-linked role is protected")

// CheckMutable protects a service-linked role's permissions and session controls.
// Description-only updates deliberately do not call it.
func (r Role) CheckMutable() error {
	if r.ServiceLinked() {
		return fmt.Errorf("role %q owned by %s: %w", r.Name, r.LinkedService, ErrProtectedRole)
	}
	return nil
}
