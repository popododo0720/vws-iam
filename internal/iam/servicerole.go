package iam

import "regexp"

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
