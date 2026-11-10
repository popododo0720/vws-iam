package policy

import (
	"slices"
	"strings"
)

// adminActions are the actions of the VWS admin API (regions, AWS
// accounts, project mappings). Nothing allows them but a policy that names
// them, vws:Admin*, vws:* or *.
var adminActions = []string{
	"vws:AdminListRegions",
	"vws:AdminRegisterRegion",
	"vws:AdminUpdateRegion",
	"vws:AdminRemoveRegion",
	"vws:AdminTestConnection",
	"vws:AdminRegisterAwsAccount",
	"vws:AdminUpdateAwsAccount",
	"vws:AdminRemoveAwsAccount",
	"vws:AdminMapProject",
}

// VWSAdministratorAccess is the managed policy granting every vws:Admin*
// action. Nothing attaches it by default.
const (
	VWSAdministratorAccess         = "VWSAdministratorAccess"
	VWSAdministratorAccessARN      = "arn:vws:iam::aws:policy/" + VWSAdministratorAccess
	VWSAdministratorAccessDocument = `{"Version":"2012-10-17",` +
		`"Statement":[{"Effect":"Allow","Action":"vws:Admin*","Resource":"*"}]}`
)

// unknownAdminAction reports whether a names an action of the vws:Admin
// namespace that the admin API does not have. A pattern with a wildcard is
// not checked: as in AWS, it may match no action.
func unknownAdminAction(a string) bool {
	svc, name, _ := strings.Cut(a, ":")
	admin := len(name) >= len("Admin") && strings.EqualFold(name[:len("Admin")], "Admin")
	if !strings.EqualFold(svc, "vws") || !admin || strings.ContainsAny(name, "*?") {
		return false
	}
	return !slices.ContainsFunc(adminActions, func(k string) bool { return strings.EqualFold(k, a) })
}
