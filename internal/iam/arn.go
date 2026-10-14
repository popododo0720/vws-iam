package iam

import "strings"

// Partition is the ARN partition of every VWS resource.
const Partition = "vws"

// ARN builds arn:vws:<service>:<region>:<account>:<resource>.
func ARN(service, region, account, resource string) string {
	return strings.Join([]string{"arn", Partition, service, region, account, resource}, ":")
}

func pathOf(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// UserARN is the ARN of a user in account.
func UserARN(account string, u User) string {
	return ARN("iam", "", account, "user"+pathOf(u.Path)+u.Name)
}

// GroupARN is the ARN of a group in account.
func GroupARN(account string, g Group) string {
	return ARN("iam", "", account, "group"+pathOf(g.Path)+g.Name)
}

// RoleARN is the ARN of a role in account.
func RoleARN(account string, r Role) string {
	return ARN("iam", "", account, "role"+pathOf(r.Path)+r.Name)
}

// PolicyARN is the ARN of a managed policy in account.
func PolicyARN(account string, p Policy) string {
	return ARN("iam", "", account, "policy"+pathOf(p.Path)+p.Name)
}
