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

// MfaDeviceARN is the ARN of a virtual MFA device in account. Its path is
// part of the serial number, as in AWS.
func MfaDeviceARN(account string, d MfaDevice) string {
	return ARN("iam", "", account, "mfa"+pathOf(d.Path)+d.Name)
}

// SplitMfaDeviceARN splits an MFA device ARN in account into the device
// name and path. The path is "/" at the root. ok is false when serial is
// not an MFA device ARN in account.
func SplitMfaDeviceARN(account, serial string) (name, path string, ok bool) {
	rest, ok := strings.CutPrefix(serial, ARN("iam", "", account, "mfa"))
	if !ok || !strings.HasPrefix(rest, "/") {
		return "", "", false
	}
	i := strings.LastIndexByte(rest, '/')
	name = rest[i+1:]
	if !ValidName(name) {
		return "", "", false
	}
	return name, rest[:i+1], true
}
