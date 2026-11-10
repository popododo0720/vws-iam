package sts

import (
	"fmt"
	"regexp"
)

// assumeRoleSourceIdentityRE is the AWS AssumeRole SourceIdentity
// parameter: 2 to 64 characters of [\w+=,.@-], so never the reserved
// "aws:" prefix. A SAML assertion may set up to 256 (sourceIdentityRE).
var assumeRoleSourceIdentityRE = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

// SourceIdentity is the AWS AssumeRole SourceIdentity parameter (#359).
// The role session keeps it, as does every session chained from it; the
// caller's permissions and the role's trust policy must then allow
// sts:SetSourceIdentity. Empty (the default) sets none. Only AssumeRole
// takes it: the other calls answer ValidationError.
func SourceIdentity(id string) IssueOption {
	return func(o *issueOptions) { o.sourceIdentity = id }
}

// chainSourceIdentity is the source identity of a role session assumed by
// a caller whose session has inherited (empty for none) with the
// SourceIdentity parameter param (empty for none). As in AWS, a set value
// cannot be changed during the role session, so a different param is
// AccessDenied (IAM User Guide, Monitor and control actions taken with
// assumed roles).
func chainSourceIdentity(inherited, param string) (string, error) {
	switch {
	case param == "" || param == inherited:
		return inherited, nil
	case inherited == "":
		return param, nil
	}
	return "", fmt.Errorf("%w: the source identity of a role session cannot be changed", ErrAccessDenied)
}
