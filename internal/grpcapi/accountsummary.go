package grpcapi

import (
	"context"
	"maps"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

// accountSummaryQuotas are the SummaryMap quotas of AWS GetAccountSummary
// that VWS enforces, each from the constant that enforces it. Quotas VWS
// does not enforce are left out rather than reported (#268).
var accountSummaryQuotas = map[string]int{
	"AccessKeysPerUserQuota":        accesskey.MaxPerUser,
	"AttachedPoliciesPerGroupQuota": MaxAttachedPolicies,
	"AttachedPoliciesPerRoleQuota":  MaxAttachedPolicies,
	"AttachedPoliciesPerUserQuota":  MaxAttachedPolicies,
	"GroupPolicySizeQuota":          maxInlineGroup,
	"GroupsPerUserQuota":            iam.MaxGroupsPerUser,
	"PolicySizeQuota":               policy.MaxSize,
	"RolePolicySizeQuota":           maxInlineRole,
	"UserPolicySizeQuota":           maxInlineUser,
	"VersionsPerPolicyQuota":        iam.MaxPolicyVersions,
}

// getAccountSummary is IAM GetAccountSummary: the SummaryMap of project
// pid, entity usage and quotas, as the AWS string to integer map.
//
// Usage is counted from the store: Users and Groups (through
// store.Visible, so an in-flight rename counts once), Roles (service-linked
// ones included, as in AWS), Policies (customer managed), InstanceProfiles,
// MFADevices (virtual devices, assigned or not, and FIDO security keys
// still owned by their user), MFADevicesInUse (assigned virtual devices
// and those security keys) and AccountAccessKeysPresent (1 when the root
// user has an access key that is not pending, else 0). The quotas are
// accountSummaryQuotas. Keys VWS cannot compute honestly (unenforced
// account quotas, unmodeled entities, root MFA and password, the STS
// global endpoint token version, policy versions in use) are left out
// (#268); no count is invented.
//
// A bad project id is ValidationError before any store access; a
// canceled request reads nothing. Any store failure is ServiceFailure,
// the one fault AWS documents for this action. The call only reads.
// Authorization (iam:GetAccountSummary) is console-api's, as for the
// other IAM reads.
//
// TODO(#80): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#138).
func (s *Server) getAccountSummary(ctx context.Context, pid string) (map[string]int, error) {
	if !iam.ValidProject(pid) {
		return nil, invalidID("project " + quote(pid) + " is not a project id")
	}
	if err := ctx.Err(); err != nil {
		return nil, toStatus(ctx, err)
	}
	b := s.project(pid).b
	users, err := store.List[iam.User](ctx, b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	groups, err := store.List[iam.Group](ctx, b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	roles, err := store.List[iam.Role](ctx, b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	policies, err := store.List[iam.Policy](ctx, b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	profiles, err := store.List[iam.InstanceProfile](ctx, b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	virtual, err := store.List[iam.MfaDevice](ctx, b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	fido, err := store.List[iam.FidoDevice](ctx, b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	keys, err := store.List[iam.AccessKey](ctx, b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}

	out := make(map[string]int, len(accountSummaryQuotas)+8)
	maps.Copy(out, accountSummaryQuotas)
	out["Users"] = len(store.Visible(users))
	out["Groups"] = len(store.Visible(groups))
	out["Roles"] = len(roles)
	out["Policies"] = len(policies)
	out["InstanceProfiles"] = len(profiles)

	inUse := 0
	for _, d := range virtual {
		if d.Object.Enabled {
			inUse++
		}
	}
	// A security key is owned while the user stored under its user name
	// is the user it was registered to (as mfa.Service.ListFido decides).
	uids := make(map[string]string, len(users))
	for _, u := range users {
		uids[store.Fold(u.Object.Name)] = u.Object.UID
	}
	owned := 0
	for _, d := range fido {
		if uid := uids[store.Fold(d.Object.UserName)]; uid != "" && uid == d.Object.UserUID {
			owned++
		}
	}
	out["MFADevices"] = len(virtual) + owned
	out["MFADevicesInUse"] = inUse + owned

	out["AccountAccessKeysPresent"] = 0
	for _, k := range keys {
		if k.Object.Root && k.Object.Status != iam.KeyPending {
			out["AccountAccessKeysPresent"] = 1
			break
		}
	}
	return out, nil
}
