package grpcapi

import (
	"context"
	"slices"
	"strings"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// The Filter values of AWS GetAccountAuthorizationDetails (the EntityType
// enum) are the EntityFilter values of ListEntitiesForPolicy.

// The kind prefixes of a GetAccountAuthorizationDetails listing key. They
// sort users, groups, roles, then policies, the order of the AWS response
// elements (UserDetailList, GroupDetailList, RoleDetailList, Policies).
const (
	detailKeyUser   = '1'
	detailKeyGroup  = '2'
	detailKeyRole   = '3'
	detailKeyPolicy = '4'
)

// userDetail is an AWS UserDetail: the stored user and the names, as
// stored, of the groups it is a member of, ordered by case-folded name.
type userDetail struct {
	User   iam.User
	Groups []string
}

// roleDetail is an AWS RoleDetail: the stored role and the instance
// profiles holding it, ordered by case-folded name.
type roleDetail struct {
	Role             iam.Role
	InstanceProfiles []iam.InstanceProfile
}

// policyDetail is an AWS ManagedPolicyDetail: the stored policy with
// every version, the number of users, groups and roles it is attached to
// (AttachmentCount) and the number of users and roles it is the
// permissions boundary of (PermissionsBoundaryUsageCount). A customer
// managed policy is always attachable (IsAttachable).
type policyDetail struct {
	Policy             iam.Policy
	AttachmentCount    int
	BoundaryUsageCount int
}

// authorizationDetails is one page of GetAccountAuthorizationDetails.
// ProfileRoles holds, by case-folded name, the stored roles the listed
// instance profiles name, so a caller can render each profile's Roles; a
// name with no stored role is absent. When IsTruncated is set, Marker
// continues the listing.
type authorizationDetails struct {
	Users        []userDetail
	Groups       []iam.Group
	Roles        []roleDetail
	Policies     []policyDetail
	ProfileRoles map[string]iam.Role
	IsTruncated  bool
	Marker       string
}

// detailEntry is one entry of a GetAccountAuthorizationDetails listing;
// key orders the listing and is what a marker carries.
type detailEntry struct {
	key    string
	user   *userDetail
	group  *iam.Group
	role   *roleDetail
	policy *policyDetail
}

// getAccountAuthorizationDetails is IAM GetAccountAuthorizationDetails:
// the users, groups, roles and customer managed policies of project pid
// with their relationships, in pages. filter selects the entity types
// (none selects all of them; duplicates are allowed).
//
// A bad project id, a filter value outside User, Role, Group,
// LocalManagedPolicy, AWSManagedPolicy (case sensitive), a maxItems
// outside 1 to 1000 (0 means not set: the AWS default of 100) or a
// marker character outside [\u0020-\u00FF] is ValidationError; a marker
// this call did not return is InvalidInput. All before any store access.
// VWS has no AWS managed policies (#260), so AWSManagedPolicy selects
// nothing. Any other failure is ServiceFailure, the one fault AWS
// documents for this action.
//
// A user has its inline policies, attached policy ARNs, permissions
// boundary and the groups it is a member of; a group its inline and
// attached policies; a role its trust policy, inline and attached
// policies, permissions boundary and the instance profiles holding it; a
// policy every version and its attachment and boundary usage counts.
// Users and groups in a rename are listed once (store.Visible). Tags and
// RoleLastUsed are not modeled yet (#68, #71, #265).
//
// The listing is ordered users, groups, roles, then policies, each by
// case-folded name, so a marker (the last entry of the previous page)
// continues after that entry even when entities change in between. The
// call only reads. Authorization (iam:GetAccountAuthorizationDetails) is
// console-api's, as for the other IAM reads.
//
// TODO(#81): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#137).
func (s *Server) getAccountAuthorizationDetails(
	ctx context.Context, pid string, filter []string, marker string, maxItems int,
) (authorizationDetails, error) {
	if !iam.ValidProject(pid) {
		return authorizationDetails{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	kinds, err := detailKinds(filter)
	if err != nil {
		return authorizationDetails{}, err
	}
	maxItems, err = listPageSize(maxItems)
	if err != nil {
		return authorizationDetails{}, err
	}
	after, err := decodeNameMarker(marker, validDetailKey)
	if err != nil {
		return authorizationDetails{}, err
	}
	p := s.project(pid)
	// Groups are read for user memberships, users and roles for policy
	// counts, and profiles (and roles) for role details.
	needUsers := kinds[detailKeyUser] || kinds[detailKeyPolicy]
	needGroups := needUsers || kinds[detailKeyGroup]
	needRoles := kinds[detailKeyRole] || kinds[detailKeyPolicy]
	var (
		users    []store.Versioned[iam.User]
		groups   []store.Versioned[iam.Group]
		roles    []store.Versioned[iam.Role]
		profiles []store.Versioned[iam.InstanceProfile]
		policies []store.Versioned[iam.Policy]
	)
	if needUsers {
		if users, err = store.List[iam.User](ctx, p.b); err != nil {
			return authorizationDetails{}, readFailure(ctx, err)
		}
		users = store.Visible(users)
	}
	if needGroups {
		if groups, err = store.List[iam.Group](ctx, p.b); err != nil {
			return authorizationDetails{}, readFailure(ctx, err)
		}
		groups = store.Visible(groups)
	}
	if needRoles {
		if roles, err = store.List[iam.Role](ctx, p.b); err != nil {
			return authorizationDetails{}, readFailure(ctx, err)
		}
	}
	if kinds[detailKeyRole] {
		if profiles, err = store.List[iam.InstanceProfile](ctx, p.b); err != nil {
			return authorizationDetails{}, readFailure(ctx, err)
		}
	}
	if kinds[detailKeyPolicy] {
		if policies, err = store.List[iam.Policy](ctx, p.b); err != nil {
			return authorizationDetails{}, readFailure(ctx, err)
		}
	}

	var match []detailEntry
	add := func(kind byte, name string, e detailEntry) {
		e.key = string(kind) + ":" + store.Fold(name)
		if after == "" || e.key > after {
			match = append(match, e)
		}
	}
	if kinds[detailKeyUser] {
		for _, u := range users {
			d, name := userDetail{User: u.Object}, store.Fold(u.Object.Name)
			for _, g := range groups {
				if slices.ContainsFunc(g.Object.Members, func(m string) bool { return store.Fold(m) == name }) {
					d.Groups = append(d.Groups, g.Object.Name)
				}
			}
			slices.SortFunc(d.Groups, func(a, b string) int { return strings.Compare(store.Fold(a), store.Fold(b)) })
			add(detailKeyUser, u.Object.Name, detailEntry{user: &d})
		}
	}
	if kinds[detailKeyGroup] {
		for _, g := range groups {
			add(detailKeyGroup, g.Object.Name, detailEntry{group: &g.Object})
		}
	}
	if kinds[detailKeyRole] {
		for _, r := range roles {
			d, name := roleDetail{Role: r.Object}, store.Fold(r.Object.Name)
			for _, ip := range profiles {
				if slices.ContainsFunc(ip.Object.Roles, func(n string) bool { return store.Fold(n) == name }) {
					d.InstanceProfiles = append(d.InstanceProfiles, ip.Object)
				}
			}
			slices.SortFunc(d.InstanceProfiles, func(a, b iam.InstanceProfile) int {
				return strings.Compare(store.Fold(a.Name), store.Fold(b.Name))
			})
			add(detailKeyRole, r.Object.Name, detailEntry{role: &d})
		}
	}
	if kinds[detailKeyPolicy] {
		for _, pol := range policies {
			d := policyDetail{Policy: pol.Object}
			arn := iam.PolicyARN(pid, pol.Object)
			for _, u := range users {
				d.AttachmentCount += holdsOnce(u.Object.AttachedPolicies, arn)
				d.BoundaryUsageCount += holdsOnce([]string{u.Object.PermissionsBoundary}, arn)
			}
			for _, g := range groups {
				d.AttachmentCount += holdsOnce(g.Object.AttachedPolicies, arn)
			}
			for _, r := range roles {
				d.AttachmentCount += holdsOnce(r.Object.AttachedPolicies, arn)
				d.BoundaryUsageCount += holdsOnce([]string{r.Object.PermissionsBoundary}, arn)
			}
			add(detailKeyPolicy, pol.Object.Name, detailEntry{policy: &d})
		}
	}
	return pageDetails(match, maxItems, roles), nil
}

// holdsOnce returns 1 when arns holds arn, else 0: an entity counts once.
func holdsOnce(arns []string, arn string) int {
	if slices.Contains(arns, arn) {
		return 1
	}
	return 0
}

// detailKinds returns the kinds (by key prefix) that the Filter values f
// select; none selects users, groups, roles and customer managed
// policies. AWSManagedPolicy selects nothing (#260). Any other value is
// ValidationError, as for an AWS enum.
func detailKinds(f []string) (map[byte]bool, error) {
	if len(f) == 0 {
		return map[byte]bool{detailKeyUser: true, detailKeyGroup: true, detailKeyRole: true, detailKeyPolicy: true}, nil
	}
	out := map[byte]bool{}
	for _, v := range f {
		switch v {
		case EntityFilterUser:
			out[detailKeyUser] = true
		case EntityFilterGroup:
			out[detailKeyGroup] = true
		case EntityFilterRole:
			out[detailKeyRole] = true
		case EntityFilterLocalManagedPolicy:
			out[detailKeyPolicy] = true
		case EntityFilterAWSManagedPolicy:
		default:
			return nil, invalidSpec("filter must be a list of User, Role, Group, LocalManagedPolicy, AWSManagedPolicy")
		}
	}
	return out, nil
}

// validDetailKey reports whether k is a listing key this call issues: a
// kind prefix, a colon, and a valid name of that kind.
func validDetailKey(k string) bool {
	kind, name, ok := strings.Cut(k, ":")
	if !ok || len(kind) != 1 {
		return false
	}
	switch kind[0] {
	case detailKeyUser, detailKeyRole:
		return iam.ValidName(name)
	case detailKeyGroup:
		return iam.ValidGroupName(name)
	case detailKeyPolicy:
		return iam.ValidPolicyName(name)
	}
	return false
}

// pageDetails orders es by key and returns the first n, split by kind,
// with the roles the listed instance profiles name. When more remain, the
// page is truncated and its marker continues after the last one returned
// (see pageByFoldedName).
func pageDetails(es []detailEntry, n int, roles []store.Versioned[iam.Role]) authorizationDetails {
	es, truncated, marker := pageByFoldedName(es, func(e detailEntry) string { return e.key }, n)
	out := authorizationDetails{IsTruncated: truncated, Marker: marker, ProfileRoles: map[string]iam.Role{}}
	want := map[string]bool{}
	for _, e := range es {
		switch {
		case e.user != nil:
			out.Users = append(out.Users, *e.user)
		case e.group != nil:
			out.Groups = append(out.Groups, *e.group)
		case e.role != nil:
			out.Roles = append(out.Roles, *e.role)
			for _, ip := range e.role.InstanceProfiles {
				for _, r := range ip.Roles {
					want[store.Fold(r)] = true
				}
			}
		default:
			out.Policies = append(out.Policies, *e.policy)
		}
	}
	for _, r := range roles {
		if k := store.Fold(r.Object.Name); want[k] {
			out.ProfileRoles[k] = r.Object
		}
	}
	return out
}
