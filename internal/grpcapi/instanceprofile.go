package grpcapi

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// removeRoleFromInstanceProfile is IAM RemoveRoleFromInstanceProfile: it
// removes role roleName from instance profile profileName in project pid.
// The profile and the role stay.
//
// A bad project id, an InstanceProfileName outside 1 to 128 or a RoleName
// outside 1 to 64 characters of [\w+=,.@-] is ValidationError before any
// store access. An unknown instance profile is NoSuchEntity. An unknown
// role is NoSuchEntity unless the profile still names it (a role deleted
// while in the profile, which DeleteRole does not refuse yet, #234): then
// the stale name is removed, so the profile can be emptied. A
// service-linked role is UnmodifiableEntity, as AWS protects it. A role
// that is not in the profile is NoSuchEntity, as in AWS, so a retry after
// a lost response is NoSuchEntity and the profile stays without the role.
// Role names compare case-insensitively, like every IAM name. The write
// is conditional on the version read, so a profile changed in between is
// read again, never written from a stale copy; a request that was
// canceled or whose deadline passed is not written. Removing a role
// raises no quota, so LimitExceeded cannot occur.
// Authorization (iam:RemoveRoleFromInstanceProfile) is console-api's, as
// for UpdateRole.
//
// TODO(#97): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#118).
func (s *Server) removeRoleFromInstanceProfile(ctx context.Context, pid, profileName, roleName string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidInstanceProfileName(profileName) {
		return invalidSpec("instanceProfileName must be 1 to 128 characters of [\\w+=,.@-]")
	}
	if !iam.ValidName(roleName) {
		return invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	p := s.project(pid)
	noProfile := notFound("Instance Profile " + profileName + " cannot be found.")
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.InstanceProfile](ctx, p.b, profileName)
		if errors.Is(err, store.ErrNotFound) {
			return noProfile
		}
		if err != nil {
			return toStatus(ctx, err)
		}
		ip := cur.Object
		at := slices.IndexFunc(ip.Roles, func(r string) bool { return store.Fold(r) == store.Fold(roleName) })
		r, err := store.Get[iam.Role](ctx, p.b, roleName)
		switch {
		case errors.Is(err, store.ErrNotFound) && at < 0:
			return notFound("The role with name " + roleName + " cannot be found.")
		case errors.Is(err, store.ErrNotFound):
			// A stale name of a deleted role: remove it.
		case err != nil:
			return toStatus(ctx, err)
		case r.Object.ServiceLinked():
			return unmodifiable("Cannot perform the operation on the protected role '" + r.Object.Name +
				"' - this role is only modifiable by its linked service")
		}
		if at < 0 {
			return notFound("The role with name " + roleName + " cannot be found in instance profile " +
				ip.Name + ".")
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; write nothing
		}
		ip.Roles = slices.Delete(ip.Roles, at, at+1)
		if len(ip.Roles) == 0 {
			ip.Roles = nil
		}
		ip.Generation++
		ip.Updated = s.now().UTC()
		_, err = store.Update(ctx, p.b, ip, cur.Version)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		case errors.Is(err, store.ErrNotFound):
			return noProfile
		default:
			return toStatus(ctx, err)
		}
	}
}

// addRoleToInstanceProfile is IAM AddRoleToInstanceProfile: it adds role
// roleName to instance profile profileName in project pid, under the
// role's name as stored.
//
// A bad project id, an InstanceProfileName outside 1 to 128 or a RoleName
// outside 1 to 64 characters of [\w+=,.@-] is ValidationError before any
// store access. An unknown instance profile or role is NoSuchEntity. A
// service-linked role is UnmodifiableEntity, as AWS protects it. A profile
// that already holds a role, this one included, is LimitExceeded: an
// instance profile holds at most one role (iam.MaxInstanceProfileRoles, a
// fixed AWS quota), so a retry after a lost response is LimitExceeded and
// the profile keeps the one role, as in AWS. AWS also lists
// EntityAlreadyExists, but the quota check comes first, so it cannot
// occur. Role names compare case-insensitively, like every IAM name.
//
// The profile write commits only while the role is still at the version
// read (store.UpdateIf), so a role deleted in between is never added; a
// profile or role changed in between is read again, never written from a
// stale copy. A request that was canceled or whose deadline passed is not
// written. Authorization (iam:AddRoleToInstanceProfile, and iam:PassRole
// on the role, as AWS requires) is console-api's, as for UpdateRole.
//
// TODO(#96): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#119).
func (s *Server) addRoleToInstanceProfile(ctx context.Context, pid, profileName, roleName string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidInstanceProfileName(profileName) {
		return invalidSpec("instanceProfileName must be 1 to 128 characters of [\\w+=,.@-]")
	}
	if !iam.ValidName(roleName) {
		return invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	p := s.project(pid)
	noProfile := notFound("Instance Profile " + profileName + " cannot be found.")
	noRole := notFound("The role with name " + roleName + " cannot be found.")
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.InstanceProfile](ctx, p.b, profileName)
		if errors.Is(err, store.ErrNotFound) {
			return noProfile
		}
		if err != nil {
			return toStatus(ctx, err)
		}
		r, err := store.Get[iam.Role](ctx, p.b, roleName)
		switch {
		case errors.Is(err, store.ErrNotFound):
			return noRole
		case err != nil:
			return toStatus(ctx, err)
		case r.Object.ServiceLinked():
			return unmodifiable("Cannot perform the operation on the protected role '" + r.Object.Name +
				"' - this role is only modifiable by its linked service")
		}
		ip := cur.Object
		if len(ip.Roles) >= iam.MaxInstanceProfileRoles {
			return quota("Cannot exceed quota for InstanceSessionsPerInstanceProfile: " +
				strconv.Itoa(iam.MaxInstanceProfileRoles))
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; write nothing
		}
		ip.Roles = append(slices.Clone(ip.Roles), r.Object.Name)
		ip.Generation++
		ip.Updated = s.now().UTC()
		_, err = store.UpdateIf(ctx, p.b, ip, cur.Version, store.PreOf(r))
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		case errors.Is(err, store.ErrNotFound):
			return noProfile
		default:
			return toStatus(ctx, err)
		}
	}
}

// Instance profile page sizes: the AWS default and maximum MaxItems of
// ListInstanceProfilesForRole.
const (
	DefaultInstanceProfilePageSize = 100
	MaxInstanceProfilePageSize     = 1000
)

// instanceProfilePage is one page of ListInstanceProfilesForRole: the
// profiles that hold Role, ordered by case-folded name. Role is the role
// as stored, which every listed profile holds (an instance profile holds
// at most one role), so a caller can render each profile's Roles. When
// IsTruncated is set, Marker continues the listing.
type instanceProfilePage struct {
	Profiles    []iam.InstanceProfile
	Role        iam.Role
	IsTruncated bool
	Marker      string
}

// listInstanceProfilesForRole is IAM ListInstanceProfilesForRole: the
// instance profiles of project pid that hold role roleName, in pages.
//
// A bad project id or a RoleName outside 1 to 64 characters of
// [\w+=,.@-] is ValidationError, as is a maxItems outside 1 to 1000 (0
// means not set: the AWS default of 100) or a marker with a character
// outside [\u0020-\u00FF]; all before any store access. A marker this
// call did not return is InvalidInput, as for ListPolicyTags. An unknown
// role is NoSuchEntity; a role in no profile is an empty page. Role
// names compare case-insensitively, like every IAM name.
//
// Profiles are ordered by case-folded name, so pages are deterministic
// and a marker (the last name of the previous page) continues after that
// name even when profiles are created or deleted in between: every
// profile that exists for the whole listing is returned once. The call
// only reads; PathPrefix does not apply, as AWS has none here.
// Authorization (iam:ListInstanceProfilesForRole) is console-api's, as
// for the other IAM reads.
//
// TODO(#95): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#120).
func (s *Server) listInstanceProfilesForRole(
	ctx context.Context, pid, roleName, marker string, maxItems int,
) (instanceProfilePage, error) {
	if !iam.ValidProject(pid) {
		return instanceProfilePage{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidName(roleName) {
		return instanceProfilePage{}, invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	maxItems, err := instanceProfilePageSize(maxItems)
	if err != nil {
		return instanceProfilePage{}, err
	}
	after, err := decodeMarker(marker)
	if err != nil {
		return instanceProfilePage{}, err
	}
	p := s.project(pid)
	r, err := store.Get[iam.Role](ctx, p.b, roleName)
	if errors.Is(err, store.ErrNotFound) {
		return instanceProfilePage{}, notFound("The role with name " + roleName + " cannot be found.")
	}
	if err != nil {
		return instanceProfilePage{}, toStatus(ctx, err)
	}
	all, err := store.List[iam.InstanceProfile](ctx, p.b)
	if err != nil {
		return instanceProfilePage{}, toStatus(ctx, err)
	}
	role := store.Fold(r.Object.Name)
	var held []iam.InstanceProfile
	for _, v := range all {
		if after != "" && store.Fold(v.Object.Name) <= after {
			continue
		}
		if slices.ContainsFunc(v.Object.Roles, func(n string) bool { return store.Fold(n) == role }) {
			held = append(held, v.Object)
		}
	}
	out := instanceProfilePage{Role: r.Object}
	out.Profiles, out.IsTruncated, out.Marker = pageInstanceProfiles(held, maxItems)
	return out, nil
}

// instanceProfileListing is one page of ListInstanceProfiles: the
// profiles whose path starts with the PathPrefix, ordered by case-folded
// name, each as stored. Roles holds, by case-folded name, the stored
// roles the listed profiles name, so a caller can render each profile's
// Roles; a name with no stored role (a role deleted while in the profile,
// #234) is absent. When IsTruncated is set, Marker continues the listing.
type instanceProfileListing struct {
	Profiles    []iam.InstanceProfile
	Roles       map[string]iam.Role
	IsTruncated bool
	Marker      string
}

// listInstanceProfiles is IAM ListInstanceProfiles: the instance profiles
// of project pid whose path starts with pathPrefix, in pages.
//
// pathPrefix "" means not set: the AWS default "/", every profile. A bad
// project id, a pathPrefix outside 1 to 512 characters of
// \u002F[\u0021-\u007F]*, a maxItems outside 1 to 1000 (0 means not set:
// the AWS default of 100) or a marker with a character outside
// [\u0020-\u00FF] is ValidationError, all before any store access. A
// marker this call did not return is InvalidInput, as for
// ListInstanceProfilesForRole. No profile is an empty page. Paths match
// case-sensitively, as IAM paths are; a profile stored without a path has
// the path "/".
//
// Profiles are ordered by case-folded name, so pages are deterministic
// and a marker (the last name of the previous page) continues after that
// name even when profiles are created or deleted in between: every
// profile that exists for the whole listing is returned once. The call
// only reads. Authorization (iam:ListInstanceProfiles) is console-api's,
// as for the other IAM reads.
//
// TODO(#94): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#121).
func (s *Server) listInstanceProfiles(
	ctx context.Context, pid, pathPrefix, marker string, maxItems int,
) (instanceProfileListing, error) {
	if !iam.ValidProject(pid) {
		return instanceProfileListing{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if pathPrefix == "" {
		pathPrefix = "/"
	}
	if !iam.ValidPathPrefix(pathPrefix) {
		return instanceProfileListing{}, invalidSpec("pathPrefix must be 1 to " +
			strconv.Itoa(iam.MaxPathPrefixLen) + " characters of \\u002F[\\u0021-\\u007F]*")
	}
	maxItems, err := instanceProfilePageSize(maxItems)
	if err != nil {
		return instanceProfileListing{}, err
	}
	after, err := decodeMarker(marker)
	if err != nil {
		return instanceProfileListing{}, err
	}
	p := s.project(pid)
	all, err := store.List[iam.InstanceProfile](ctx, p.b)
	if err != nil {
		return instanceProfileListing{}, toStatus(ctx, err)
	}
	var match []iam.InstanceProfile
	for _, v := range all {
		if after != "" && store.Fold(v.Object.Name) <= after {
			continue
		}
		path := v.Object.Path
		if path == "" {
			path = "/"
		}
		if strings.HasPrefix(path, pathPrefix) {
			match = append(match, v.Object)
		}
	}
	var out instanceProfileListing
	out.Profiles, out.IsTruncated, out.Marker = pageInstanceProfiles(match, maxItems)
	if out.Roles, err = profileRoles(ctx, p.b, out.Profiles); err != nil {
		return instanceProfileListing{}, toStatus(ctx, err)
	}
	return out, nil
}

// profileRoles returns, by case-folded name, the stored roles of b that
// the profiles ps name; empty, without a store read, when they name none.
// Names with no stored role are left out. It lists the roles once rather
// than reading each.
func profileRoles(ctx context.Context, b store.Backend, ps []iam.InstanceProfile) (map[string]iam.Role, error) {
	want := map[string]bool{}
	for _, ip := range ps {
		for _, n := range ip.Roles {
			want[store.Fold(n)] = true
		}
	}
	out := make(map[string]iam.Role, len(want))
	if len(want) == 0 {
		return out, nil
	}
	roles, err := store.List[iam.Role](ctx, b)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if k := store.Fold(r.Object.Name); want[k] {
			out[k] = r.Object
		}
	}
	return out, nil
}

// instanceProfilePageSize returns the page size of an instance profile
// listing for maxItems: 0 means not set, the AWS default of 100; a value
// outside 1 to 1000 is ValidationError.
func instanceProfilePageSize(maxItems int) (int, error) {
	switch {
	case maxItems == 0:
		return DefaultInstanceProfilePageSize, nil
	case maxItems < 1 || maxItems > MaxInstanceProfilePageSize:
		return 0, invalidSpec("maxItems must be 1 to " + strconv.Itoa(MaxInstanceProfilePageSize))
	}
	return maxItems, nil
}

// pageInstanceProfiles orders ps by case-folded name, whatever order the
// backend listed them in, and returns the first n of them. When more
// remain, truncated is set and marker continues after the last one
// returned (the base64url of its folded name, see decodeMarker).
func pageInstanceProfiles(ps []iam.InstanceProfile, n int) (page []iam.InstanceProfile, truncated bool, marker string) {
	slices.SortFunc(ps, func(a, b iam.InstanceProfile) int {
		return strings.Compare(store.Fold(a.Name), store.Fold(b.Name))
	})
	if len(ps) <= n {
		return ps, false, ""
	}
	ps = ps[:n]
	return ps, true, base64.RawURLEncoding.EncodeToString([]byte(store.Fold(ps[n-1].Name)))
}

// decodeMarker returns the case-folded profile name an instance profile
// listing marker continues after; "" for no marker.
// A marker outside the AWS pattern [\u0020-\u00FF]+ is ValidationError;
// one this service did not issue is InvalidInput.
func decodeMarker(marker string) (string, error) {
	if marker == "" {
		return "", nil
	}
	for _, c := range marker {
		if c < 0x20 || c > 0xFF {
			return "", invalidSpec("marker must be characters of [\\u0020-\\u00FF]")
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(marker)
	if err != nil || !iam.ValidInstanceProfileName(string(raw)) || store.Fold(string(raw)) != string(raw) {
		return "", invalidInput("marker is not valid")
	}
	return string(raw), nil
}

// instanceProfileView is the result of GetInstanceProfile: the profile as
// stored, its ARN, and the stored roles it names, in the profile's order,
// so a caller can render InstanceProfile.Roles with every role field. A
// name with no stored role (a role deleted while in the profile, #234) is
// left out.
type instanceProfileView struct {
	Profile iam.InstanceProfile
	ARN     string
	Roles   []iam.Role
}

// getInstanceProfile is IAM GetInstanceProfile: instance profile
// profileName of project pid, with its roles.
//
// A bad project id or an InstanceProfileName outside 1 to 128 characters
// of [\w+=,.@-] is ValidationError before any store access. An unknown
// instance profile is NoSuchEntity. Names compare case-insensitively, like
// every IAM name; the profile is returned under its name as stored. The
// call only reads: one profile read and one read per role it names (at
// most iam.MaxInstanceProfileRoles). Authorization (iam:GetInstanceProfile)
// is console-api's, as for the other IAM reads. AWS also returns the
// profile's Tags, which iam.InstanceProfile does not model yet (#239).
//
// TODO(#93): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#122).
func (s *Server) getInstanceProfile(ctx context.Context, pid, profileName string) (instanceProfileView, error) {
	if !iam.ValidProject(pid) {
		return instanceProfileView{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidInstanceProfileName(profileName) {
		return instanceProfileView{}, invalidSpec("instanceProfileName must be 1 to 128 characters of [\\w+=,.@-]")
	}
	p := s.project(pid)
	cur, err := store.Get[iam.InstanceProfile](ctx, p.b, profileName)
	if errors.Is(err, store.ErrNotFound) {
		return instanceProfileView{}, notFound("Instance Profile " + profileName + " cannot be found.")
	}
	if err != nil {
		return instanceProfileView{}, toStatus(ctx, err)
	}
	ip := cur.Object
	out := instanceProfileView{Profile: ip, ARN: iam.InstanceProfileARN(p.id, ip)}
	for _, n := range ip.Roles {
		r, err := store.Get[iam.Role](ctx, p.b, n)
		if errors.Is(err, store.ErrNotFound) {
			continue // a stale name of a deleted role (#234)
		}
		if err != nil {
			return instanceProfileView{}, toStatus(ctx, err)
		}
		out.Roles = append(out.Roles, r.Object)
	}
	return out, nil
}
