package grpcapi

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

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
// while in the profile by a release before #234): then
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
// for UpdateRole. RemoveRoleFromInstanceProfile serves it over gRPC.
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
// stale copy. A role a DeleteRole is checking (iam.Role.DeleteStarted,
// #234) is waited for, then ConcurrentModification; a mark older than
// roleDeleteLease is cleared first, so that delete fails instead. A
// request that was canceled or whose deadline passed is not written.
// Authorization (iam:AddRoleToInstanceProfile, and iam:PassRole
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
		case !r.Object.DeleteStarted.IsZero():
			if err := p.awaitRoleDelete(ctx, r, attempt); err != nil {
				return toStatus(ctx, err)
			}
			continue
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
	DefaultInstanceProfilePageSize = DefaultListPageSize
	MaxInstanceProfilePageSize     = MaxListPageSize
)

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
// profile that exists for the whole listing is returned once. Each
// profile is returned as GetInstanceProfile returns it, with the role
// as read. The call only reads: one role read and one profile listing;
// PathPrefix does not apply, as AWS has none here. Authorization
// (iam:ListInstanceProfilesForRole) is console-api's, as for the other
// IAM reads.
func (s *Server) listInstanceProfilesForRole(
	ctx context.Context, pid, roleName, marker string, maxItems int,
) (instanceProfileListing, error) {
	if !iam.ValidProject(pid) {
		return instanceProfileListing{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidName(roleName) {
		return instanceProfileListing{}, invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
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
	r, err := store.Get[iam.Role](ctx, p.b, roleName)
	if errors.Is(err, store.ErrNotFound) {
		return instanceProfileListing{}, notFound("The role with name " + roleName + " cannot be found.")
	}
	if err != nil {
		return instanceProfileListing{}, toStatus(ctx, err)
	}
	all, err := store.List[iam.InstanceProfile](ctx, p.b)
	if err != nil {
		return instanceProfileListing{}, toStatus(ctx, err)
	}
	role := store.Fold(r.Object.Name)
	var held []store.Versioned[iam.InstanceProfile]
	for _, v := range all {
		if after != "" && store.Fold(v.Object.Name) <= after {
			continue
		}
		if slices.ContainsFunc(v.Object.Roles, func(n string) bool { return store.Fold(n) == role }) {
			held = append(held, v)
		}
	}
	page, truncated, next := pageByFoldedName(held,
		func(v store.Versioned[iam.InstanceProfile]) string { return v.Object.Name }, maxItems)
	out := instanceProfileListing{IsTruncated: truncated, Marker: next}
	for _, v := range page {
		out.Profiles = append(out.Profiles, instanceProfileView{
			Profile: v.Object, Version: v.Version, ARN: iam.InstanceProfileARN(p.id, v.Object),
			Roles: []store.Versioned[iam.Role]{r},
		})
	}
	return out, nil
}

// instanceProfileListing is one page of ListInstanceProfiles or
// ListInstanceProfilesForRole: the profiles that match, ordered by
// case-folded name, each as GetInstanceProfile returns it (the version read, its ARN
// and the stored roles it names; a name with no stored role, a role
// deleted while in the profile, #234, is left out). When IsTruncated is
// set, Marker continues the listing.
type instanceProfileListing struct {
	Profiles    []instanceProfileView
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
// only reads: one profile listing and, when the page names a role, one
// role listing. Authorization (iam:ListInstanceProfiles) is console-api's,
// as for the other IAM reads.
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
	var match []store.Versioned[iam.InstanceProfile]
	for _, v := range all {
		if after != "" && store.Fold(v.Object.Name) <= after {
			continue
		}
		if strings.HasPrefix(defaultPath(v.Object.Path), pathPrefix) {
			match = append(match, v)
		}
	}
	page, truncated, next := pageByFoldedName(match,
		func(v store.Versioned[iam.InstanceProfile]) string { return v.Object.Name }, maxItems)
	roles, err := profileRoles(ctx, p.b, page)
	if err != nil {
		return instanceProfileListing{}, toStatus(ctx, err)
	}
	out := instanceProfileListing{IsTruncated: truncated, Marker: next}
	for _, v := range page {
		view := instanceProfileView{Profile: v.Object, Version: v.Version, ARN: iam.InstanceProfileARN(p.id, v.Object)}
		for _, n := range v.Object.Roles {
			if r, ok := roles[store.Fold(n)]; ok {
				view.Roles = append(view.Roles, r)
			}
		}
		out.Profiles = append(out.Profiles, view)
	}
	return out, nil
}

// profileRoles returns, by case-folded name, the stored roles of b that
// the profiles ps name; empty, without a store read, when they name none.
// Names with no stored role are left out. It lists the roles once rather
// than reading each.
func profileRoles(
	ctx context.Context, b store.Backend, ps []store.Versioned[iam.InstanceProfile],
) (map[string]store.Versioned[iam.Role], error) {
	want := map[string]bool{}
	for _, ip := range ps {
		for _, n := range ip.Object.Roles {
			want[store.Fold(n)] = true
		}
	}
	out := make(map[string]store.Versioned[iam.Role], len(want))
	if len(want) == 0 {
		return out, nil
	}
	roles, err := store.List[iam.Role](ctx, b)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if k := store.Fold(r.Object.Name); want[k] {
			out[k] = r
		}
	}
	return out, nil
}

// instanceProfilePageSize returns the page size of an instance profile
// listing for maxItems (see listPageSize).
func instanceProfilePageSize(maxItems int) (int, error) { return listPageSize(maxItems) }

// decodeMarker returns the case-folded profile name an instance profile
// listing marker continues after; "" for no marker (see
// decodeNameMarker).
func decodeMarker(marker string) (string, error) {
	return decodeNameMarker(marker, iam.ValidInstanceProfileName)
}

// instanceProfileView is the result of GetInstanceProfile: the profile as
// stored at Version, its ARN, and the stored roles it names, in the
// profile's order, so a caller can render InstanceProfile.Roles with every
// role field. A name with no stored role (a role deleted while in the
// profile, #234) is left out.
type instanceProfileView struct {
	Profile iam.InstanceProfile
	Version string
	ARN     string
	Roles   []store.Versioned[iam.Role]
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
	out := instanceProfileView{Profile: ip, Version: cur.Version, ARN: iam.InstanceProfileARN(p.id, ip)}
	for _, n := range ip.Roles {
		r, err := store.Get[iam.Role](ctx, p.b, n)
		if errors.Is(err, store.ErrNotFound) {
			continue // a stale name of a deleted role (#234)
		}
		if err != nil {
			return instanceProfileView{}, toStatus(ctx, err)
		}
		out.Roles = append(out.Roles, r)
	}
	return out, nil
}

// deleteInstanceProfile is IAM DeleteInstanceProfile: it deletes instance
// profile profileName of project pid.
//
// A bad project id or an InstanceProfileName outside 1 to 128 characters
// of [\w+=,.@-] is ValidationError before any store access. An unknown
// instance profile is NoSuchEntity, so a retry after a lost response is
// NoSuchEntity, as in AWS. A profile that still holds a role is
// DeleteConflict: the role must be removed first. A stale name of a role
// deleted while in the profile (#234) holds no role, as in
// GetInstanceProfile and ListInstanceProfiles, so it does not block the
// delete. The delete is conditional on the version read, so a role added
// in between (AddRoleToInstanceProfile writes the profile) makes the
// profile be read again and the delete refused, never done blind; a
// request that was canceled or whose deadline passed deletes nothing. A
// store failure is InternalFailure. Authorization
// (iam:DeleteInstanceProfile) is console-api's, as for DeleteRole.
//
// TODO(#92): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#124).
func (s *Server) deleteInstanceProfile(ctx context.Context, pid, profileName string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidInstanceProfileName(profileName) {
		return invalidSpec("instanceProfileName must be 1 to 128 characters of [\\w+=,.@-]")
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
		for _, n := range cur.Object.Roles {
			_, err := store.Get[iam.Role](ctx, p.b, n)
			if errors.Is(err, store.ErrNotFound) {
				continue // a stale name of a deleted role (#234)
			}
			if err != nil {
				return toStatus(ctx, err)
			}
			return deleteConflict("Cannot delete entity, must remove roles from instance profile first.")
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; delete nothing
		}
		err = store.Delete[iam.InstanceProfile](ctx, p.b, profileName, cur.Version)
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

// createInstanceProfile is IAM CreateInstanceProfile: it creates instance
// profile profileName under path in project pid, without a role, and
// returns it with its ARN.
//
// A bad project id, an InstanceProfileName outside 1 to 128 characters of
// [\w+=,.@-] or a Path that is not "/" or a slash-delimited run of 1 to
// 512 printable ASCII characters is ValidationError before any store
// access. An empty path is "/", the AWS default. A name that is taken, in
// any case (IAM names compare case-insensitively), is EntityAlreadyExists
// and the stored profile stays: the create is one store create, so of
// racing requests on any replica exactly one makes the profile, and a
// retry after a lost response is EntityAlreadyExists, as in AWS, which has
// no request id here. A request that was canceled or whose deadline
// passed writes nothing. A store failure is InternalFailure. Tags are not
// modeled yet (#239), and the InstanceProfilesPerAccount quota is not
// enforced yet (#243). Authorization (iam:CreateInstanceProfile) is
// console-api's, as for CreateRole.
//
// TODO(#91): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#126).
func (s *Server) createInstanceProfile(
	ctx context.Context, pid, profileName, path string,
) (instanceProfileView, error) {
	if !iam.ValidProject(pid) {
		return instanceProfileView{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidInstanceProfileName(profileName) {
		return instanceProfileView{}, invalidSpec("instanceProfileName must be 1 to 128 characters of [\\w+=,.@-]")
	}
	if path == "" {
		path = "/"
	}
	if !iam.ValidPath(path) {
		return instanceProfileView{}, invalidSpec("path must be / or 1 to 512 characters of " +
			"\\u002F[\\u0021-\\u007E]+\\u002F")
	}
	if err := ctx.Err(); err != nil {
		return instanceProfileView{}, toStatus(ctx, err) // the caller is gone; write nothing
	}
	p := s.project(pid)
	ip := iam.InstanceProfile{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: profileName, Path: path,
		ID: iam.NewUniqueID("AIPA"), Created: s.now().UTC(),
	}
	version, err := store.Create(ctx, p.b, ip)
	if errors.Is(err, store.ErrExists) {
		return instanceProfileView{}, alreadyExists("Instance Profile " + profileName + " already exists.")
	}
	if err != nil {
		return instanceProfileView{}, toStatus(ctx, err)
	}
	return instanceProfileView{Profile: ip, Version: version, ARN: iam.InstanceProfileARN(p.id, ip)}, nil
}

// GetInstanceProfile is IAM GetInstanceProfile over gRPC (#93): the
// instance profile name names, through getInstanceProfile.
func (s *Server) GetInstanceProfile(
	ctx context.Context, req *iamv1.GetInstanceProfileRequest,
) (*iamv1.InstanceProfile, error) {
	pid, id, err := child(req.GetName(), "instanceProfiles")
	if err != nil {
		return nil, err
	}
	v, err := s.getInstanceProfile(ctx, pid, id)
	if err != nil {
		return nil, err
	}
	return s.project(pid).instanceProfileProto(v), nil
}

// ListInstanceProfiles is IAM ListInstanceProfiles over gRPC (#94): the
// instance profiles of parent whose path starts with path_prefix, through
// listInstanceProfiles. page_size is MaxItems and page_token the Marker;
// next_page_token is set exactly when the page is truncated.
func (s *Server) ListInstanceProfiles(
	ctx context.Context, req *iamv1.ListInstanceProfilesRequest,
) (*iamv1.ListInstanceProfilesResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	pg, err := s.listInstanceProfiles(ctx, pid, req.GetPathPrefix(), req.GetPageToken(), int(req.GetPageSize()))
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	out := &iamv1.ListInstanceProfilesResponse{NextPageToken: pg.Marker}
	for _, v := range pg.Profiles {
		out.InstanceProfiles = append(out.InstanceProfiles, p.instanceProfileProto(v))
	}
	return out, nil
}

// ListInstanceProfilesForRole is IAM ListInstanceProfilesForRole over
// gRPC (#95): the instance profiles of parent that hold role_name,
// through listInstanceProfilesForRole. page_size is MaxItems and
// page_token the Marker; next_page_token is set exactly when the page is
// truncated.
func (s *Server) ListInstanceProfilesForRole(
	ctx context.Context, req *iamv1.ListInstanceProfilesForRoleRequest,
) (*iamv1.ListInstanceProfilesForRoleResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	pg, err := s.listInstanceProfilesForRole(ctx, pid, req.GetRoleName(), req.GetPageToken(), int(req.GetPageSize()))
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	out := &iamv1.ListInstanceProfilesForRoleResponse{NextPageToken: pg.Marker}
	for _, v := range pg.Profiles {
		out.InstanceProfiles = append(out.InstanceProfiles, p.instanceProfileProto(v))
	}
	return out, nil
}

// RemoveRoleFromInstanceProfile is IAM RemoveRoleFromInstanceProfile over
// gRPC (#97): it removes role_name from the instance profile name names,
// through removeRoleFromInstanceProfile. The response is empty, as AWS
// returns only a request id.
func (s *Server) RemoveRoleFromInstanceProfile(
	ctx context.Context, req *iamv1.RemoveRoleFromInstanceProfileRequest,
) (*iamv1.RemoveRoleFromInstanceProfileResponse, error) {
	pid, id, err := child(req.GetName(), "instanceProfiles")
	if err != nil {
		return nil, err
	}
	if err := s.removeRoleFromInstanceProfile(ctx, pid, id, req.GetRoleName()); err != nil {
		return nil, err
	}
	return &iamv1.RemoveRoleFromInstanceProfileResponse{}, nil
}

// instanceProfileProto renders v. spec.roles and status.roles both list
// the stored roles of v, so a stale name of a deleted role (#234) is in
// neither.
func (p project) instanceProfileProto(v instanceProfileView) *iamv1.InstanceProfile {
	ip := v.Profile
	out := &iamv1.InstanceProfile{
		Name: name(p.id, "instanceProfiles", ip.Name), Uid: ip.UID, Generation: ip.Generation, Etag: v.Version,
		Labels:     labels(ip.Labels),
		Spec:       &iamv1.InstanceProfileSpec{Path: defaultPath(ip.Path)},
		Status:     &iamv1.InstanceProfileStatus{Observed: ready(ip.Generation), Arn: v.ARN, UniqueId: ip.ID},
		CreateTime: ts(ip.Created), UpdateTime: ts(ip.Updated),
	}
	for _, r := range v.Roles {
		out.Spec.Roles = append(out.Spec.Roles, name(p.id, "roles", r.Object.Name))
		out.Status.Roles = append(out.Status.Roles, p.roleProto(r))
	}
	return out
}
