package grpcapi

import (
	"context"
	"errors"
	"slices"

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
