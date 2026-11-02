package grpcapi

import (
	"context"
	"errors"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// deleteRolePermissionsBoundary is IAM DeleteRolePermissionsBoundary: it
// removes the permissions boundary of role roleName in project pid. The
// role and its policies stay. A role with no boundary is left unwritten
// and the call succeeds, so a retry after a lost response succeeds too.
// An unknown role is NoSuchEntity; a service-linked role is
// UnmodifiableEntity, as AWS protects it. The write is conditional on
// the version read, so a role changed in between is read again, never
// written from a stale copy.
// Authorization (iam:DeleteRolePermissionsBoundary) is console-api's, as
// for UpdateRole.
//
// TODO(#101): serve this as RoleService.DeleteRolePermissionsBoundary
// once vws-proto carries the RPC (popododo0720/vws-proto#114).
func (s *Server) deleteRolePermissionsBoundary(ctx context.Context, pid, roleName string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidName(roleName) {
		return invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	p := s.project(pid)
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.Role](ctx, p.b, roleName)
		if errors.Is(err, store.ErrNotFound) {
			return notFound("The role with name " + roleName + " cannot be found.")
		}
		if err != nil {
			return toStatus(ctx, err)
		}
		r := cur.Object
		if r.ServiceLinked() {
			return unmodifiable("Cannot perform the operation on the protected role '" + r.Name +
				"' - this role is only modifiable by its linked service")
		}
		if r.PermissionsBoundary == "" {
			return nil
		}
		r.PermissionsBoundary = ""
		bumpRole(&r)
		r.Updated = s.now().UTC()
		_, err = store.Update(ctx, p.b, r, cur.Version)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		case errors.Is(err, store.ErrNotFound):
			return notFound("The role with name " + roleName + " cannot be found.")
		default:
			return toStatus(ctx, err)
		}
	}
}
