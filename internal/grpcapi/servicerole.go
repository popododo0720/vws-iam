package grpcapi

import (
	"context"
	"errors"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// maxDeleteAttempts bounds the re-reads of a role that changed between
// the read and the delete.
const maxDeleteAttempts = 8

// deleteServiceLinkedRole is IAM DeleteServiceLinkedRole: it deletes the
// service-linked role name of project pid and returns its AWS
// DeletionTaskId. The deletion is complete when it returns, so
// GetServiceLinkedRoleDeletionStatus can only report SUCCEEDED for it.
// The task id comes from the role's UID: a request that read the role
// before a concurrent request deleted it gets the same id (only this
// method deletes a service-linked role; DeleteRole refuses one), and a
// repeat after the role is gone is NoSuchEntity. A role that is not
// service-linked is NoSuchEntity too, and is never deleted here. The
// delete is conditional on the version read, so a role changed in
// between is read again, never deleted blind.
// Authorization (iam:DeleteServiceLinkedRole) is console-api's, as for
// DeleteRole.
//
// TODO(#104): serve this as RoleService.DeleteServiceLinkedRole once
// vws-proto carries the RPC (popododo0720/vws-proto#106).
func (s *Server) deleteServiceLinkedRole(ctx context.Context, pid, roleName string) (string, error) {
	if !iam.ValidProject(pid) {
		return "", invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidName(roleName) {
		return "", invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	p := s.project(pid)
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.Role](ctx, p.b, roleName)
		if errors.Is(err, store.ErrNotFound) || err == nil && !cur.Object.ServiceLinked() {
			return "", notFound("The service-linked role with name " + roleName + " cannot be found.")
		}
		if err != nil {
			return "", toStatus(ctx, err)
		}
		err = store.Delete[iam.Role](ctx, p.b, cur.Object.Name, cur.Version)
		switch {
		case err == nil || errors.Is(err, store.ErrNotFound):
			return iam.DeletionTaskID(cur.Object), nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		default:
			return "", toStatus(ctx, err)
		}
	}
}
