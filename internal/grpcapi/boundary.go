package grpcapi

import (
	"context"
	"errors"
	"strings"

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

// putRolePermissionsBoundary is IAM PutRolePermissionsBoundary: it sets
// the permissions boundary of role roleName in project pid to the managed
// policy boundaryARN, replacing any boundary the role has. The trust and
// permission policies stay. A role that already has this boundary is left
// unwritten and the call succeeds, so a retry after a lost response
// succeeds too.
//
// RoleName and the ARN length are ValidationError and an ARN that is not a
// managed policy ARN is InvalidInput, all before any store access. The
// policy must be a managed policy of pid; any other ARN, including one of
// another account, is NoSuchEntity, as VWS has no AWS managed policies and
// so no policy that is not attachable (PolicyNotAttachable). An unknown
// role is NoSuchEntity; a service-linked role is UnmodifiableEntity, as
// AWS protects it. The write is conditional on the version read, so a role
// changed in between is read again, never written from a stale copy.
// Authorization (iam:PutRolePermissionsBoundary) is console-api's, as for
// UpdateRole.
//
// TODO(#100): serve this as RoleService.PutRolePermissionsBoundary once
// vws-proto carries the RPC (popododo0720/vws-proto#115).
func (s *Server) putRolePermissionsBoundary(ctx context.Context, pid, roleName, boundaryARN string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidName(roleName) {
		return invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	if n := len(boundaryARN); n < minBoundaryARN || n > maxBoundaryARN {
		return invalidSpec("permissionsBoundary must be 20 to 2048 characters")
	}
	if !iam.ValidPolicyARN(boundaryARN) {
		return invalidInput("ARN " + boundaryARN + " is not valid.")
	}
	p := s.project(pid)
	if err := p.boundaryPolicy(ctx, boundaryARN); err != nil {
		return err
	}
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
		if r.PermissionsBoundary == boundaryARN {
			return nil
		}
		r.PermissionsBoundary = boundaryARN
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

// The AWS PermissionsBoundary length constraints.
const (
	minBoundaryARN = 20
	maxBoundaryARN = 2048
)

// boundaryPolicy reports NoSuchEntity unless arn names a managed policy of
// project p, path included, as the authorizer resolves attached policies.
func (p project) boundaryPolicy(ctx context.Context, arn string) error {
	missing := notFound("Policy " + arn + " does not exist or is not attachable.")
	id := arn[strings.LastIndexByte(arn, '/')+1:]
	if !strings.HasPrefix(arn, iam.ARN("iam", "", p.id, "policy/")) || !iam.ValidPolicyName(id) {
		return missing
	}
	pol, err := store.Get[iam.Policy](ctx, p.b, id)
	if errors.Is(err, store.ErrNotFound) {
		return missing
	}
	if err != nil {
		return toStatus(ctx, err)
	}
	if iam.PolicyARN(p.id, pol.Object) != arn {
		return missing
	}
	return nil
}
