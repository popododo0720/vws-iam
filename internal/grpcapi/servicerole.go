package grpcapi

import (
	"context"
	"errors"
	"regexp"
	"unicode/utf8"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

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

// ServiceLinkedRoleRequest is the input of IAM CreateServiceLinkedRole.
// An empty CustomSuffix or Description is absent.
type ServiceLinkedRoleRequest struct {
	AWSServiceName string
	CustomSuffix   string
	Description    string
}

var (
	// slrParamRE is the AWS pattern of AWSServiceName and CustomSuffix.
	slrParamRE = regexp.MustCompile(`^[\w+=,.@-]+$`)
	// descriptionRE is the AWS pattern of a role Description.
	descriptionRE = regexp.MustCompile(`^[\x{0009}\x{000A}\x{000D}\x{0020}-\x{007E}\x{00A1}-\x{00FF}]*$`)
)

// checkServiceLinkedRoleRequest checks the AWS length and pattern
// constraints of req (ValidationError, as for every IAM parameter).
func checkServiceLinkedRoleRequest(req ServiceLinkedRoleRequest) error {
	if n := len(req.AWSServiceName); n < 1 || n > 128 || !slrParamRE.MatchString(req.AWSServiceName) {
		return invalidSpec("awsServiceName must be 1 to 128 characters of [\\w+=,.@-]")
	}
	if n := len(req.CustomSuffix); n > 64 || n > 0 && !slrParamRE.MatchString(req.CustomSuffix) {
		return invalidSpec("customSuffix must be 1 to 64 characters of [\\w+=,.@-]")
	}
	if utf8.RuneCountInString(req.Description) > 1000 || !descriptionRE.MatchString(req.Description) {
		return invalidSpec("description must be at most 1000 characters of " +
			"[\\u0009\\u000A\\u000D\\u0020-\\u007E\\u00A1-\\u00FF]")
	}
	return nil
}

// createServiceLinkedRole is IAM CreateServiceLinkedRole: it stores, in
// project pid, the role of the linked service req.AWSServiceName, named
// AWSServiceRoleFor<service role name>[_<CustomSuffix>], at path
// /aws-service-role/<service>/, trusting only that service principal.
// Only services in the catalog (WithLinkedServices) are accepted, by
// exact principal; any other is InvalidInput, as is a CustomSuffix the
// service does not allow or a role name over 64 characters. A name that
// is taken, by a service-linked role or any other role (case folded),
// is InvalidInput "has been taken", as in AWS: the create is one store
// create, so racing requests on any replica make the role once and the
// others get that error. CreateServiceLinkedRole has no request id in
// AWS, so a retry after a lost response gets it too.
// Authorization (iam:CreateServiceLinkedRole) is console-api's, as for
// CreateRole.
//
// TODO(#103): serve this as RoleService.CreateServiceLinkedRole once
// vws-proto carries the RPC (popododo0720/vws-proto#112).
func (s *Server) createServiceLinkedRole(
	ctx context.Context, pid string, req ServiceLinkedRoleRequest,
) (*iamv1.Role, error) {
	if !iam.ValidProject(pid) {
		return nil, invalidID("project " + quote(pid) + " is not a project id")
	}
	if err := checkServiceLinkedRoleRequest(req); err != nil {
		return nil, err
	}
	l, ok := s.linked[req.AWSServiceName]
	if !ok {
		return nil, invalidInput("Service principal " + req.AWSServiceName + " does not support service-linked roles.")
	}
	if err := l.Validate(); err != nil {
		return nil, serviceFailure("linked service " + req.AWSServiceName + " is misconfigured")
	}
	if req.CustomSuffix != "" && !l.CustomSuffix {
		return nil, invalidInput("Custom suffix is not allowed for " + req.AWSServiceName + ".")
	}
	roleName := l.ServiceLinkedRoleName(req.CustomSuffix)
	if !iam.ValidName(roleName) {
		return nil, invalidInput("Service role name " + roleName + " is longer than 64 characters.")
	}
	desc := req.Description
	if desc == "" {
		desc = l.Description
	}
	r := iam.Role{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: roleName, Path: iam.ServiceRolePath(l.Principal),
		ID: iam.NewUniqueID("AROA"), Created: s.now().UTC(), LinkedService: l.Principal,
		AssumeRolePolicy: iam.ServiceTrustPolicy(l.Principal), Description: desc,
	}
	p := s.project(pid)
	ver, err := store.Create(ctx, p.b, r)
	if errors.Is(err, store.ErrExists) {
		return nil, invalidInput("Service role name " + roleName +
			" has been taken in this account, please try a different suffix.")
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return p.roleProto(store.Versioned[iam.Role]{Object: r, Version: ver}), nil
}
