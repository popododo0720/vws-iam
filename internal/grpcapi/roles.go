package grpcapi

import (
	"context"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

var rolePaths = []string{"spec.path", "spec.assume_role_policy", "spec.max_session_duration_seconds", "spec.attached_policies", "spec.inline_policies", "spec.description"}

func (p project) roleProto(v store.Versioned[iam.Role]) *iamv1.Role {
	r := v.Object
	return &iamv1.Role{
		Name: name(p.id, "roles", r.Name), Uid: r.UID, Generation: r.Generation, Etag: v.Version, Labels: labels(r.Labels),
		Spec: &iamv1.RoleSpec{
			Path: defaultPath(r.Path), AssumeRolePolicy: r.AssumeRolePolicy, MaxSessionDurationSeconds: int32(maxSession(r) / time.Second),
			AttachedPolicies: p.policyNames(r.AttachedPolicies), InlinePolicies: r.InlinePolicies, Description: r.Description,
		},
		Status:     &iamv1.RoleStatus{Observed: ready(r.Generation), Arn: iam.RoleARN(p.id, r), UniqueId: r.ID, SessionsRevokeTime: ts(r.SessionsRevokedBefore)},
		CreateTime: ts(r.Created), UpdateTime: ts(r.Updated),
	}
}

func maxSession(r iam.Role) time.Duration {
	if r.MaxSessionDuration == 0 {
		return time.Hour
	}
	return r.MaxSessionDuration
}

func (p project) roleSpec(ctx context.Context, r *iam.Role, spec *iamv1.RoleSpec, set map[string]bool) error {
	if set["spec.path"] {
		r.Path = spec.GetPath()
	}
	if set["spec.description"] {
		if len(spec.GetDescription()) > 1000 {
			return invalidSpec("description is longer than 1000 characters")
		}
		r.Description = spec.GetDescription()
	}
	if set["spec.assume_role_policy"] {
		if _, err := policy.ParseTrust(spec.GetAssumeRolePolicy()); err != nil {
			return err
		}
		r.AssumeRolePolicy = spec.GetAssumeRolePolicy()
	}
	if set["spec.max_session_duration_seconds"] {
		r.MaxSessionDuration = time.Duration(spec.GetMaxSessionDurationSeconds()) * time.Second
	}
	if set["spec.attached_policies"] {
		arns, err := p.attachedARNs(ctx, spec.GetAttachedPolicies())
		if err != nil {
			return err
		}
		r.AttachedPolicies = arns
	}
	if set["spec.inline_policies"] {
		if err := checkInline("role", r.Name, maxInlineRole, spec.GetInlinePolicies()); err != nil {
			return err
		}
		r.InlinePolicies = spec.GetInlinePolicies()
	}
	return nil
}

func bumpRole(g *iam.Role) { g.Generation++ }

// GetRole returns one role.
func (s *Server) GetRole(ctx context.Context, req *iamv1.GetRoleRequest) (*iamv1.Role, error) {
	pid, id, err := child(req.GetName(), "roles")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	v, err := store.Get[iam.Role](ctx, p.b, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return p.roleProto(v), nil
}

// ListRoles pages through a project's roles.
func (s *Server) ListRoles(ctx context.Context, req *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	all, err := store.List[iam.Role](ctx, p.b)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	items, next, err := page(all, func(v store.Versioned[iam.Role]) string { return v.Object.Name }, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListRolesResponse{NextPageToken: next}
	for _, v := range items {
		out.Roles = append(out.Roles, p.roleProto(v))
	}
	return out, nil
}

// CreateRole creates a role.
func (s *Server) CreateRole(ctx context.Context, req *iamv1.CreateRoleRequest) (*longrunningpb.Operation, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	if err := checkID(req.GetRoleId(), "role"); err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "CreateRole", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	g := iam.Role{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1, Labels: req.GetRole().GetLabels(), RequestID: req.GetRequestId()}, Name: req.GetRoleId(), ID: iam.NewUniqueID("AROA"), Created: s.now().UTC()}
	if err := p.roleSpec(ctx, &g, req.GetRole().GetSpec(), allPaths(rolePaths)); err != nil {
		return nil, toStatus(ctx, err)
	}
	v, err := create(ctx, p.b, g, req.GetRequestId(), req.GetValidateOnly())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := p.roleProto(v)
	op, err := s.done(ctx, opArgs{project: pid, method: "CreateRole", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_CREATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// UpdateRole changes spec and labels.
func (s *Server) UpdateRole(ctx context.Context, req *iamv1.UpdateRoleRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetRole().GetName(), "roles")
	if err != nil {
		return nil, err
	}
	set, err := paths(req.GetUpdateMask(), rolePaths...)
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "UpdateRole", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	apply := func(g *iam.Role) error {
		if err := p.roleSpec(ctx, g, req.GetRole().GetSpec(), set); err != nil {
			return err
		}
		if set["labels"] {
			g.Labels = req.GetRole().GetLabels()
		}
		g.Updated = s.now().UTC()
		return g.Validate()
	}
	v, err := mutateOrValidate(ctx, p.b, id, req.GetRole().GetEtag(), req.GetValidateOnly(), req.GetAllowMissing(), bumpRole, apply, func() (iam.Role, error) {
		g := iam.Role{Meta: iam.Meta{UID: iam.NewUID()}, Name: id, ID: iam.NewUniqueID("AROA"), Created: s.now().UTC()}
		if err := checkID(id, "role"); err != nil {
			return g, err
		}
		return g, apply(&g)
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := p.roleProto(v)
	op, err := s.done(ctx, opArgs{project: pid, method: "UpdateRole", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// DeleteRole deletes a role with no policies (AWS DeleteConflict).
func (s *Server) DeleteRole(ctx context.Context, req *iamv1.DeleteRoleRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "roles")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "DeleteRole", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	v, _, err := remove(ctx, p.b, id, req.GetEtag(), req.GetAllowMissing(), func(g iam.Role) error {
		if len(g.AttachedPolicies) > 0 || len(g.InlinePolicies) > 0 {
			return deleteConflict("role has attached or inline policies")
		}
		return nil
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := &iamv1.Role{Name: req.GetName()}
	if v.Object.Name != "" {
		resp = p.roleProto(v)
		resp.DeleteTime = timestamppb.New(s.now())
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "DeleteRole", requestID: req.GetRequestId(), req: req, resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE, generation: v.Object.Generation, response: resp})
	return op, toStatus(ctx, err)
}

func (p project) roleByName(ctx context.Context, n string) (iam.Role, error) {
	v, err := store.Get[iam.Role](ctx, p.b, n)
	return v.Object, err
}
