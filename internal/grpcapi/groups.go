package grpcapi

import (
	"context"
	"errors"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

var groupPaths = []string{"spec.path", "spec.members", "spec.attached_policies", "spec.inline_policies"}

func (p project) groupProto(v store.Versioned[iam.Group]) *iamv1.Group {
	g := v.Object
	members := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, name(p.id, "users", m))
	}
	return &iamv1.Group{
		Name: name(p.id, "groups", g.Name), Uid: g.UID, Generation: g.Generation, Etag: v.Version, Labels: labels(g.Labels),
		Spec:       &iamv1.GroupSpec{Path: defaultPath(g.Path), Members: members, AttachedPolicies: p.policyNames(g.AttachedPolicies), InlinePolicies: g.InlinePolicies},
		Status:     &iamv1.GroupStatus{Observed: ready(g.Generation), Arn: iam.GroupARN(p.id, g), UniqueId: g.ID},
		CreateTime: ts(g.Created), UpdateTime: ts(g.Updated),
	}
}

func (p project) groupSpec(ctx context.Context, g *iam.Group, spec *iamv1.GroupSpec, set map[string]bool) error {
	if set["spec.path"] {
		g.Path = spec.GetPath()
	}
	if set["spec.members"] {
		g.Members = nil
		for _, m := range spec.GetMembers() {
			proj, id, err := child(m, "users")
			if err != nil {
				return err
			}
			if proj != p.id {
				return invalidSpec("member " + quote(m) + " is in another project")
			}
			u, err := store.Get[iam.User](ctx, p.b, id)
			if errors.Is(err, store.ErrNotFound) {
				return notFound("user " + quote(m) + " does not exist")
			}
			if err != nil {
				return err
			}
			g.Members = append(g.Members, u.Object.Name)
		}
	}
	if set["spec.attached_policies"] {
		arns, err := p.attachedARNs(ctx, spec.GetAttachedPolicies())
		if err != nil {
			return err
		}
		g.AttachedPolicies = arns
	}
	if set["spec.inline_policies"] {
		if err := checkInline(spec.GetInlinePolicies()); err != nil {
			return err
		}
		g.InlinePolicies = spec.GetInlinePolicies()
	}
	return nil
}

func bumpGroup(g *iam.Group) { g.Generation++ }

// GetGroup returns one group.
func (s *Server) GetGroup(ctx context.Context, req *iamv1.GetGroupRequest) (*iamv1.Group, error) {
	pid, id, err := child(req.GetName(), "groups")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	v, err := store.Get[iam.Group](ctx, p.b, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return p.groupProto(v), nil
}

// ListGroups pages through a project's groups.
func (s *Server) ListGroups(ctx context.Context, req *iamv1.ListGroupsRequest) (*iamv1.ListGroupsResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	all, err := store.List[iam.Group](ctx, p.b)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	items, next, err := page(all, func(v store.Versioned[iam.Group]) string { return v.Object.Name }, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListGroupsResponse{NextPageToken: next}
	for _, v := range items {
		out.Groups = append(out.Groups, p.groupProto(v))
	}
	return out, nil
}

// CreateGroup creates a group.
func (s *Server) CreateGroup(ctx context.Context, req *iamv1.CreateGroupRequest) (*longrunningpb.Operation, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	if err := checkID(req.GetGroupId(), "group"); err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "CreateGroup", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	g := iam.Group{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1, Labels: req.GetGroup().GetLabels(), RequestID: req.GetRequestId()}, Name: req.GetGroupId(), ID: iam.NewUniqueID("AGPA"), Created: s.now().UTC()}
	if err := p.groupSpec(ctx, &g, req.GetGroup().GetSpec(), allPaths(groupPaths)); err != nil {
		return nil, toStatus(ctx, err)
	}
	v, err := create(ctx, p.b, g, req.GetRequestId(), req.GetValidateOnly())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := p.groupProto(v)
	op, err := s.done(ctx, opArgs{project: pid, method: "CreateGroup", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_CREATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// UpdateGroup changes spec (including members) and labels.
func (s *Server) UpdateGroup(ctx context.Context, req *iamv1.UpdateGroupRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetGroup().GetName(), "groups")
	if err != nil {
		return nil, err
	}
	set, err := paths(req.GetUpdateMask(), groupPaths...)
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "UpdateGroup", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	apply := func(g *iam.Group) error {
		if err := p.groupSpec(ctx, g, req.GetGroup().GetSpec(), set); err != nil {
			return err
		}
		if set["labels"] {
			g.Labels = req.GetGroup().GetLabels()
		}
		g.Updated = s.now().UTC()
		return g.Validate()
	}
	v, err := mutateOrValidate(ctx, p.b, id, req.GetGroup().GetEtag(), req.GetValidateOnly(), req.GetAllowMissing(), bumpGroup, apply, func() (iam.Group, error) {
		g := iam.Group{Meta: iam.Meta{UID: iam.NewUID()}, Name: id, ID: iam.NewUniqueID("AGPA"), Created: s.now().UTC()}
		if err := checkID(id, "group"); err != nil {
			return g, err
		}
		return g, apply(&g)
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := p.groupProto(v)
	op, err := s.done(ctx, opArgs{project: pid, method: "UpdateGroup", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// DeleteGroup deletes an empty group with no policies (AWS DeleteConflict).
func (s *Server) DeleteGroup(ctx context.Context, req *iamv1.DeleteGroupRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "groups")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "DeleteGroup", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	v, _, err := remove(ctx, p.b, id, req.GetEtag(), req.GetAllowMissing(), func(g iam.Group) error {
		switch {
		case len(g.Members) > 0:
			return deleteConflict("group has members")
		case len(g.AttachedPolicies) > 0 || len(g.InlinePolicies) > 0:
			return deleteConflict("group has attached or inline policies")
		}
		return nil
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := &iamv1.Group{Name: req.GetName()}
	if v.Object.Name != "" {
		resp = p.groupProto(v)
		resp.DeleteTime = timestamppb.New(s.now())
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "DeleteGroup", requestID: req.GetRequestId(), req: req, resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE, generation: v.Object.Generation, response: resp})
	return op, toStatus(ctx, err)
}
