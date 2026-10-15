package grpcapi

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

var policyPaths = []string{"spec.description", "spec.default_version"}

// attachments counts users, groups and roles with arn attached.
func (p project) attachments(ctx context.Context, arn string) (int, error) {
	n := 0
	count := func(list []string) {
		for _, a := range list {
			if a == arn {
				n++
			}
		}
	}
	us, err := store.List[iam.User](ctx, p.b)
	if err != nil {
		return 0, err
	}
	for _, u := range us {
		count(u.Object.AttachedPolicies)
	}
	gs, err := store.List[iam.Group](ctx, p.b)
	if err != nil {
		return 0, err
	}
	for _, g := range gs {
		count(g.Object.AttachedPolicies)
	}
	rs, err := store.List[iam.Role](ctx, p.b)
	if err != nil {
		return 0, err
	}
	for _, r := range rs {
		count(r.Object.AttachedPolicies)
	}
	return n, nil
}

func (p project) policyProto(ctx context.Context, v store.Versioned[iam.Policy]) (*iamv1.Policy, error) {
	pol := v.Object
	arn := iam.PolicyARN(p.id, pol)
	n, err := p.attachments(ctx, arn)
	if err != nil {
		return nil, err
	}
	return &iamv1.Policy{
		Name: name(p.id, "policies", pol.Name), Uid: pol.UID, Generation: pol.Generation, Etag: v.Version, Labels: labels(pol.Labels),
		Spec: &iamv1.PolicySpec{
			Path:           defaultPath(pol.Path),
			Description:    pol.Description,
			Document:       pol.Default(),
			DefaultVersion: pol.DefaultVersion,
		},
		Status:     &iamv1.PolicyStatus{Observed: ready(pol.Generation), Arn: arn, UniqueId: pol.ID, AttachmentCount: int32(n)}, //nolint:gosec // bounded by entity count
		CreateTime: ts(pol.Created), UpdateTime: ts(pol.Updated),
	}, nil
}

func (p project) versionProto(v store.Versioned[iam.Policy], pv iam.PolicyVersion) *iamv1.PolicyVersion {
	pol := v.Object
	return &iamv1.PolicyVersion{
		Name: name(p.id, "policies", pol.Name) + "/versions/" + pv.ID, Generation: 1, Etag: v.Version,
		Spec:       &iamv1.PolicyVersionSpec{Document: pv.Document},
		Status:     &iamv1.PolicyVersionStatus{Observed: ready(1), DefaultVersion: pv.ID == pol.DefaultVersion},
		CreateTime: ts(pv.Created),
	}
}

func bumpPolicy(p *iam.Policy) { p.Generation++ }

func versionID(s string) string { return s[strings.LastIndex(s, "/")+1:] }

// GetPolicy returns a managed policy with its default document.
func (s *Server) GetPolicy(ctx context.Context, req *iamv1.GetPolicyRequest) (*iamv1.Policy, error) {
	pid, id, err := child(req.GetName(), "policies")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	v, err := store.Get[iam.Policy](ctx, p.b, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	out, err := p.policyProto(ctx, v)
	return out, toStatus(ctx, err)
}

// ListPolicies pages through a project's managed policies.
func (s *Server) ListPolicies(ctx context.Context, req *iamv1.ListPoliciesRequest) (*iamv1.ListPoliciesResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	all, err := store.List[iam.Policy](ctx, p.b)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	items, next, err := page(all, func(v store.Versioned[iam.Policy]) string { return v.Object.Name }, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListPoliciesResponse{NextPageToken: next}
	for _, v := range items {
		pp, err := p.policyProto(ctx, v)
		if err != nil {
			return nil, toStatus(ctx, err)
		}
		out.Policies = append(out.Policies, pp)
	}
	return out, nil
}

// CreatePolicy creates a managed policy with version v1 as default.
func (s *Server) CreatePolicy(ctx context.Context, req *iamv1.CreatePolicyRequest) (*longrunningpb.Operation, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	if err := checkID(req.GetPolicyId(), "policy"); err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "CreatePolicy", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	spec := req.GetPolicy().GetSpec()
	if _, err := policy.ParseIdentity(spec.GetDocument()); err != nil {
		return nil, toStatus(ctx, err)
	}
	if len(spec.GetDescription()) > 1000 {
		return nil, invalidSpec("description is longer than 1000 characters")
	}
	if dv := spec.GetDefaultVersion(); dv != "" && versionID(dv) != "v1" {
		return nil, invalidSpec("default_version of a new policy is v1")
	}
	now := s.now().UTC()
	pol := iam.Policy{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1, Labels: req.GetPolicy().GetLabels(), RequestID: req.GetRequestId()},
		Name: req.GetPolicyId(), Path: spec.GetPath(), ID: iam.NewUniqueID("ANPA"), Created: now, Description: spec.GetDescription(),
		DefaultVersion: "v1", NextVersion: 2, Versions: []iam.PolicyVersion{{ID: "v1", Document: spec.GetDocument(), Created: now}},
	}
	v, err := create(ctx, p.b, pol, req.GetRequestId(), req.GetValidateOnly())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp, err := p.policyProto(ctx, v)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "CreatePolicy", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_CREATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// UpdatePolicy changes the description, labels or default version. The
// document is immutable: add a version instead.
func (s *Server) UpdatePolicy(ctx context.Context, req *iamv1.UpdatePolicyRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetPolicy().GetName(), "policies")
	if err != nil {
		return nil, err
	}
	set, err := paths(req.GetUpdateMask(), policyPaths...)
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "UpdatePolicy", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	spec := req.GetPolicy().GetSpec()
	apply := func(pol *iam.Policy) error {
		if d := spec.GetDocument(); d != "" && d != pol.Default() {
			return invalidSpec("document is immutable; create a policy version")
		}
		if set["spec.description"] {
			if len(spec.GetDescription()) > 1000 {
				return invalidSpec("description is longer than 1000 characters")
			}
			pol.Description = spec.GetDescription()
		}
		if set["spec.default_version"] && spec.GetDefaultVersion() != "" {
			pol.DefaultVersion = versionID(spec.GetDefaultVersion())
		}
		if set["labels"] {
			pol.Labels = req.GetPolicy().GetLabels()
		}
		pol.Updated = s.now().UTC()
		if err := pol.Validate(); err != nil {
			return notFound("policy version " + quote(spec.GetDefaultVersion()) + " does not exist")
		}
		return nil
	}
	if req.GetAllowMissing() {
		return nil, invalidSpec("allow_missing is not supported for policies; use CreatePolicy")
	}
	v, err := mutateOrValidate(ctx, p.b, id, req.GetPolicy().GetEtag(), req.GetValidateOnly(), false, bumpPolicy, apply, nil)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp, err := p.policyProto(ctx, v)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "UpdatePolicy", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// DeletePolicy deletes a policy that is attached nowhere.
func (s *Server) DeletePolicy(ctx context.Context, req *iamv1.DeletePolicyRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "policies")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "DeletePolicy", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	v, _, err := remove(ctx, p.b, id, req.GetEtag(), req.GetAllowMissing(), func(pol iam.Policy) error {
		n, err := p.attachments(ctx, iam.PolicyARN(p.id, pol))
		if err != nil {
			return err
		}
		if n > 0 {
			return deleteConflict("policy is attached to " + strconv.Itoa(n) + " entities")
		}
		return nil
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := &iamv1.Policy{Name: req.GetName()}
	if v.Object.Name != "" {
		pol := v.Object
		resp = &iamv1.Policy{
			Name: req.GetName(), Uid: pol.UID, Generation: pol.Generation, Labels: labels(pol.Labels),
			Spec: &iamv1.PolicySpec{
				Path:           defaultPath(pol.Path),
				Description:    pol.Description,
				Document:       pol.Default(),
				DefaultVersion: pol.DefaultVersion,
			},
			Status:     &iamv1.PolicyStatus{Observed: ready(pol.Generation), Arn: iam.PolicyARN(p.id, pol), UniqueId: pol.ID},
			CreateTime: ts(pol.Created),
			UpdateTime: ts(pol.Updated),
			DeleteTime: timestamppb.New(s.now()),
		}
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "DeletePolicy", requestID: req.GetRequestId(), req: req, resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE, generation: v.Object.Generation, response: resp})
	return op, toStatus(ctx, err)
}

// GetPolicyVersion returns one stored version.
func (s *Server) GetPolicyVersion(ctx context.Context, req *iamv1.GetPolicyVersionRequest) (*iamv1.PolicyVersion, error) {
	pid, id, ver, err := grandchild(req.GetName(), "policies", "versions")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	v, err := store.Get[iam.Policy](ctx, p.b, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	for _, pv := range v.Object.Versions {
		if pv.ID == ver {
			return p.versionProto(v, pv), nil
		}
	}
	return nil, toStatus(ctx, notFound("policy version "+quote(req.GetName())+" does not exist"))
}

// ListPolicyVersions lists a policy's versions (at most five).
func (s *Server) ListPolicyVersions(ctx context.Context, req *iamv1.ListPolicyVersionsRequest) (*iamv1.ListPolicyVersionsResponse, error) {
	pid, id, err := child(req.GetParent(), "policies")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	v, err := store.Get[iam.Policy](ctx, p.b, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	items, next, err := page(v.Object.Versions, func(pv iam.PolicyVersion) string { return pv.ID }, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListPolicyVersionsResponse{NextPageToken: next}
	for _, pv := range items {
		out.PolicyVersions = append(out.PolicyVersions, p.versionProto(v, pv))
	}
	return out, nil
}

// CreatePolicyVersion adds a version. Its id is assigned like AWS (v<n>);
// a non-empty policy_version_id must equal the next id.
func (s *Server) CreatePolicyVersion(ctx context.Context, req *iamv1.CreatePolicyVersionRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetParent(), "policies")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "CreatePolicyVersion", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	spec := req.GetPolicyVersion().GetSpec()
	if _, err := policy.ParseIdentity(spec.GetDocument()); err != nil {
		return nil, toStatus(ctx, err)
	}
	var added iam.PolicyVersion
	v, err := mutateOrValidate(ctx, p.b, id, "", req.GetValidateOnly(), false, bumpPolicy, func(pol *iam.Policy) error {
		if len(pol.Versions) >= iam.MaxPolicyVersions {
			return quota("a policy can have at most 5 versions")
		}
		next := pol.NextVersion
		if next == 0 {
			next = len(pol.Versions) + 1
		}
		added = iam.PolicyVersion{ID: "v" + strconv.Itoa(next), Document: spec.GetDocument(), Created: s.now().UTC()}
		if want := req.GetPolicyVersionId(); want != "" && want != added.ID {
			return invalidID("policy_version_id must be " + added.ID + " (assigned in order)")
		}
		pol.Versions = append(pol.Versions, added)
		pol.NextVersion = next + 1
		if spec.GetSetAsDefault() {
			pol.DefaultVersion = added.ID
		}
		pol.Updated = s.now().UTC()
		return pol.Validate()
	}, nil)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := p.versionProto(v, added)
	op, err := s.done(ctx, opArgs{project: pid, method: "CreatePolicyVersion", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_CREATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// DeletePolicyVersion deletes a non-default version.
func (s *Server) DeletePolicyVersion(ctx context.Context, req *iamv1.DeletePolicyVersionRequest) (*longrunningpb.Operation, error) {
	pid, id, ver, err := grandchild(req.GetName(), "policies", "versions")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "DeletePolicyVersion", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	var gone *iam.PolicyVersion
	v, _, err := update(ctx, p.b, id, req.GetEtag(), false, bumpPolicy, func(pol *iam.Policy) error {
		gone = nil
		kept := pol.Versions[:0:0]
		for _, pv := range pol.Versions {
			if pv.ID == ver {
				gone = &pv
				continue
			}
			kept = append(kept, pv)
		}
		switch {
		case gone == nil && req.GetAllowMissing():
			return errNoop
		case gone == nil:
			return notFound("policy version " + quote(req.GetName()) + " does not exist")
		case ver == pol.DefaultVersion:
			return deleteConflict("the default version cannot be deleted")
		}
		pol.Versions = kept
		pol.Updated = s.now().UTC()
		return nil
	}, nil)
	resp := &iamv1.PolicyVersion{Name: req.GetName()}
	switch {
	case errors.Is(err, errNoop):
	case err != nil:
		return nil, toStatus(ctx, err)
	default:
		resp = p.versionProto(v, *gone)
		resp.Status.DefaultVersion = false
		resp.DeleteTime = timestamppb.New(s.now())
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "DeletePolicyVersion", requestID: req.GetRequestId(), req: req, resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE, generation: v.Object.Generation, response: resp})
	return op, toStatus(ctx, err)
}
