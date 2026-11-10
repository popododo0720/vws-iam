package grpcapi

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"slices"
	"strconv"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// awsTag is one AWS Tag.
type awsTag struct {
	Key   string
	Value string
}

// tagPage is one page of a tag listing (ListRoleTags,
// ListSAMLProviderTags). When IsTruncated is set, Marker continues the
// listing.
type tagPage struct {
	Tags        []awsTag
	IsTruncated bool
	Marker      string
}

// listRoleTags is IAM ListRoleTags: the tags of role roleName in project
// pid, sorted by key, in pages.
//
// A bad project id, a RoleName outside 1 to 64 characters of [\w+=,.@-],
// a maxItems outside 1 to 1000 (0 means not set: the AWS default of 100)
// or a marker with a character outside [\u0020-\u00FF] is
// ValidationError; a marker this call did not return is InvalidInput;
// all before any store access. An unknown role is NoSuchEntity (role
// names compare case-insensitively); an untagged role is an empty page.
// Any other store failure is ServiceFailure, the fault AWS documents.
//
// Keys sort by byte order, as tag keys are case sensitive, and a marker
// (the base64url of the last key of the previous page) continues after
// that key even when tags change in between: every tag that exists for
// the whole listing is returned once. The call only reads.
// Authorization (iam:ListRoleTags) is console-api's, as for the other
// IAM reads; its Query dispatch is popododo0720/vws-console-api#558.
func (s *Server) listRoleTags(ctx context.Context, pid, roleName, marker string, maxItems int) (tagPage, error) {
	if !iam.ValidProject(pid) {
		return tagPage{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidName(roleName) {
		return tagPage{}, invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	maxItems, err := listPageSize(maxItems)
	if err != nil {
		return tagPage{}, err
	}
	after, err := decodeTagMarker(marker)
	if err != nil {
		return tagPage{}, err
	}
	r, err := store.Get[iam.Role](ctx, s.project(pid).b, roleName)
	if errors.Is(err, store.ErrNotFound) {
		return tagPage{}, notFound("The role with name " + roleName + " cannot be found.")
	}
	if err != nil {
		return tagPage{}, readFailure(ctx, err)
	}
	return pageTags(r.Object.Tags, after, maxItems), nil
}

// ListRoleTags is IAM ListRoleTags over gRPC (#73): the tags of the role
// name names, through listRoleTags. page_size is MaxItems and page_token
// the Marker; next_page_token is set exactly when the page is truncated.
func (s *Server) ListRoleTags(
	ctx context.Context, req *iamv1.ListRoleTagsRequest,
) (*iamv1.ListRoleTagsResponse, error) {
	pid, id, err := child(req.GetName(), "roles")
	if err != nil {
		return nil, err
	}
	pg, err := s.listRoleTags(ctx, pid, id, req.GetPageToken(), int(req.GetPageSize()))
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListRoleTagsResponse{NextPageToken: pg.Marker}
	for _, tg := range pg.Tags {
		out.Tags = append(out.Tags, &iamv1.Tag{Key: tg.Key, Value: tg.Value})
	}
	return out, nil
}

// pageTags is the page of tags after key after (every key when ""),
// sorted by key in byte order, at most maxItems long; when more remain,
// its marker (the base64url of its last key) continues after that key.
func pageTags(tags map[string]string, after string, maxItems int) tagPage {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		if after == "" || k > after {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var out tagPage
	if len(keys) > maxItems {
		keys = keys[:maxItems]
		out.IsTruncated = true
		out.Marker = base64.RawURLEncoding.EncodeToString([]byte(keys[maxItems-1]))
	}
	for _, k := range keys {
		out.Tags = append(out.Tags, awsTag{Key: k, Value: tags[k]})
	}
	return out
}

// decodeTagMarker returns the tag key a tag listing marker continues
// after; "" for no marker. A marker outside the AWS pattern
// [\u0020-\u00FF]+ is ValidationError; one this service did not issue
// (not the base64url of a valid tag key) is InvalidInput.
func decodeTagMarker(marker string) (string, error) {
	if marker == "" {
		return "", nil
	}
	for _, c := range marker {
		if c < 0x20 || c > 0xFF {
			return "", invalidSpec("marker must be characters of [\\u0020-\\u00FF]")
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(marker)
	if err != nil || iam.CheckTagKey(string(raw)) != nil {
		return "", invalidInput("marker is not valid")
	}
	return string(raw), nil
}

// TagRole is IAM TagRole (#71): it adds tags to the role name names (any
// case), overwriting the value of a key the role already has. The role's
// other fields and its timestamps stay, as for TagPolicy.
//
// A bad name, project or RoleName, and no tag or more than 50 are
// ValidationError; a tag outside the AWS tag rules is InvalidInput, and of
// a key repeated in the request the last value is kept and counts once; all
// before any store access. An unknown role is NoSuchEntity. A role that
// would keep more than 50 tags is LimitExceeded and is not written. Tags the
// role already has write nothing; a request_id answers its first operation.
// Authorization (iam:TagRole) is console-api's; its Query dispatch is
// popododo0720/vws-console-api (#71 box 2).
func (s *Server) TagRole(ctx context.Context, req *iamv1.TagRoleRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "roles")
	if err != nil {
		return nil, err
	}
	if !iam.ValidName(id) {
		return nil, invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	tags := req.GetTags()
	if err := checkTagRequestTags(len(tags), iam.MaxRoleTags); err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if err := iam.CheckTag(tag.GetKey(), tag.GetValue()); err != nil {
			return nil, invalidInput(err.Error())
		}
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "TagRole", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	o := newOnce(pid, "TagRole", req.GetRequestId(), req)
	v, err := mutateOrValidate(ctx, p.b, id, "", o, req.GetValidateOnly(), false, bumpRole, func(r *iam.Role) error {
		merged := make(map[string]string, len(r.Tags)+len(tags))
		maps.Copy(merged, r.Tags)
		for _, tag := range tags {
			merged[tag.GetKey()] = tag.GetValue()
		}
		if len(merged) > iam.MaxRoleTags {
			return quota("Cannot exceed quota for TagsPerRole: " + strconv.Itoa(iam.MaxRoleTags))
		}
		if maps.Equal(merged, r.Tags) {
			return errNoop
		}
		r.Tags = merged
		return nil
	}, nil)
	if errors.Is(err, errApplied) {
		if op, err := s.applied(ctx, pid, "TagRole", req.GetRequestId(), req); op != nil || err != nil {
			return op, toStatus(ctx, err)
		}
		err = nil
	}
	switch {
	case err == nil, errors.Is(err, errNoop):
	case errors.Is(err, store.ErrNotFound):
		return nil, notFound("The role with name " + id + " cannot be found.")
	default:
		return nil, toStatus(ctx, err)
	}
	resp := p.roleProto(v)
	op, err := s.done(ctx, opArgs{
		project: pid, method: "TagRole", requestID: req.GetRequestId(), req: req, resource: resp.Name,
		verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation,
		response: resp, validateOnly: req.GetValidateOnly(),
	})
	return op, toStatus(ctx, err)
}
