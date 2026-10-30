package grpcapi

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"sort"
	"strconv"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// DefaultTagPageSize is the AWS default MaxItems for ListPolicyTags.
const DefaultTagPageSize = 100

// MaxTagPageSize is the AWS maximum MaxItems for ListPolicyTags.
const MaxTagPageSize = 1000

// checkTagRequestTags checks the list a tag request carries: 1 to limit
// items. The array constraints are request validation, so AWS answers them
// as ValidationError, not InvalidInput.
func checkTagRequestTags(n, limit int) error {
	if n < 1 || n > limit {
		return invalidSpec("tags must have 1 to " + strconv.Itoa(limit) + " items")
	}
	return nil
}

// missingPolicy maps a missing policy to the AWS NoSuchEntity message. The
// requested name carries no path, so the ARN uses the default path.
func missingPolicy(ctx context.Context, err error, project, policy string) error {
	if errors.Is(err, store.ErrNotFound) {
		arn := iam.PolicyARN(project, iam.Policy{Name: policy})
		return toStatus(ctx, notFound("Policy "+arn+" does not exist or is not attachable."))
	}
	return toStatus(ctx, err)
}

// TagPolicy adds or overwrites tags on a managed policy. The request fails
// and stores nothing when one tag is invalid or the policy would keep more
// than 50 tags.
func (s *Server) TagPolicy(ctx context.Context, req *iamv1.TagPolicyRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "policies")
	if err != nil {
		return nil, err
	}
	tags := req.GetTags()
	if err := checkTagRequestTags(len(tags), iam.MaxPolicyTags); err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if err := iam.CheckTag(tag.GetKey(), tag.GetValue()); err != nil {
			return nil, invalidInput(err.Error())
		}
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "TagPolicy", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	v, err := mutateOrValidate(ctx, p.b, id, "", req.GetValidateOnly(), false, bumpPolicy, func(pol *iam.Policy) error {
		merged := make(map[string]string, len(pol.Tags)+len(tags))
		maps.Copy(merged, pol.Tags)
		for _, tag := range tags {
			merged[tag.GetKey()] = tag.GetValue()
		}
		if len(merged) > iam.MaxPolicyTags {
			return quota("Cannot exceed quota for TagsPerPolicy: " + strconv.Itoa(iam.MaxPolicyTags))
		}
		if maps.Equal(merged, pol.Tags) {
			return errNoop
		}
		pol.Tags = merged
		// AWS changes a policy's UpdateDate only for a new version, not for a tag change.
		return nil
	}, nil)
	if errors.Is(err, errNoop) {
		err = nil
	}
	if err != nil {
		return nil, missingPolicy(ctx, err, pid, id)
	}
	resp, err := p.policyProto(ctx, v)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	op, err := s.done(ctx, opArgs{
		project: pid, method: "TagPolicy", requestID: req.GetRequestId(), req: req, resource: resp.Name,
		verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation,
		response: resp, validateOnly: req.GetValidateOnly(),
	})
	return op, toStatus(ctx, err)
}

// UntagPolicy removes the named keys. A key that is not attached is ignored.
func (s *Server) UntagPolicy(ctx context.Context, req *iamv1.UntagPolicyRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "policies")
	if err != nil {
		return nil, err
	}
	keys := req.GetTagKeys()
	if err := checkTagRequestTags(len(keys), iam.MaxPolicyTags); err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := iam.CheckTagKey(key); err != nil {
			return nil, invalidInput(err.Error())
		}
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "UntagPolicy", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	v, err := mutateOrValidate(ctx, p.b, id, "", req.GetValidateOnly(), false, bumpPolicy, func(pol *iam.Policy) error {
		if len(pol.Tags) == 0 {
			return errNoop
		}
		kept := make(map[string]string, len(pol.Tags))
		maps.Copy(kept, pol.Tags)
		for _, key := range keys {
			delete(kept, key)
		}
		if maps.Equal(kept, pol.Tags) {
			return errNoop
		}
		pol.Tags = kept
		// AWS changes a policy's UpdateDate only for a new version, not for a tag change.
		return nil
	}, nil)
	if errors.Is(err, errNoop) {
		err = nil
	}
	if err != nil {
		return nil, missingPolicy(ctx, err, pid, id)
	}
	resp, err := p.policyProto(ctx, v)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	op, err := s.done(ctx, opArgs{
		project: pid, method: "UntagPolicy", requestID: req.GetRequestId(), req: req, resource: resp.Name,
		verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation,
		response: resp, validateOnly: req.GetValidateOnly(),
	})
	return op, toStatus(ctx, err)
}

// ListPolicyTags lists a policy's tags sorted by key and pages them.
func (s *Server) ListPolicyTags(
	ctx context.Context, req *iamv1.ListPolicyTagsRequest,
) (*iamv1.ListPolicyTagsResponse, error) {
	pid, id, err := child(req.GetName(), "policies")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	v, err := store.Get[iam.Policy](ctx, p.b, id)
	if err != nil {
		return nil, missingPolicy(ctx, err, pid, id)
	}
	keys := make([]string, 0, len(v.Object.Tags))
	for key := range v.Object.Tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	size := int(req.GetPageSize())
	switch {
	case size <= 0:
		size = DefaultTagPageSize
	case size > MaxTagPageSize:
		size = MaxTagPageSize
	}
	start := 0
	if token := req.GetPageToken(); token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return nil, invalidInput("page_token is not valid")
		}
		after := string(raw)
		start = sort.Search(len(keys), func(i int) bool { return keys[i] > after })
	}
	end := min(start+size, len(keys))
	out := &iamv1.ListPolicyTagsResponse{}
	if end < len(keys) {
		out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(keys[end-1]))
	}
	for _, key := range keys[start:end] {
		out.Tags = append(out.Tags, &iamv1.Tag{Key: key, Value: v.Object.Tags[key]})
	}
	return out, nil
}
