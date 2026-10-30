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

// missingMFADevice maps a missing device to the AWS NoSuchEntity message.
func missingMFADevice(ctx context.Context, err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return toStatus(ctx, notFound("The specified MFA device does not exist."))
	}
	return toStatus(ctx, err)
}

// bumpMfaDevice moves the generation only. AWS has no update time for a
// virtual MFA device, so a tag change leaves every stored timestamp alone.
func bumpMfaDevice(d *iam.MfaDevice) { d.Generation++ }

// TagMFADevice adds or overwrites tags on a virtual MFA device. The request
// fails and stores nothing when one tag is invalid or the device would keep
// more than 50 tags.
func (s *Server) TagMFADevice(ctx context.Context, req *iamv1.TagMFADeviceRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "mfaDevices")
	if err != nil {
		return nil, err
	}
	tags := req.GetTags()
	if err := checkTagRequestTags(len(tags), iam.MaxMFADeviceTags); err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if err := iam.CheckTag(tag.GetKey(), tag.GetValue()); err != nil {
			return nil, invalidInput(err.Error())
		}
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "TagMFADevice", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	v, err := mutateOrValidate(
		ctx, p.b, id, "", req.GetValidateOnly(), false, bumpMfaDevice, func(d *iam.MfaDevice) error {
			merged := make(map[string]string, len(d.Tags)+len(tags))
			maps.Copy(merged, d.Tags)
			for _, tag := range tags {
				merged[tag.GetKey()] = tag.GetValue()
			}
			if len(merged) > iam.MaxMFADeviceTags {
				return quota("Cannot exceed quota for TagsPerMfaDevice: " + strconv.Itoa(iam.MaxMFADeviceTags))
			}
			d.Tags = merged
			return nil
		}, nil)
	if err != nil {
		return nil, missingMFADevice(ctx, err)
	}
	resp := p.mfaProto(v.Object, v.Version)
	op, err := s.done(ctx, opArgs{
		project: pid, method: "TagMFADevice", requestID: req.GetRequestId(), req: req, resource: resp.Name,
		verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation,
		response: resp, validateOnly: req.GetValidateOnly(),
	})
	return op, toStatus(ctx, err)
}

// UntagMFADevice removes the named keys. A key that is not attached is
// ignored.
func (s *Server) UntagMFADevice(
	ctx context.Context, req *iamv1.UntagMFADeviceRequest,
) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "mfaDevices")
	if err != nil {
		return nil, err
	}
	keys := req.GetTagKeys()
	if err := checkTagRequestTags(len(keys), iam.MaxMFADeviceTags); err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := iam.CheckTagKey(key); err != nil {
			return nil, invalidInput(err.Error())
		}
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "UntagMFADevice", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	v, err := mutateOrValidate(
		ctx, p.b, id, "", req.GetValidateOnly(), false, bumpMfaDevice, func(d *iam.MfaDevice) error {
			if len(d.Tags) == 0 {
				return nil
			}
			kept := make(map[string]string, len(d.Tags))
			maps.Copy(kept, d.Tags)
			for _, key := range keys {
				delete(kept, key)
			}
			d.Tags = kept
			return nil
		}, nil)
	if err != nil {
		return nil, missingMFADevice(ctx, err)
	}
	resp := p.mfaProto(v.Object, v.Version)
	op, err := s.done(ctx, opArgs{
		project: pid, method: "UntagMFADevice", requestID: req.GetRequestId(), req: req, resource: resp.Name,
		verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation,
		response: resp, validateOnly: req.GetValidateOnly(),
	})
	return op, toStatus(ctx, err)
}

// ListMFADeviceTags lists a device's tags sorted by key and pages them.
func (s *Server) ListMFADeviceTags(
	ctx context.Context, req *iamv1.ListMFADeviceTagsRequest,
) (*iamv1.ListMFADeviceTagsResponse, error) {
	pid, id, err := child(req.GetName(), "mfaDevices")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	v, err := store.Get[iam.MfaDevice](ctx, p.b, id)
	if err != nil {
		return nil, missingMFADevice(ctx, err)
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
	out := &iamv1.ListMFADeviceTagsResponse{}
	if end < len(keys) {
		out.NextPageToken = base64.RawURLEncoding.EncodeToString([]byte(keys[end-1]))
	}
	for _, key := range keys[start:end] {
		out.Tags = append(out.Tags, &iamv1.Tag{Key: key, Value: v.Object.Tags[key]})
	}
	return out, nil
}
