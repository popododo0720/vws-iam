package grpcapi

import (
	"context"
	"maps"
	"strconv"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// tagSAMLProvider is IAM TagSAMLProvider: it adds tags to the SAML
// provider arn names in project pid, overwriting the value of a key it
// already has.
//
// The ARN errors are those of getSAMLProvider. A request with no tag or
// more than 50 is ValidationError; a tag outside the AWS tag rules is
// InvalidInput, and of a key repeated in the request the last value is
// kept and counts once (as TagPolicy); all before any store access. An
// unknown provider is NoSuchEntity. A provider that would keep more than
// 50 tags is LimitExceeded, and one whose stored encoding would pass
// iam.MaxSAMLProviderEncodedLen bytes InvalidInput; neither writes. Tags
// the provider already has with those values write nothing, so a retry
// after a lost response succeeds unchanged. The write is conditional on
// the version read: a provider written in between is read again, keeping
// that writer's change, up to maxDeleteAttempts, then
// ConcurrentModification. A request that was canceled or whose deadline
// passed writes nothing. A store failure is ServiceFailure
// (ServiceUnavailable when the store is unavailable), the fault AWS
// documents. Authorization (iam:TagSAMLProvider) is console-api's.
//
// TODO(#196): serve this as an RPC once vws-proto carries TagSAMLProvider.
func (s *Server) tagSAMLProvider(ctx context.Context, pid, arn string, tags []*iamv1.Tag) error {
	missing := noSAMLProvider(arn)
	p, name, err := s.samlProviderArg(pid, arn, missing)
	if err != nil {
		return err
	}
	if err := checkTagRequestTags(len(tags), iam.MaxSAMLProviderTags); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := iam.CheckTag(tag.GetKey(), tag.GetValue()); err != nil {
			return invalidInput(err.Error())
		}
	}
	_, err = s.changeSAMLProvider(ctx, p, name, missing, func(sp *iam.SAMLProvider) (bool, error) {
		merged := make(map[string]string, len(sp.Tags)+len(tags))
		maps.Copy(merged, sp.Tags)
		for _, tag := range tags {
			merged[tag.GetKey()] = tag.GetValue()
		}
		if len(merged) > iam.MaxSAMLProviderTags {
			return false, quota("Cannot exceed quota for TagsPerSAMLProvider: " + strconv.Itoa(iam.MaxSAMLProviderTags))
		}
		if maps.Equal(merged, sp.Tags) {
			return false, nil
		}
		sp.Tags = merged
		return true, nil
	})
	return readFailure(ctx, err)
}

// untagSAMLProvider is IAM UntagSAMLProvider: it removes the tag keys from
// the SAML provider arn names in project pid. A key the provider does not
// have is ignored.
//
// The ARN errors are those of getSAMLProvider. A request with no key or
// more than 50 is ValidationError and a key outside the AWS tag key rules
// InvalidInput, all before any store access. An unknown provider is
// NoSuchEntity. Keys the provider does not have write nothing, so a retry
// after a lost response succeeds unchanged. The write, the retries, a
// canceled request and a store failure are as in tagSAMLProvider.
// Authorization (iam:UntagSAMLProvider) is console-api's.
//
// TODO(#196): serve this as an RPC once vws-proto carries UntagSAMLProvider.
func (s *Server) untagSAMLProvider(ctx context.Context, pid, arn string, keys []string) error {
	missing := noSAMLProvider(arn)
	p, name, err := s.samlProviderArg(pid, arn, missing)
	if err != nil {
		return err
	}
	if err := checkTagRequestTags(len(keys), iam.MaxSAMLProviderTags); err != nil {
		return err
	}
	for _, key := range keys {
		if err := iam.CheckTagKey(key); err != nil {
			return invalidInput(err.Error())
		}
	}
	_, err = s.changeSAMLProvider(ctx, p, name, missing, func(sp *iam.SAMLProvider) (bool, error) {
		kept := maps.Clone(sp.Tags)
		for _, key := range keys {
			delete(kept, key)
		}
		if len(kept) == len(sp.Tags) {
			return false, nil
		}
		if len(kept) == 0 {
			kept = nil
		}
		sp.Tags = kept
		return true, nil
	})
	return readFailure(ctx, err)
}

// listSAMLProviderTags is IAM ListSAMLProviderTags: the tags of the SAML
// provider arn names in project pid, sorted by key in byte order (tag keys
// are case sensitive), in pages.
//
// The ARN errors are those of getSAMLProvider; a maxItems outside 1 to
// 1000 (0 means not set: the AWS default of 100) or a marker with a
// character outside [ -ÿ] is ValidationError and a marker this
// call did not return InvalidInput; all before any store access. An
// unknown provider is NoSuchEntity; an untagged provider is an empty
// page. A marker continues after the last key of the previous page, so
// every tag that exists for the whole listing is returned once even when
// tags change in between. A store failure is ServiceFailure
// (ServiceUnavailable when the store is unavailable). The call only
// reads. Authorization (iam:ListSAMLProviderTags) is console-api's.
//
// TODO(#196): serve this as an RPC once vws-proto carries ListSAMLProviderTags.
func (s *Server) listSAMLProviderTags(
	ctx context.Context, pid, arn, marker string, maxItems int,
) (tagPage, error) {
	missing := noSAMLProvider(arn)
	p, name, err := s.samlProviderArg(pid, arn, missing)
	if err != nil {
		return tagPage{}, err
	}
	maxItems, err = listPageSize(maxItems)
	if err != nil {
		return tagPage{}, err
	}
	after, err := decodeTagMarker(marker)
	if err != nil {
		return tagPage{}, err
	}
	cur, err := readSAMLProvider(ctx, p, name, missing)
	if err != nil {
		return tagPage{}, readFailure(ctx, err)
	}
	return pageTags(cur.Object.Tags, after, maxItems), nil
}
