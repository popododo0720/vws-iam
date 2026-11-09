package grpcapi

import (
	"context"
	"errors"
	"maps"
	"strconv"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// tagOIDCProvider is IAM TagOpenIDConnectProvider: it adds tags to the
// OpenID Connect provider arn names in project pid, overwriting the value
// of a key it already has.
//
// The ARN errors are those of getOIDCProvider. A request with no tag or
// more than 50 is ValidationError; a tag outside the AWS tag rules is
// InvalidInput, and of a key repeated in the request the last value is
// kept and counts once (as TagPolicy); all before any store access. An
// unknown provider is NoSuchEntity. A provider that would keep more than
// 50 tags is LimitExceeded and is not written. Tags the provider already
// has with those values write nothing, so a retry after a lost response
// succeeds unchanged. The write, the retries, a canceled request and a
// store failure are as in updateOIDCProviderThumbprint. Authorization
// (iam:TagOpenIDConnectProvider) is console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// TagOpenIDConnectProvider.
func (s *Server) tagOIDCProvider(ctx context.Context, pid, arn string, tags []*iamv1.Tag) error {
	p, url, err := s.oidcProviderArg(pid, arn)
	if err != nil {
		return err
	}
	if err := checkTagRequestTags(len(tags), iam.MaxOIDCProviderTags); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := iam.CheckTag(tag.GetKey(), tag.GetValue()); err != nil {
			return invalidInput(err.Error())
		}
	}
	err = s.changeOIDCProvider(ctx, p, url, noOIDCProvider(arn), func(op *iam.OIDCProvider) (bool, error) {
		merged := make(map[string]string, len(op.Tags)+len(tags))
		maps.Copy(merged, op.Tags)
		for _, tag := range tags {
			merged[tag.GetKey()] = tag.GetValue()
		}
		if len(merged) > iam.MaxOIDCProviderTags {
			return false, quota("Cannot exceed quota for TagsPerOpenIdConnectProvider: " +
				strconv.Itoa(iam.MaxOIDCProviderTags))
		}
		if maps.Equal(merged, op.Tags) {
			return false, nil
		}
		op.Tags = merged
		return true, nil
	})
	return readFailure(ctx, err)
}

// untagOIDCProvider is IAM UntagOpenIDConnectProvider: it removes the tag
// keys from the OpenID Connect provider arn names in project pid. A key
// the provider does not have is ignored.
//
// The ARN errors are those of getOIDCProvider. A request with no key or
// more than 50 is ValidationError and a key outside the AWS tag key rules
// InvalidInput, all before any store access. An unknown provider is
// NoSuchEntity. Keys the provider does not have write nothing, so a retry
// after a lost response succeeds unchanged. The write, the retries, a
// canceled request and a store failure are as in tagOIDCProvider.
// Authorization (iam:UntagOpenIDConnectProvider) is console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// UntagOpenIDConnectProvider.
func (s *Server) untagOIDCProvider(ctx context.Context, pid, arn string, keys []string) error {
	p, url, err := s.oidcProviderArg(pid, arn)
	if err != nil {
		return err
	}
	if err := checkTagRequestTags(len(keys), iam.MaxOIDCProviderTags); err != nil {
		return err
	}
	for _, key := range keys {
		if err := iam.CheckTagKey(key); err != nil {
			return invalidInput(err.Error())
		}
	}
	err = s.changeOIDCProvider(ctx, p, url, noOIDCProvider(arn), func(op *iam.OIDCProvider) (bool, error) {
		kept := maps.Clone(op.Tags)
		for _, key := range keys {
			delete(kept, key)
		}
		if len(kept) == len(op.Tags) {
			return false, nil
		}
		op.Tags = kept
		return true, nil
	})
	return readFailure(ctx, err)
}

// listOIDCProviderTags is IAM ListOpenIDConnectProviderTags: the tags of
// the OpenID Connect provider arn names in project pid, sorted by key in
// byte order (tag keys are case sensitive), in pages.
//
// The ARN errors are those of getOIDCProvider; a maxItems outside 1 to
// 1000 (0 means not set: the AWS default of 100) or a marker with a
// character outside [ -ÿ] is ValidationError and a marker this
// call did not return InvalidInput; all before any store access. An
// unknown provider is NoSuchEntity; an untagged provider is an empty page.
// A marker continues after the last key of the previous page, so every tag
// that exists for the whole listing is returned once even when tags change
// in between. A store failure is ServiceFailure (ServiceUnavailable when
// the store is unavailable). The call only reads. Authorization
// (iam:ListOpenIDConnectProviderTags) is console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// ListOpenIDConnectProviderTags.
func (s *Server) listOIDCProviderTags(
	ctx context.Context, pid, arn, marker string, maxItems int,
) (tagPage, error) {
	p, url, err := s.oidcProviderArg(pid, arn)
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
	cur, err := store.Get[iam.OIDCProvider](ctx, p.b, iam.OIDCProviderKey(url))
	if errors.Is(err, store.ErrNotFound) {
		return tagPage{}, noOIDCProvider(arn)
	}
	if err != nil {
		return tagPage{}, readFailure(ctx, err)
	}
	return pageTags(cur.Object.Tags, after, maxItems), nil
}
