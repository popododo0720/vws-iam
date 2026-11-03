package grpcapi

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// roleTag is one AWS Tag of a role.
type roleTag struct {
	Key   string
	Value string
}

// roleTagPage is one page of ListRoleTags. When IsTruncated is set,
// Marker continues the listing.
type roleTagPage struct {
	Tags        []roleTag
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
// IAM reads.
//
// TODO(#73): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#139); console-api dispatch is
// popododo0720/vws-console-api#558.
func (s *Server) listRoleTags(ctx context.Context, pid, roleName, marker string, maxItems int) (roleTagPage, error) {
	if !iam.ValidProject(pid) {
		return roleTagPage{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidName(roleName) {
		return roleTagPage{}, invalidSpec("roleName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	maxItems, err := listPageSize(maxItems)
	if err != nil {
		return roleTagPage{}, err
	}
	after, err := decodeTagMarker(marker)
	if err != nil {
		return roleTagPage{}, err
	}
	r, err := store.Get[iam.Role](ctx, s.project(pid).b, roleName)
	if errors.Is(err, store.ErrNotFound) {
		return roleTagPage{}, notFound("The role with name " + roleName + " cannot be found.")
	}
	if err != nil {
		return roleTagPage{}, readFailure(ctx, err)
	}
	keys := make([]string, 0, len(r.Object.Tags))
	for k := range r.Object.Tags {
		if after == "" || k > after {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var out roleTagPage
	if len(keys) > maxItems {
		keys = keys[:maxItems]
		out.IsTruncated = true
		out.Marker = base64.RawURLEncoding.EncodeToString([]byte(keys[maxItems-1]))
	}
	for _, k := range keys {
		out.Tags = append(out.Tags, roleTag{Key: k, Value: r.Object.Tags[k]})
	}
	return out, nil
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
