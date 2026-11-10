package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// tagUser is IAM TagUser: it adds tags to user userName in project pid,
// overwriting the value of a key the user already has. The user, its
// policies, groups and credentials stay.
//
// A bad project, a UserName outside 1 to 64 characters of [\w+=,.@-] and a
// request with no tag or more than 50 are ValidationError; a tag outside the
// AWS tag rules is InvalidInput, and of a key repeated in the request the
// last value is kept and counts once (as TagPolicy); all before any store
// access. An unknown user is NoSuchEntity. A user that would keep more than
// 50 tags is LimitExceeded and is not written. Tags the user already has
// with those values write nothing, so a retry after a lost response
// succeeds unchanged. A user being renamed is frozen and keeps its tags
// (ConcurrentModification, as for UpdateUser). The write goes through
// store.Mutate, so a user changed in between is read again, never written
// from a stale copy; a canceled request writes nothing.
// Authorization (iam:TagUser) is console-api's, as for UpdateUser.
//
// TODO(#68): serve this as UserService.TagUser once vws-proto carries it.
func (s *Server) tagUser(ctx context.Context, pid, userName string, tags []*iamv1.Tag) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidName(userName) {
		return invalidSpec("userName must be 1 to 64 characters of [\\w+=,.@-]")
	}
	if err := checkTagRequestTags(len(tags), iam.MaxUserTags); err != nil {
		return err
	}
	for _, tag := range tags {
		if err := iam.CheckTag(tag.GetKey(), tag.GetValue()); err != nil {
			return invalidInput(err.Error())
		}
	}
	_, err := store.Mutate(ctx, s.project(pid).b, userName, func(u *iam.User) error {
		merged := make(map[string]string, len(u.Tags)+len(tags))
		maps.Copy(merged, u.Tags)
		for _, tag := range tags {
			merged[tag.GetKey()] = tag.GetValue()
		}
		if len(merged) > iam.MaxUserTags {
			return quota("Cannot exceed quota for TagsPerUser: " + strconv.Itoa(iam.MaxUserTags))
		}
		if maps.Equal(merged, u.Tags) {
			return errNoop
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("tag user %q: %w", u.Name, err) // the caller is gone; write nothing
		}
		u.Tags = merged
		bumpUser(u)
		u.Updated = s.now().UTC()
		return nil
	})
	switch {
	case err == nil, errors.Is(err, errNoop):
		return nil
	case errors.Is(err, store.ErrNotFound):
		return notFound("The user with name " + userName + " cannot be found.")
	default:
		return toStatus(ctx, err)
	}
}
