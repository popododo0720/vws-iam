package grpcapi

import (
	"context"
	"errors"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// deleteAccountPasswordPolicy is IAM DeleteAccountPasswordPolicy: it
// deletes the custom password policy of project pid.
//
// A bad project id is ValidationError before any store access. A project
// without a custom policy is NoSuchEntity, so a repeat after success (or
// a retry after a lost response) is NoSuchEntity, as in AWS, and changes
// nothing. The delete is conditional on the version read: when the policy
// changes in between, it is read again, up to maxDeleteAttempts times,
// and then ConcurrentModification; a request that was canceled or whose
// deadline passed deletes nothing. LimitExceeded, which AWS also
// documents, never applies to a delete. Any other store failure is an
// internal error, which console-api answers as ServiceFailure.
// Authorization (iam:DeleteAccountPasswordPolicy) is console-api's, as
// for the other IAM writes.
//
// TODO(#84): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#134).
func (s *Server) deleteAccountPasswordPolicy(ctx context.Context, pid string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	p := s.project(pid)
	noPolicy := notFound("The Password Policy with domain name " + pid + " cannot be found.")
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.PasswordPolicy](ctx, p.b, iam.PasswordPolicyKey)
		if errors.Is(err, store.ErrNotFound) {
			return noPolicy
		}
		if err != nil {
			return toStatus(ctx, err)
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; delete nothing
		}
		err = store.Delete[iam.PasswordPolicy](ctx, p.b, iam.PasswordPolicyKey, cur.Version)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		case errors.Is(err, store.ErrNotFound):
			return noPolicy
		default:
			return toStatus(ctx, err)
		}
	}
}
