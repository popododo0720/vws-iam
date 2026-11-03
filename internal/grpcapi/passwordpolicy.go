package grpcapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// noPasswordPolicy is the AWS NoSuchEntity of an account without a
// custom password policy.
func noPasswordPolicy(pid string) error {
	return notFound("The Password Policy with domain name " + pid + " cannot be found.")
}

// accountPasswordPolicy is the GetAccountPasswordPolicy response, the AWS
// PasswordPolicy data type. MaxPasswordAge and PasswordReusePrevention
// are nil when not set (AWS leaves them out; their valid range starts at
// 1), and ExpirePasswords is true exactly when MaxPasswordAge is above 0.
type accountPasswordPolicy struct {
	MinimumPasswordLength      int
	RequireSymbols             bool
	RequireNumbers             bool
	RequireUppercaseCharacters bool
	RequireLowercaseCharacters bool
	AllowUsersToChangePassword bool
	ExpirePasswords            bool
	MaxPasswordAge             *int
	PasswordReusePrevention    *int
	HardExpiry                 bool
}

// awsPasswordPolicy returns p in the AWS response shape.
func awsPasswordPolicy(p iam.PasswordPolicy) accountPasswordPolicy {
	out := accountPasswordPolicy{
		MinimumPasswordLength:      p.MinimumPasswordLength,
		RequireSymbols:             p.RequireSymbols,
		RequireNumbers:             p.RequireNumbers,
		RequireUppercaseCharacters: p.RequireUppercaseCharacters,
		RequireLowercaseCharacters: p.RequireLowercaseCharacters,
		AllowUsersToChangePassword: p.AllowUsersToChangePassword,
		ExpirePasswords:            p.MaxPasswordAge > 0,
		HardExpiry:                 p.HardExpiry,
	}
	if p.MaxPasswordAge > 0 {
		out.MaxPasswordAge = &p.MaxPasswordAge
	}
	if p.PasswordReusePrevention > 0 {
		out.PasswordReusePrevention = &p.PasswordReusePrevention
	}
	return out
}

// getAccountPasswordPolicy is IAM GetAccountPasswordPolicy: it returns the
// custom password policy of project pid.
//
// A bad project id is ValidationError before any store access. A project
// without a custom policy is NoSuchEntity ("The Password Policy with
// domain name <project> cannot be found."), as in AWS. The read writes
// nothing, so a repeat returns the same policy until it is changed. A
// request that was canceled or whose deadline passed reads nothing. Any
// other store failure is an internal error, which console-api answers as
// ServiceFailure. Authorization (iam:GetAccountPasswordPolicy) is
// console-api's, as for the other IAM reads.
//
// TODO(#82): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#136).
func (s *Server) getAccountPasswordPolicy(ctx context.Context, pid string) (accountPasswordPolicy, error) {
	if !iam.ValidProject(pid) {
		return accountPasswordPolicy{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if err := ctx.Err(); err != nil {
		return accountPasswordPolicy{}, toStatus(ctx, err)
	}
	cur, err := store.Get[iam.PasswordPolicy](ctx, s.project(pid).b, iam.PasswordPolicyKey)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return accountPasswordPolicy{}, noPasswordPolicy(pid)
	case err != nil:
		return accountPasswordPolicy{}, toStatus(ctx, err)
	}
	return awsPasswordPolicy(cur.Object), nil
}

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
	noPolicy := noPasswordPolicy(pid)
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

// maxPutAttempts bounds how often updateAccountPasswordPolicy reads the
// policy again after a concurrent write before ConcurrentModification.
const maxPutAttempts = 8

// passwordPolicyInput is the UpdateAccountPasswordPolicy request. A nil
// integer is a parameter the caller left out; an omitted boolean is false.
// AWS has no partial update: every omitted parameter takes its default.
type passwordPolicyInput struct {
	MinimumPasswordLength      *int
	RequireSymbols             bool
	RequireNumbers             bool
	RequireUppercaseCharacters bool
	RequireLowercaseCharacters bool
	AllowUsersToChangePassword bool
	MaxPasswordAge             *int
	PasswordReusePrevention    *int
	HardExpiry                 bool
}

// policy returns the password policy in requests, with the AWS default
// for every omitted parameter: a minimum length of 6, no maximum age and
// no reuse prevention. An explicit value outside its AWS range, including
// an explicit 0 for MaxPasswordAge or PasswordReusePrevention whose
// default can only be had by omitting them, is ValidationError.
func (in passwordPolicyInput) policy() (iam.PasswordPolicy, error) {
	p := iam.PasswordPolicy{
		MinimumPasswordLength:      iam.MinPasswordLength,
		RequireSymbols:             in.RequireSymbols,
		RequireNumbers:             in.RequireNumbers,
		RequireUppercaseCharacters: in.RequireUppercaseCharacters,
		RequireLowercaseCharacters: in.RequireLowercaseCharacters,
		AllowUsersToChangePassword: in.AllowUsersToChangePassword,
		HardExpiry:                 in.HardExpiry,
	}
	for _, f := range []struct {
		name     string
		v        *int
		min, max int
		dst      *int
	}{
		{
			"minimumPasswordLength", in.MinimumPasswordLength,
			iam.MinPasswordLength, iam.MaxPasswordLength, &p.MinimumPasswordLength,
		},
		{"maxPasswordAge", in.MaxPasswordAge, 1, iam.MaxPasswordAgeDays, &p.MaxPasswordAge},
		{
			"passwordReusePrevention", in.PasswordReusePrevention,
			1, iam.MaxPasswordReusePrevention, &p.PasswordReusePrevention,
		},
	} {
		if f.v == nil {
			continue
		}
		switch {
		case *f.v < f.min:
			return p, rangeError(*f.v, f.name, "greater than or equal to", f.min)
		case *f.v > f.max:
			return p, rangeError(*f.v, f.name, "less than or equal to", f.max)
		}
		*f.dst = *f.v
	}
	return p, nil
}

// rangeError is the AWS ValidationError of an integer parameter outside
// its range.
func rangeError(v int, param, rel string, bound int) error {
	return invalidSpec(fmt.Sprintf(
		"1 validation error detected: Value '%d' at '%s' failed to satisfy constraint: Member must have value %s %d",
		v, param, rel, bound))
}

// samePasswordPolicy reports whether a and b set the same rules.
func samePasswordPolicy(a, b iam.PasswordPolicy) bool {
	return a.MinimumPasswordLength == b.MinimumPasswordLength &&
		a.RequireSymbols == b.RequireSymbols &&
		a.RequireNumbers == b.RequireNumbers &&
		a.RequireUppercaseCharacters == b.RequireUppercaseCharacters &&
		a.RequireLowercaseCharacters == b.RequireLowercaseCharacters &&
		a.AllowUsersToChangePassword == b.AllowUsersToChangePassword &&
		a.MaxPasswordAge == b.MaxPasswordAge &&
		a.PasswordReusePrevention == b.PasswordReusePrevention &&
		a.HardExpiry == b.HardExpiry
}

// updateAccountPasswordPolicy is IAM UpdateAccountPasswordPolicy: it sets
// the custom password policy of project pid to in, creating it when the
// account has none.
//
// A bad project id or a parameter outside its AWS range is
// ValidationError before any store access. Every omitted parameter takes
// its AWS default, so the stored policy is exactly the request and a
// repeat (or a retry after a lost response) stores the same policy; a
// request that changes nothing writes nothing. The write is conditional on
// the version read (or on there being none): when the policy changes in
// between, it is read again, up to maxPutAttempts times, and then
// ConcurrentModification; a request that was canceled or whose deadline
// passed writes nothing. NoSuchEntity, LimitExceeded and
// MalformedPolicyDocument, which AWS also documents, never apply: the
// account always exists and the request carries no policy document. Any
// other store failure is an internal error, which console-api answers as
// ServiceFailure. Authorization (iam:UpdateAccountPasswordPolicy) is
// console-api's, as for the other IAM writes.
//
// TODO(#83): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#135).
func (s *Server) updateAccountPasswordPolicy(ctx context.Context, pid string, in passwordPolicyInput) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	want, err := in.policy()
	if err != nil {
		return err
	}
	p := s.project(pid)
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.PasswordPolicy](ctx, p.b, iam.PasswordPolicyKey)
		found := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return toStatus(ctx, err)
		}
		if found && samePasswordPolicy(cur.Object, want) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; write nothing
		}
		next := want
		next.Updated = s.now().UTC()
		if found {
			next.UID, next.Generation, next.Labels = cur.Object.UID, cur.Object.Generation+1, cur.Object.Labels
			_, err = store.Update(ctx, p.b, next, cur.Version)
		} else {
			next.UID, next.Generation = iam.NewUID(), 1
			_, err = store.Create(ctx, p.b, next)
		}
		// A lost create (ErrExists), a stale version (ErrConflict) or a
		// policy deleted in between (ErrNotFound) is read again.
		raced := errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) ||
			errors.Is(err, store.ErrNotFound)
		switch {
		case err == nil:
			return nil
		case raced && attempt < maxPutAttempts:
			continue
		case raced:
			return toStatus(ctx, store.ErrConflict)
		default:
			return toStatus(ctx, err)
		}
	}
}
