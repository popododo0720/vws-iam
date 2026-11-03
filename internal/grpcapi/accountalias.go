package grpcapi

import (
	"context"
	"errors"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// accountAliasPage is one page of ListAccountAliases: the aliases of the
// account, in name order (AWS allows one, so at most one in practice).
// When IsTruncated is set, Marker continues the listing.
type accountAliasPage struct {
	Aliases     []string
	IsTruncated bool
	Marker      string
}

// listAccountAliases is IAM ListAccountAliases: the account aliases of
// project pid, in pages.
//
// A bad project id, a maxItems outside 1 to 1000 (0 means not set: the
// AWS default of 100) or a marker with a character outside
// [\u0020-\u00FF] is ValidationError, all before any store access. A
// marker this call did not return is InvalidInput, as for
// ListInstanceProfiles. A project without an alias is an empty, complete
// page. Any store failure is an internal error, which console-api answers
// as ServiceFailure, the one error AWS documents here.
//
// Aliases are ordered by name (aliases are lowercase, so this is the
// case-folded order the shared page helpers use), and a marker (the last
// alias of the previous page) continues after it even when aliases change
// in between. The call only reads; creating and deleting an alias are #88
// and #89. Authorization (iam:ListAccountAliases) is console-api's, as
// for the other IAM reads.
//
// TODO(#90): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#127).
func (s *Server) listAccountAliases(ctx context.Context, pid, marker string, maxItems int) (accountAliasPage, error) {
	if !iam.ValidProject(pid) {
		return accountAliasPage{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	maxItems, err := listPageSize(maxItems)
	if err != nil {
		return accountAliasPage{}, err
	}
	after, err := decodeNameMarker(marker, iam.ValidAccountAlias)
	if err != nil {
		return accountAliasPage{}, err
	}
	all, err := store.List[iam.AccountAlias](ctx, s.project(pid).b)
	if err != nil {
		return accountAliasPage{}, toStatus(ctx, err)
	}
	var names []string
	for _, v := range all {
		if n := v.Object.Name; after == "" || store.Fold(n) > after {
			names = append(names, n)
		}
	}
	var out accountAliasPage
	out.Aliases, out.IsTruncated, out.Marker = pageByFoldedName(names, func(n string) string { return n }, maxItems)
	return out, nil
}

// deleteAccountAlias is IAM DeleteAccountAlias: it deletes account alias
// alias of project pid.
//
// A bad project id or an AccountAlias that is not 3 to 63 characters of
// ^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$ is ValidationError before any
// store access. An alias the project does not hold (also one another
// project holds) is NoSuchEntity, so a retry after a lost response is
// NoSuchEntity, as in AWS, and changes nothing. The delete is conditional
// on the version read: when the alias changes in between, it is read
// again, up to maxDeleteAttempts times, and then ConcurrentModification;
// a request that was canceled or whose deadline passed deletes nothing.
// LimitExceeded, which AWS also documents, never applies: a delete frees
// quota. Any other store failure is an internal error, which console-api
// answers as ServiceFailure. Authorization (iam:DeleteAccountAlias) is
// console-api's, as for the other IAM writes.
//
// TODO(#89): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#128).
func (s *Server) deleteAccountAlias(ctx context.Context, pid, alias string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidAccountAlias(alias) {
		return invalidSpec("accountAlias must be 3 to 63 lowercase letters, digits and hyphens, " +
			"without a hyphen at either end or two in a row")
	}
	p := s.project(pid)
	noAlias := notFound("The account alias " + alias + " cannot be found.")
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.AccountAlias](ctx, p.b, alias)
		if errors.Is(err, store.ErrNotFound) {
			return noAlias
		}
		if err != nil {
			return toStatus(ctx, err)
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; delete nothing
		}
		err = store.Delete[iam.AccountAlias](ctx, p.b, alias, cur.Version)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		case errors.Is(err, store.ErrNotFound):
			return noAlias
		default:
			return toStatus(ctx, err)
		}
	}
}
