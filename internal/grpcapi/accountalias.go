package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"time"

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
// case-folded order the shared page helpers use), and a marker from a previous release continues after that name.
// Only the latest held alias (Seq, then name) is visible, even if a
// stopped create left older held records behind. The call only reads; creating and deleting an alias are #88
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
	latest, err := s.latestAccountAlias(ctx, pid)
	if err != nil {
		return accountAliasPage{}, toStatus(ctx, err)
	}
	var names []string
	if latest.UID != "" && (after == "" || store.Fold(latest.Name) > after) {
		names = []string{latest.Name}
	}
	var out accountAliasPage
	out.Aliases, out.IsTruncated, out.Marker = pageByFoldedName(names, func(n string) string { return n }, maxItems)
	return out, nil
}

// latestAccountAlias returns the alias project pid exposes: its latest
// held alias (aliasBefore), or a zero alias when it holds none. An older
// held alias is one a stopped create left behind; an unheld one is a
// create's that never won the claim.
func (s *Server) latestAccountAlias(ctx context.Context, pid string) (iam.AccountAlias, error) {
	all, err := store.List[iam.AccountAlias](ctx, s.project(pid).b)
	if err != nil {
		return iam.AccountAlias{}, err
	}
	var latest iam.AccountAlias
	for _, v := range all {
		held, err := s.holdsAccountAlias(ctx, pid, v.Object)
		if err != nil {
			return iam.AccountAlias{}, err
		}
		if held && (latest.UID == "" || aliasBefore(latest, v.Object)) {
			latest = v.Object
		}
	}
	return latest, nil
}

// deleteAccountAlias is IAM DeleteAccountAlias: it deletes account alias
// alias of project pid.
//
// A bad project id or an AccountAlias that is not 3 to 63 characters of
// ^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$ is ValidationError before any
// store access. An alias the project does not hold (also one another
// project holds) is NoSuchEntity, so a retry after a lost response is
// NoSuchEntity, as in AWS, and changes nothing. So is an older alias a
// stopped create left held, which ListAccountAliases hides; deleting the
// listed alias first deletes those (dropOlderAliases), so none of them
// is listed after it. The delete is conditional
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
		latest, err := s.latestAccountAlias(ctx, pid)
		if err != nil {
			return toStatus(ctx, err)
		}
		if latest.UID != cur.Object.UID {
			return noAlias // unclaimed, or hidden behind a later held alias
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; delete nothing
		}
		if err := s.dropOlderAliases(ctx, p); err != nil {
			return toStatus(ctx, err) // a repeat drops them
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

// maxAliasClaimAttempts bounds how often a create rereads an account
// alias claim that changed under it, or stages again an alias of its
// project that vanished under it, before ConcurrentModification.
const maxAliasClaimAttempts = 8

// createAccountAlias is IAM CreateAccountAlias: it makes alias the
// account alias of project pid.
//
// A bad project id or an AccountAlias that is not 3 to 63 characters of
// ^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$ is ValidationError before
// any store access. The alias claim (iam.AccountAliasClaim, outside any
// project, keyed by the alias) points at one stored alias by project and
// UID; a project holds an alias only while the claim points at it. A
// create stores its alias, then points the claim at it by one store
// create or compare-and-swap, taking it from another project only when
// it no longer points at an alias that project stores. Only the create
// that writes the claim succeeds; others are EntityAlreadyExists (an
// alias held by this or another project, AWS: unique across accounts).
// So two projects never hold one alias, of racing creates of one alias
// exactly one succeeds, and an alias stored by a create that failed or
// lost its response is held by no project until a repeat claims it.
//
// AWS overwrites the previous alias: once a create holds its alias, every
// alias of the project before the latest held one (by Seq, then name,
// never a replica clock) is deleted before it returns, so LimitExceeded
// never applies; if that fails, the create fails and its repeat deletes
// them. A
// claim that keeps changing is ConcurrentModification; a canceled request
// writes nothing more; any other store failure is an internal error
// (console-api: ServiceFailure). Authorization is console-api's.
//
// TODO(#88): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#130).
func (s *Server) createAccountAlias(ctx context.Context, pid, alias string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidAccountAlias(alias) {
		return invalidSpec("accountAlias must be 3 to 63 lowercase letters, digits and hyphens, " +
			"without a hyphen at either end or two in a row")
	}
	p := s.project(pid)
	a, err := s.storeAccountAlias(ctx, p, alias)
	if err != nil {
		return err
	}
	held, wrote, err := s.claimAccountAlias(ctx, pid, a)
	if err != nil {
		return err
	}
	if held {
		if err := s.dropOlderAliases(ctx, p); err != nil {
			return toStatus(ctx, err) // a repeat of this create drops them
		}
	}
	if !wrote {
		return alreadyExists("The account alias " + alias + " already exists.")
	}
	return nil
}

// storeAccountAlias returns the stored alias of p named alias, creating
// it one past the greatest Seq of p. Reclaiming an unheld record advances
// its sequence by CAS; a held alias is unchanged. A create of p that loses
// the claim drops the alias it stored, so between this call's create
// (ErrExists) and its next read the alias can be gone again. Each such
// round means another create of p has finished, so the read and the create
// are tried again, up to maxAliasClaimAttempts rounds, before
// ConcurrentModification (#272).
func (s *Server) storeAccountAlias(
	ctx context.Context, p project, alias string,
) (store.Versioned[iam.AccountAlias], error) {
	for range maxAliasClaimAttempts {
		cur, err := store.Get[iam.AccountAlias](ctx, p.b, alias)
		exists := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return cur, toStatus(ctx, err)
		}
		if exists {
			held, err := s.holdsAccountAlias(ctx, p.id, cur.Object)
			if err != nil || held {
				return cur, toStatus(ctx, err)
			}
		}
		if err := ctx.Err(); err != nil {
			return cur, toStatus(ctx, err) // the caller is gone; write nothing
		}
		all, err := store.List[iam.AccountAlias](ctx, p.b)
		if err != nil {
			return cur, toStatus(ctx, err)
		}
		var seq int64
		for _, v := range all {
			seq = max(seq, v.Object.Seq)
		}
		if seq == math.MaxInt64 {
			return cur, toStatus(ctx, store.ErrConflict)
		}
		a := iam.AccountAlias{
			Meta: iam.Meta{UID: iam.NewUID(), Generation: 1},
			Name: alias, Created: p.now().UTC(), Seq: seq + 1,
		}
		var v string
		if exists {
			a = cur.Object
			a.Seq = seq + 1
			a.Generation++
			v, err = store.Update(ctx, p.b, a, cur.Version)
		} else {
			v, err = store.Create(ctx, p.b, a)
		}
		if !errors.Is(err, store.ErrExists) && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
			return store.Versioned[iam.AccountAlias]{Object: a, Version: v}, toStatus(ctx, err)
		}
	}
	return store.Versioned[iam.AccountAlias]{}, toStatus(ctx, store.ErrConflict)
}

// claimAccountAlias points the claim of a, stored for pid, at a: held
// reports whether it points at a, wrote whether this call made it. On a
// loss, a is deleted once, best effort, only while the claim is unchanged.
func (s *Server) claimAccountAlias(
	ctx context.Context, pid string, a store.Versioned[iam.AccountAlias],
) (held, wrote bool, err error) {
	mine := iam.AccountAliasClaim{Name: a.Object.Name, Project: pid, UID: a.Object.UID}
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return false, false, toStatus(ctx, err) // the caller is gone; write nothing more
		}
		cur, err := store.Get[iam.AccountAliasClaim](ctx, s.b, mine.Name)
		switch {
		case errors.Is(err, store.ErrNotFound):
			_, err = store.Create(ctx, s.b, mine)
		case err != nil:
			return false, false, toStatus(ctx, err)
		case cur.Object == mine:
			return true, false, nil
		default:
			c := cur.Object
			var other store.Versioned[iam.AccountAlias]
			other, err = store.Get[iam.AccountAlias](ctx, s.project(c.Project).b, c.Name)
			switch {
			case errors.Is(err, store.ErrNotFound) || err == nil && other.Object.UID != c.UID:
				_, err = store.Update(ctx, s.b, mine, cur.Version) // the claim points at no alias
			case err != nil:
				return false, false, toStatus(ctx, err)
			default: // unscoped: a project view would prefix the claim key too
				err = store.DeleteIf[iam.AccountAlias](ctx, s.b, pid+"/"+c.Name, a.Version, store.PreOf(cur))
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					slog.Default().LogAttrs(ctx, slog.LevelWarn, "unclaimed account alias left",
						slog.String("project", pid), slog.String("alias", c.Name), slog.String("error", err.Error()))
				}
				return false, false, nil
			}
		}
		switch {
		case err == nil:
			return true, true, nil
		case errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists):
			if attempt >= maxAliasClaimAttempts {
				return false, false, toStatus(ctx, store.ErrConflict)
			}
		default:
			return false, false, toStatus(ctx, err)
		}
	}
}

// holdsAccountAlias reports whether the claim of stored alias a of
// project pid points at it.
func (s *Server) holdsAccountAlias(ctx context.Context, pid string, a iam.AccountAlias) (bool, error) {
	c, err := store.Get[iam.AccountAliasClaim](ctx, s.b, a.Name)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil && c.Object.Project == pid && c.Object.UID == a.UID, err
}

// dropOlderAliases deletes every alias of p before its latest held one
// (aliasBefore), so p never ends without one. It runs even when the
// request is canceled. On a failure some may be left: the create fails,
// and its repeat (the alias is held then) drops them.
func (s *Server) dropOlderAliases(ctx context.Context, p project) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	all, err := store.List[iam.AccountAlias](ctx, p.b)
	var keep iam.AccountAlias
	for _, v := range all {
		held, herr := s.holdsAccountAlias(ctx, p.id, v.Object)
		if herr != nil {
			err = herr
		} else if held && !aliasBefore(v.Object, keep) {
			keep = v.Object
		}
	}
	for _, v := range all {
		if err == nil && keep.UID != "" && aliasBefore(v.Object, keep) {
			if err = store.Delete[iam.AccountAlias](ctx, p.b, v.Object.Name, v.Version); errors.Is(err, store.ErrNotFound) {
				err = nil
			}
		}
	}
	return err
}

// aliasBefore orders aliases by Seq, then name.
func aliasBefore(a, b iam.AccountAlias) bool {
	return a.Seq < b.Seq || a.Seq == b.Seq && a.Name < b.Name
}
