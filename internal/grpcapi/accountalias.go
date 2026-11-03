package grpcapi

import (
	"context"
	"errors"
	"log/slog"
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

// aliasClaimLease is how long an account alias claim, from when its
// project last wrote it, keeps other projects from taking it over even
// though the project holds no alias of that name yet. The project writes
// its alias only within aliasClaimLease/2 of writing the claim, so the
// replicas' clocks may differ by up to aliasClaimLease/2.
const aliasClaimLease = 2 * MaxTimeout

// maxAliasClaimAttempts bounds how often a create rereads an account
// alias claim that changed under it before ConcurrentModification.
const maxAliasClaimAttempts = 8

// createAccountAlias is IAM CreateAccountAlias: it makes alias the
// account alias of project pid.
//
// A bad project id or an AccountAlias that is not 3 to 63 characters of
// ^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$ is ValidationError before
// any store access. An alias the project already holds is
// EntityAlreadyExists and changes nothing (but see the repeat below), so a retry after a lost
// response is EntityAlreadyExists and of racing creates of one alias
// exactly one succeeds. An alias another project holds (AWS: unique
// across accounts) is EntityAlreadyExists too.
//
// An account has one alias, and AWS overwrites the previous one, so a
// different alias of the project is deleted once the new one is stored:
// LimitExceeded, which AWS also documents, never applies. Which alias is
// the latest rests on stored state only, never on a replica clock: a
// create numbers its alias one past the greatest Seq the project has
// stored, so a create that starts after another returned replaces it. Of
// racing creates of different aliases in one project every one succeeds
// and exactly one stays (the greatest Seq, then name). A repeat of a
// stored alias first deletes any alias it replaced that a create stopped
// before deleting.
//
// Uniqueness across projects rests on one store create of the alias
// claim (iam.AccountAliasClaim). The project's alias is written only
// within aliasClaimLease/2 of the claim write, and a claim is taken over
// only when it is older than aliasClaimLease and its project holds no
// such alias, by a compare-and-swap on the claim; a claim that keeps
// changing is ConcurrentModification after maxAliasClaimAttempts. Both
// sides are fenced, so a write that outruns its window never leaves two
// projects holding the alias: the taker rereads the old project after
// its swap and hands the claim back if the alias is there, and the writer
// rereads the claim after storing the alias and deletes it again (the
// create is then EntityAlreadyExists) if the claim names another project. A
// claim outlives its alias (DeleteAccountAlias leaves it) and is taken
// over, never deleted, so a delete racing a create cannot drop the claim
// of a live alias. A canceled request writes nothing more. Any other
// store failure is an internal error, which console-api answers as
// ServiceFailure. Authorization (iam:CreateAccountAlias) is console-api's,
// as for the other IAM writes.
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
	taken := alreadyExists("The account alias " + alias + " already exists.")
	_, err := store.Get[iam.AccountAlias](ctx, p.b, alias)
	if err == nil {
		// Maybe the repeat of a create that stopped before it deleted the
		// alias it replaced: finish that first.
		p.dropReplacedAliases(ctx)
		return taken
	}
	if !errors.Is(err, store.ErrNotFound) {
		return toStatus(ctx, err)
	}
	wctx, cancel, err := s.claimAccountAlias(ctx, pid, alias, taken)
	if err != nil {
		return err
	}
	defer cancel()
	all, err := store.List[iam.AccountAlias](wctx, p.b)
	if err != nil {
		return toStatus(ctx, err)
	}
	a := iam.AccountAlias{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: alias, Created: p.now().UTC(),
		Seq: latestAlias(all).Seq + 1,
	}
	v, err := store.Create(wctx, p.b, a)
	if errors.Is(err, store.ErrExists) {
		return taken
	}
	if err != nil {
		return toStatus(ctx, err)
	}
	if err := s.fenceAccountAlias(ctx, p, alias, v, taken); err != nil {
		return err
	}
	p.dropReplacedAliases(ctx)
	return nil
}

// claimAccountAlias writes the claim of alias for pid: a new claim, a
// renewal of pid's own, or a takeover of a stale one; pid's own claim
// written within aliasClaimLease/4 is used as is, so racing creates in
// one project do not contend on it. It returns the context to write
// pid's alias under, which ends aliasClaimLease/2 after the claim was
// written, and taken if another project holds the alias.
func (s *Server) claimAccountAlias(
	ctx context.Context, pid, alias string, taken error,
) (context.Context, context.CancelFunc, error) {
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, toStatus(ctx, err) // the caller is gone; write nothing
		}
		// Every deadline counts from before the claim read, so a slow read
		// shortens the write window instead of moving it past the lease.
		start := time.Now()
		deadline := start.Add(aliasClaimLease / 2)
		now := s.now().UTC()
		c := iam.AccountAliasClaim{Name: alias, Project: pid, Claimed: now}
		cur, err := store.Get[iam.AccountAliasClaim](ctx, s.b, alias)
		switch {
		case errors.Is(err, store.ErrNotFound):
			_, err = store.Create(ctx, s.b, c)
		case err != nil:
			return nil, nil, toStatus(ctx, err)
		case cur.Object.Project != pid:
			held, herr := s.aliasHeld(ctx, cur.Object, now)
			if herr != nil {
				return nil, nil, toStatus(ctx, herr)
			}
			if held {
				return nil, nil, taken
			}
			var v string
			if v, err = store.Update(ctx, s.b, c, cur.Version); err == nil {
				if err := s.handBackIfHeld(ctx, cur.Object, v, taken); err != nil {
					return nil, nil, err
				}
			}
		case now.Before(cur.Object.Claimed.Add(aliasClaimLease / 4)):
			// pid's own claim, written recently: no other project can take
			// it before Claimed+aliasClaimLease, so write under it as is.
			left := cur.Object.Claimed.Add(aliasClaimLease / 2).Sub(now)
			wctx, cancel := context.WithDeadline(ctx, start.Add(left))
			return wctx, cancel, nil
		default:
			_, err = store.Update(ctx, s.b, c, cur.Version)
		}
		switch {
		case err == nil:
			wctx, cancel := context.WithDeadline(ctx, deadline)
			return wctx, cancel, nil
		case errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists):
			if attempt >= maxAliasClaimAttempts {
				return nil, nil, toStatus(ctx, store.ErrConflict)
			}
		default:
			return nil, nil, toStatus(ctx, err)
		}
	}
}

// aliasHeld reports whether claim c still holds its alias for its
// project at now: it was written within aliasClaimLease, or the project
// holds the alias.
func (s *Server) aliasHeld(ctx context.Context, c iam.AccountAliasClaim, now time.Time) (bool, error) {
	if now.Before(c.Claimed.Add(aliasClaimLease)) {
		return true, nil
	}
	_, err := store.Get[iam.AccountAlias](ctx, s.project(c.Project).b, c.Name)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// handBackIfHeld rechecks, after claim old was taken over at version v,
// that its project still holds no such alias. One the project stored
// while the claim was being taken (a write that outran its window) keeps
// the alias: old is written back and the create is taken.
func (s *Server) handBackIfHeld(ctx context.Context, old iam.AccountAliasClaim, v string, taken error) error {
	_, err := store.Get[iam.AccountAlias](ctx, s.project(old.Project).b, old.Name)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, uerr := store.Update(hctx, s.b, old, v); uerr != nil {
		slog.Default().LogAttrs(hctx, slog.LevelWarn, "account alias claim not handed back",
			slog.String("alias", old.Name), slog.String("error", uerr.Error()))
	}
	if err != nil {
		return toStatus(ctx, err)
	}
	return taken
}

// fenceAccountAlias fences alias, just stored for p at version v, against
// a takeover of its claim during the write: unless the claim still names
// p, the alias is deleted again and the create is taken (or failed, when
// the claim cannot be read). It runs even when the request is canceled.
func (s *Server) fenceAccountAlias(ctx context.Context, p project, alias, v string, taken error) error {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	c, err := store.Get[iam.AccountAliasClaim](fctx, s.b, alias)
	if err == nil && c.Object.Project == p.id {
		return nil
	}
	if derr := store.Delete[iam.AccountAlias](fctx, p.b, alias, v); derr != nil && !errors.Is(derr, store.ErrNotFound) {
		slog.Default().LogAttrs(fctx, slog.LevelWarn, "account alias stored under a lost claim not deleted",
			slog.String("project", p.id), slog.String("alias", alias), slog.String("error", derr.Error()))
	}
	if err != nil {
		return toStatus(fctx, err)
	}
	return taken
}

// latestAlias returns the alias of all that a create made last: the
// greatest Seq, then the greatest name, so racing creates agree on the
// alias that stays. It is the zero AccountAlias when all is empty.
func latestAlias(all []store.Versioned[iam.AccountAlias]) iam.AccountAlias {
	var keep iam.AccountAlias
	for _, v := range all {
		if a := v.Object; a.Seq > keep.Seq || a.Seq == keep.Seq && a.Name > keep.Name {
			keep = a
		}
	}
	return keep
}

// dropReplacedAliases deletes every alias of the project but the latest
// (latestAlias): AWS overwrites the previous alias. It runs even when the
// request is canceled, as the new alias is already stored. A delete that
// fails leaves an alias the next create of the project deletes; it does
// not fail the create, which has committed.
func (p project) dropReplacedAliases(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	all, err := store.List[iam.AccountAlias](ctx, p.b)
	if err != nil {
		slog.Default().LogAttrs(ctx, slog.LevelWarn, "replaced account alias left for the next create",
			slog.String("project", p.id), slog.String("error", err.Error()))
		return
	}
	keep := latestAlias(all)
	for _, v := range all {
		if v.Object.Name == keep.Name {
			continue
		}
		err := store.Delete[iam.AccountAlias](ctx, p.b, v.Object.Name, v.Version)
		if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
			slog.Default().LogAttrs(ctx, slog.LevelWarn, "replaced account alias left for the next create",
				slog.String("project", p.id), slog.String("alias", v.Object.Name), slog.String("error", err.Error()))
		}
	}
}
