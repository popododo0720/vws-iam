package grpcapi

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// maxMemberAttempts bounds how often one member-adding group write waits
// for the membership lock or retries a lost commit (about 12 s at the
// 32 ms backoff cap).
const maxMemberAttempts = 400

func groupsPerUserExceeded() error {
	return quota(fmt.Sprintf("Cannot exceed quota for GroupsPerUser: %d", iam.MaxGroupsPerUser))
}

// addedMembers returns the members of next that are not in prev. Names
// are case-insensitive.
func addedMembers(prev, next []string) []string {
	had := make(map[string]bool, len(prev))
	for _, m := range prev {
		had[store.Fold(m)] = true
	}
	var out []string
	for _, m := range next {
		if !had[store.Fold(m)] {
			out = append(out, m)
		}
	}
	return out
}

// checkGroupsPerUser refuses users that are already members of
// MaxGroupsPerUser groups other than group.
func (p project) checkGroupsPerUser(ctx context.Context, group string, users []string) error {
	if len(users) == 0 {
		return nil
	}
	want := make(map[string]int, len(users))
	for _, u := range users {
		want[store.Fold(u)] = 0
	}
	all, err := store.List[iam.Group](ctx, p.b)
	if err != nil {
		return err
	}
	for _, g := range store.Visible(all) {
		if store.Fold(g.Object.Name) == store.Fold(group) {
			continue
		}
		for _, m := range g.Object.Members {
			n, ok := want[store.Fold(m)]
			if !ok {
				continue
			}
			if n+1 >= iam.MaxGroupsPerUser {
				return groupsPerUserExceeded()
			}
			want[store.Fold(m)] = n + 1
		}
	}
	return nil
}

// checkMembers runs under the membership lock: every added user must
// still exist and have no rename in flight. A rename takes the lock after
// it marks the user (renameUser), so an add that read the user before the
// mark either commits before the rename moves the group references or
// sees the mark here (#134).
func (p project) checkMembers(ctx context.Context, users []string) error {
	for _, n := range users {
		u, err := store.Get[iam.User](ctx, p.b, n)
		if errors.Is(err, store.ErrNotFound) {
			return notFound("user " + quote(n) + " does not exist")
		}
		if err != nil {
			return err
		}
		if u.Object.Renaming() {
			return fmt.Errorf("user %q: %w", n, store.ErrRenaming)
		}
	}
	return nil
}

// membershipLease is how long a member add holds the project's
// membership lock. It bounds how long a crashed writer blocks other adds;
// correctness does not depend on it.
const membershipLease = 10 * time.Second

// lockMembership takes the project's membership lock and returns the
// precondition that nobody took it since, and a release. A lock held by
// another live writer is waited for, not taken. Access key creates take
// the same lock for the AccessKeysPerUser count (createKey).
func (p project) lockMembership(ctx context.Context) (store.Pre, func(), error) {
	idb := make([]byte, 32)
	if _, err := crand.Read(idb); err != nil {
		return store.Pre{}, nil, fmt.Errorf("lock holder id: %w", err)
	}
	id := hex.EncodeToString(idb)
	for attempt := 0; ; attempt++ {
		now := p.now().UTC()
		cur, err := store.Get[iam.MembershipLock](ctx, p.b, iam.MembershipLockKey)
		var v string
		switch {
		case errors.Is(err, store.ErrNotFound):
			l := iam.MembershipLock{Name: iam.MembershipLockKey, Epoch: 1, Holder: id, Expires: now.Add(membershipLease)}
			v, err = store.Create(ctx, p.b, l)
		case err == nil && cur.Object.Holder != "" && now.Before(cur.Object.Expires):
			err = store.ErrConflict // held: wait
		case err == nil:
			cur.Object.Epoch++
			cur.Object.Holder, cur.Object.Expires = id, now.Add(membershipLease)
			v, err = store.Update(ctx, p.b, cur.Object, cur.Version)
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) {
			if berr := backoff(ctx, attempt); berr != nil {
				return store.Pre{}, nil, berr
			}
			continue
		}
		if err != nil {
			return store.Pre{}, nil, err
		}
		pre := store.Pre{Kind: iam.KindMemberLock, Key: iam.MembershipLockKey, Version: v}
		return pre, func() { p.unlockMembership(ctx, id) }, nil
	}
}

// unlockMembership releases the lock if id still holds it. Best effort:
// a lock left held expires.
func (p project) unlockMembership(ctx context.Context, id string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	for range 8 {
		cur, err := store.Get[iam.MembershipLock](ctx, p.b, iam.MembershipLockKey)
		if err != nil || cur.Object.Holder != id {
			return
		}
		cur.Object.Holder, cur.Object.Expires = "", time.Time{}
		if _, err := store.Update(ctx, p.b, cur.Object, cur.Version); !errors.Is(err, store.ErrConflict) {
			return
		}
	}
}

// errLockBusy is a member add that kept losing to other adds. It is a
// ConcurrentModification the caller may retry.
var errLockBusy = fmt.Errorf("%w: group membership is changing concurrently", store.ErrConflict)

// backoff waits a jittered, growing delay (capped at 32 ms) before retry
// attempt+1, or returns errLockBusy after maxMemberAttempts or when ctx
// ends.
func backoff(ctx context.Context, attempt int) error {
	if attempt+1 >= maxMemberAttempts {
		return errLockBusy
	}
	d := time.Millisecond << min(attempt, 5)
	t := time.NewTimer(d/2 + rand.N(d))
	defer t.Stop()
	select {
	case <-ctx.Done():
		return errors.Join(errLockBusy, ctx.Err())
	case <-t.C:
		return nil
	}
}

// commitGroup writes g, read at g.Version, over its stored members prev.
// A write that adds members runs under the membership lock: take it,
// count, then commit only while the lock is unchanged, so two concurrent
// adds of one user cannot both pass the GroupsPerUser count. ErrConflict
// other than errLockBusy means g itself moved.
func (p project) commitGroup(ctx context.Context, g store.Versioned[iam.Group], prev []string) (string, error) {
	added := addedMembers(prev, g.Object.Members)
	if len(added) == 0 {
		return store.Update(ctx, p.b, g.Object, g.Version)
	}
	for attempt := 0; ; attempt++ {
		pre, unlock, err := p.lockMembership(ctx)
		if err != nil {
			return "", err
		}
		err = p.checkMembers(ctx, added)
		if err == nil {
			err = p.checkGroupsPerUser(ctx, g.Object.Name, added)
		}
		var v string
		if err == nil {
			v, err = store.UpdateIf(ctx, p.b, g.Object, g.Version, pre)
		}
		unlock()
		if !errors.Is(err, store.ErrConflict) {
			return v, err
		}
		now, gerr := store.Get[iam.Group](ctx, p.b, g.Object.Name)
		if gerr != nil {
			return "", gerr
		}
		if now.Version != g.Version {
			return "", err
		}
		// The lease ran out and another add took the lock: count again.
		if berr := backoff(ctx, attempt); berr != nil {
			return "", berr
		}
	}
}

// createGroup stores a new group. A group with members is stored empty
// first and the members are added by commitGroup, because a create cannot
// be conditional on the lock. If the add is refused, the empty group is
// removed again, unless a rename has marked it. A retry of the same
// request adopts the group it left. o is recorded by the write that
// completes the group, never on the empty group alone.
func (p project) createGroup(
	ctx context.Context, g iam.Group, requestID string, o once,
) (store.Versioned[iam.Group], error) {
	if err := p.checkGroupsPerUser(ctx, g.Name, g.Members); err != nil {
		return store.Versioned[iam.Group]{}, err
	}
	if len(g.Members) == 0 {
		o.record(&g.Meta)
		return create(ctx, p.b, g, requestID, false)
	}
	empty := g
	empty.Members = nil
	v, err := create(ctx, p.b, empty, requestID, false)
	if err != nil {
		return v, err
	}
	prev := v.Object.Members
	if len(addedMembers(prev, g.Members)) == 0 {
		return v, nil
	}
	staged := v
	v.Object.Members = g.Members
	o.record(&v.Object.Meta)
	ver, err := p.commitGroup(ctx, v, prev)
	if errors.Is(err, store.ErrConflict) && requestID != "" {
		if done, ok := p.completedBy(ctx, staged, g.Members); ok {
			return done, nil
		}
	}
	if err != nil {
		// A rename may have marked the group this request left (a retry
		// adopts it with the mark). Only the rename coordinator may remove
		// a marked group; dropStaged reads the group again before each
		// delete and every delete is versioned, so a mark that lands
		// after a read makes it fail.
		if len(prev) == 0 && !errors.Is(err, store.ErrRenaming) {
			p.dropStaged(ctx, staged)
		}
		return store.Versioned[iam.Group]{}, err
	}
	v.Version = ver
	return v, nil
}

// completedBy reports the group a duplicate delivery of the request that
// staged it completed first: the staged group (same UID, so its RequestID
// is this request's), unmarked, holding exactly members. A member add that
// lost to that duplicate answers as it did instead of ABORTED (#162).
func (p project) completedBy(
	ctx context.Context, staged store.Versioned[iam.Group], members []string,
) (store.Versioned[iam.Group], bool) {
	cur, err := store.Get[iam.Group](ctx, p.b, staged.Object.Name)
	if err != nil || cur.Object.UID != staged.Object.UID || cur.Object.Renaming() ||
		len(addedMembers(cur.Object.Members, members)) > 0 || len(addedMembers(members, cur.Object.Members)) > 0 {
		return cur, false
	}
	return cur, true
}

// dropStaged removes the empty group a refused createGroup staged. Another
// writer may have changed it since (a label or path update), so a stale
// delete reads the group again (#161). It is deleted only while it is
// still the group staged (same UID), unmarked and empty: no members and
// no policies, so nothing another writer gave it is lost. Best effort:
// an empty group left behind holds no quota.
func (p project) dropStaged(ctx context.Context, staged store.Versioned[iam.Group]) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	cur := staged
	for attempt := 0; ; attempt++ {
		g := cur.Object
		if g.UID != staged.Object.UID || g.Renaming() ||
			len(g.Members) > 0 || len(g.AttachedPolicies) > 0 || len(g.InlinePolicies) > 0 {
			return
		}
		err := store.Delete[iam.Group](ctx, p.b, g.Name, cur.Version)
		if !errors.Is(err, store.ErrConflict) || backoff(ctx, attempt) != nil {
			return
		}
		if cur, err = store.Get[iam.Group](ctx, p.b, g.Name); err != nil {
			return
		}
	}
}

// updateGroup is update for groups, committing through commitGroup. A group
// it creates is adopted through its RequestID, as createGroup does.
func (p project) updateGroup(
	ctx context.Context, key, etag, requestID string, o once, allowMissing bool,
	fn func(*iam.Group) error, mk func() (iam.Group, error),
) (store.Versioned[iam.Group], error) {
	for attempt := 0; ; attempt++ {
		cur, err := store.Get[iam.Group](ctx, p.b, key)
		if errors.Is(err, store.ErrNotFound) && allowMissing {
			g, err := mk()
			if err != nil {
				return cur, err
			}
			return p.createGroup(ctx, g, requestID, o)
		}
		if err != nil {
			return cur, err
		}
		if err := o.check(cur.Object.Meta); err != nil {
			return cur, err
		}
		if err := checkEtag(etag, cur.Version); err != nil {
			return cur, err
		}
		prev := cur.Object.Members
		if err := fn(&cur.Object); err != nil {
			return cur, err
		}
		bumpGroup(&cur.Object)
		o.record(&cur.Object.Meta)
		v, err := p.commitGroup(ctx, cur, prev)
		if errors.Is(err, errLockBusy) {
			return cur, err
		}
		if errors.Is(err, store.ErrConflict) && (etag == "" || o.op != "") && attempt < 8 {
			continue
		}
		if errors.Is(err, store.ErrConflict) {
			return cur, checkEtag("stale", "")
		}
		cur.Version = v
		return cur, err
	}
}
