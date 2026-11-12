package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// roleDeleteLease is how long AddRoleToInstanceProfile waits on a role a
// DeleteRole marked (iam.Role.DeleteStarted) before it clears the mark.
// It bounds how long a DeleteRole that stopped after marking blocks adds;
// correctness does not depend on it, nor on replica clocks.
const roleDeleteLease = 10 * time.Second

// deleteRole deletes role id of p for DeleteRole, refusing a role an
// instance profile of p holds with DeleteConflict (#234), as AWS does.
//
// It marks the role (DeleteStarted, a write that moves the role's
// version), lists the instance profiles, and deletes the role only at the
// marked version. AddRoleToInstanceProfile commits only while the role is
// at the version it read and never adds a marked role, so an add that
// committed before the mark is seen by the listing, and one that commits
// after it first cleared the mark, which fails the delete: a role is
// never deleted while being added. A role that changed after it was read,
// or after it was marked, is ConcurrentModification and stays, as before.
// A refused or failed delete clears the mark again; a mark left by a
// crash goes stale after roleDeleteLease and is cleared by the next add.
func (p project) deleteRole(
	ctx context.Context, id, etag string, allowMissing bool,
) (store.Versioned[iam.Role], error) {
	cur, err := store.Get[iam.Role](ctx, p.b, id)
	if errors.Is(err, store.ErrNotFound) && allowMissing {
		return cur, nil
	}
	if err != nil {
		return cur, err
	}
	if err := checkEtag(etag, cur.Version); err != nil {
		return cur, err
	}
	r := cur.Object
	if r.ServiceLinked() {
		return cur, unmodifiable("role " + r.Name + " is service-linked; delete it with DeleteServiceLinkedRole")
	}
	if len(r.AttachedPolicies) > 0 || len(r.InlinePolicies) > 0 {
		return cur, deleteConflict("role has attached or inline policies")
	}
	r.DeleteStarted = p.now().UTC()
	marked, err := store.Update(ctx, p.b, r, cur.Version)
	if errors.Is(err, store.ErrConflict) {
		return cur, checkEtag("stale", "")
	}
	if err != nil {
		return cur, err
	}
	held, err := p.roleInInstanceProfile(ctx, r.Name)
	if err == nil && held {
		err = deleteConflict("Cannot delete entity, must remove roles from instance profile first.")
	}
	if err == nil {
		err = store.Delete[iam.Role](ctx, p.b, r.Name, marked)
		if errors.Is(err, store.ErrConflict) {
			err = checkEtag("stale", "")
		}
	}
	if err != nil {
		p.unmarkRole(ctx, r.Name, r.DeleteStarted)
		return cur, err
	}
	return cur, nil
}

// roleInInstanceProfile reports whether an instance profile of p names
// role name (case folded).
func (p project) roleInInstanceProfile(ctx context.Context, name string) (bool, error) {
	all, err := store.List[iam.InstanceProfile](ctx, p.b)
	if err != nil {
		return false, fmt.Errorf("list instance profiles: %w", err)
	}
	k := store.Fold(name)
	for _, v := range all {
		if slices.ContainsFunc(v.Object.Roles, func(n string) bool { return store.Fold(n) == k }) {
			return true, nil
		}
	}
	return false, nil
}

// unmarkRole clears the delete mark started of role name, if the role
// still carries that mark (another write may have moved its version
// since). Best effort, also after the request's context
// ended: a mark left set goes stale after roleDeleteLease.
func (p project) unmarkRole(ctx context.Context, name string, started time.Time) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	for range maxDeleteAttempts {
		cur, err := store.Get[iam.Role](ctx, p.b, name)
		if err != nil || !cur.Object.DeleteStarted.Equal(started) {
			return
		}
		cur.Object.DeleteStarted = time.Time{}
		if _, err := store.Update(ctx, p.b, cur.Object, cur.Version); !errors.Is(err, store.ErrConflict) {
			return
		}
	}
}

// awaitRoleDelete is the step of AddRoleToInstanceProfile for role r
// that a DeleteRole marked: while the mark is recent it waits (attempt is
// the add's retry count) and fails with ConcurrentModification once the
// waits run out; a stale mark is cleared at r's version, so a delete
// still holding it fails. The caller reads the role again either way.
func (p project) awaitRoleDelete(ctx context.Context, r store.Versioned[iam.Role], attempt int) error {
	if p.now().Sub(r.Object.DeleteStarted) < roleDeleteLease {
		if err := backoff(ctx, attempt); err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return fmt.Errorf("wait for the delete of role %s: %w", r.Object.Name, cerr)
			}
			return fmt.Errorf("%w: role %s is being deleted", store.ErrConflict, r.Object.Name)
		}
		return nil
	}
	cleared := r.Object
	cleared.DeleteStarted = time.Time{}
	_, err := store.Update(ctx, p.b, cleared, r.Version)
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("clear delete mark of role %s: %w", r.Object.Name, err)
	}
	return nil
}
