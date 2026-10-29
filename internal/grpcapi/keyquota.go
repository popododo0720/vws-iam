package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func accessKeysPerUserExceeded() error {
	return quota(fmt.Sprintf("Cannot exceed quota for AccessKeysPerUser: %d", accesskey.MaxPerUser))
}

// errLockLost is a key create whose quota lock lease ran out before the
// key was confirmed; the key was removed and the create is retried.
var errLockLost = errors.New("quota lock lost during key create")

// createKey creates an access key for user under the project's quota lock
// (the lock member adds take), so two concurrent creates for one user
// cannot both pass the AccessKeysPerUser count. A create cannot be
// conditional on the lock, so the key is confirmed after it is written:
// if the lock is still at the version taken, any later holder counts
// after this key exists; if it moved, the key is removed and the create
// runs again.
func (p project) createKey(ctx context.Context, user string) (accesskey.Credential, error) {
	for attempt := 0; ; attempt++ {
		cred, err := p.createKeyLocked(ctx, user)
		if !errors.Is(err, errLockLost) {
			if errors.Is(err, accesskey.ErrLimitExceeded) {
				return cred, accessKeysPerUserExceeded()
			}
			return cred, err
		}
		if berr := backoff(ctx, attempt); berr != nil {
			return accesskey.Credential{}, berr
		}
	}
}

func (p project) createKeyLocked(ctx context.Context, user string) (accesskey.Credential, error) {
	pre, unlock, err := p.lockMembership(ctx)
	if err != nil {
		return accesskey.Credential{}, err
	}
	defer unlock()
	cred, err := p.keys.Create(ctx, user)
	if err != nil {
		return cred, err
	}
	cur, err := store.Get[iam.MembershipLock](ctx, p.b, pre.Key)
	if err == nil && cur.Version == pre.Version {
		return cred, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		// Unknown whether the lock held: keep the quota safe.
		err = fmt.Errorf("confirm quota lock: %w", err)
	} else {
		err = errLockLost
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if derr := p.keys.Delete(dctx, cred.UserName, cred.AccessKeyID); derr != nil && !errors.Is(derr, store.ErrNotFound) {
		return accesskey.Credential{}, errors.Join(err, fmt.Errorf("remove unconfirmed key: %w", derr))
	}
	return accesskey.Credential{}, err
}
