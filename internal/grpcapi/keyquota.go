package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func accessKeysPerUserExceeded() error {
	return quota(fmt.Sprintf("Cannot exceed quota for AccessKeysPerUser: %d", accesskey.MaxPerUser))
}

// errLockLost is a key create whose quota lock was taken by another
// writer before the key was committed; the pending key is removed and the
// create is retried.
var errLockLost = errors.New("quota lock lost during key create")

// requestRepeated is a CreateAccessKey request_id that already created
// key id. It names the key and never carries its secret.
func requestRepeated(id string) error {
	return fail(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists",
		"access key "+id+" was already created with this request_id; its secret is not returned again")
}

// createKey creates an access key for user under the project's quota lock
// (the lock member adds take), so two concurrent creates for one user
// cannot both pass the AccessKeysPerUser count. A non-empty requestID that
// already created a key of user is ALREADY_EXISTS; it is checked and
// stored under the same lock hold, so concurrent creates with one
// requestID make one key.
func (p project) createKey(ctx context.Context, user, requestID string) (accesskey.Credential, error) {
	for attempt := 0; ; attempt++ {
		cred, err := p.createKeyLocked(ctx, user, requestID)
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

// createKeyLocked counts and writes the key in two steps that both commit
// only under the lock hold taken here. The key is written as
// iam.KeyPending, which authenticates nothing and is not counted, and is
// made active by store.UpdateIf on the lock: if another writer took the
// lock in between (the lease ran out), the activation is refused and the
// key stays pending. A writer that dies at any point leaves at most an
// inert pending key, which the next create for the user removes, so the
// stored active keys never exceed accesskey.MaxPerUser.
//
// requestID is looked up among user's committed keys after the sweep and
// stored with the pending key. A writer that wrote its key and then lost
// the lock cannot activate it, so of two creates with one requestID only
// the one whose activation commits under its hold makes a key; the other
// retries under a later hold and finds that key.
func (p project) createKeyLocked(ctx context.Context, user, requestID string) (accesskey.Credential, error) {
	pre, unlock, err := p.lockMembership(ctx)
	if err != nil {
		return accesskey.Credential{}, err
	}
	defer unlock()
	hold, err := p.lockHold(ctx, pre)
	if err != nil {
		return accesskey.Credential{}, err
	}
	if err := p.keys.SweepPending(ctx, user, pre); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return accesskey.Credential{}, errLockLost
		}
		return accesskey.Credential{}, err
	}
	// A conditional delete may advance the lock's version (kubestore
	// fences); the hold is still ours while holder and epoch are.
	if pre, err = p.stillHeld(ctx, hold); err != nil {
		return accesskey.Credential{}, err
	}
	if requestID != "" {
		id, ok, err := p.keys.ByRequestID(ctx, user, requestID)
		if err != nil {
			return accesskey.Credential{}, err
		}
		if ok {
			return accesskey.Credential{}, requestRepeated(id)
		}
	}
	cred, version, err := p.keys.CreatePending(ctx, user, requestID)
	if err != nil {
		return accesskey.Credential{}, err
	}
	aerr := p.keys.Activate(ctx, cred.AccessKeyID, version, pre)
	if aerr == nil {
		return cred, nil
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	// An activation whose outcome was lost may have committed.
	if k, gerr := store.Get[iam.AccessKey](dctx, p.b, cred.AccessKeyID); gerr == nil && k.Object.Status == iam.KeyActive {
		return cred, nil
	} else if gerr == nil {
		version = k.Version
	}
	err = errLockLost
	if !errors.Is(aerr, store.ErrConflict) && !errors.Is(aerr, store.ErrNotFound) {
		err = fmt.Errorf("activate access key: %w", aerr)
	}
	// Best effort: a pending key left behind is inert and swept by the
	// next create, so a failed removal does not block the retry.
	if derr := p.keys.DeletePending(dctx, cred.AccessKeyID, version, nil); derr != nil {
		slog.Default().LogAttrs(ctx, slog.LevelWarn, "pending access key left for the next sweep",
			slog.String("access_key_id", cred.AccessKeyID), slog.String("error", derr.Error()))
	}
	return accesskey.Credential{}, err
}

// lockHold reads the quota lock taken at pre: its holder and epoch name
// this hold. errLockLost if the lock already moved.
func (p project) lockHold(ctx context.Context, pre store.Pre) (iam.MembershipLock, error) {
	cur, err := p.readLock(ctx)
	if err != nil {
		return iam.MembershipLock{}, err
	}
	if cur.Version != pre.Version {
		return iam.MembershipLock{}, errLockLost
	}
	return cur.Object, nil
}

// stillHeld returns the precondition that the lock is at its current
// version, if hold is still the lock's holder and epoch, and errLockLost
// if not.
func (p project) stillHeld(ctx context.Context, hold iam.MembershipLock) (store.Pre, error) {
	cur, err := p.readLock(ctx)
	if err != nil {
		return store.Pre{}, err
	}
	if cur.Object.Holder != hold.Holder || cur.Object.Epoch != hold.Epoch {
		return store.Pre{}, errLockLost
	}
	return store.PreOf(cur), nil
}

func (p project) readLock(ctx context.Context) (store.Versioned[iam.MembershipLock], error) {
	cur, err := store.Get[iam.MembershipLock](ctx, p.b, iam.MembershipLockKey)
	if errors.Is(err, store.ErrNotFound) {
		return cur, errLockLost
	}
	if err != nil {
		return cur, fmt.Errorf("read quota lock: %w", err)
	}
	return cur, nil
}
