package mfa

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

var ErrLimitExceeded = errors.New("mfa devices per user limit exceeded")

// claimMFASlot counts while the caller holds the user's quota lease.
// The device commits conditionally on the same user version, so taking an
// expired hold invalidates the old writer before the next count.
func (s *Service) claimMFASlot(
	ctx context.Context, u store.Versioned[iam.User], holder string, fido bool,
) (store.Pre, error) {
	if u.Object.MFARegistrationLease.Holder != holder {
		return store.Pre{}, store.ErrConflict
	}
	if u.Object.Renaming() {
		return store.Pre{}, store.ErrRenaming
	}
	virtual, err := store.List[iam.MfaDevice](ctx, s.b)
	if err != nil {
		return store.Pre{}, fmt.Errorf("count virtual mfa devices: %w", err)
	}
	keys, err := store.List[iam.FidoDevice](ctx, s.b)
	if err != nil {
		return store.Pre{}, fmt.Errorf("count fido devices: %w", err)
	}
	count := 0
	for _, d := range virtual {
		if d.Object.Enabled && store.Fold(d.Object.UserName) == store.Fold(u.Object.Name) {
			count++
		}
	}
	for _, d := range keys {
		sameUser := store.Fold(d.Object.UserName) == store.Fold(u.Object.Name)
		if !d.Object.Pending && d.Object.UserUID == u.Object.UID && sameUser {
			count++
		}
	}
	if count >= iam.MaxMFADevicesPerUser {
		return store.Pre{}, ErrLimitExceeded
	}
	u.Object.Generation++
	if fido {
		u.Object.FidoRegistrations++
	}
	version, err := store.Update(ctx, s.b, u.Object, u.Version)
	if err != nil {
		return store.Pre{}, fmt.Errorf("claim mfa device slot: %w", err)
	}
	u.Version = version
	return store.PreOf(u), nil
}

// lockMFA bounds crash recovery to ten seconds. The conditional device
// commit, not clocks or process-local exclusion, supplies quota safety.
func (s *Service) lockMFA(ctx context.Context, user string) (store.Versioned[iam.User], func(), error) {
	return s.lockMFAChecked(ctx, user, nil)
}

func (s *Service) lockMFAChecked(
	ctx context.Context, user string, check func(store.Versioned[iam.User]) error,
) (store.Versioned[iam.User], func(), error) {
	id := iam.NewUID()
	for attempt := 0; attempt < 400; attempt++ {
		u, err := store.Get[iam.User](ctx, s.b, user)
		if err != nil {
			return u, nil, fmt.Errorf("lock mfa registrations: %w", err)
		}
		if u.Object.Renaming() {
			return u, nil, store.ErrRenaming
		}
		if check != nil {
			if err := check(u); err != nil {
				return u, nil, err
			}
		}
		lease := u.Object.MFARegistrationLease
		if lease.Holder == "" || !s.now().Before(lease.Expires) {
			u.Object.MFARegistrationLease = iam.MFARegistrationLease{Holder: id, Expires: s.now().Add(10 * time.Second)}
			v, err := store.Update(ctx, s.b, u.Object, u.Version)
			if err == nil {
				u.Version = v
				return u, func() { s.unlockMFA(ctx, user, id) }, nil
			}
			if check != nil || !errors.Is(err, store.ErrConflict) {
				return u, nil, fmt.Errorf("lock mfa registrations: %w", err)
			}
		}
		delay := time.Millisecond << min(attempt, 5)
		timer := time.NewTimer(delay/2 + rand.N(delay))
		select {
		case <-ctx.Done():
			timer.Stop()
			return u, nil, fmt.Errorf("lock mfa registrations: %w", ctx.Err())
		case <-timer.C:
		}
	}
	return store.Versioned[iam.User]{}, nil, fmt.Errorf("lock mfa registrations: %w", store.ErrConflict)
}

func (s *Service) unlockMFA(ctx context.Context, user, holder string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	for range 8 {
		u, err := store.Get[iam.User](ctx, s.b, user)
		if err != nil || u.Object.MFARegistrationLease.Holder != holder {
			return
		}
		u.Object.MFARegistrationLease = iam.MFARegistrationLease{}
		if _, err := store.Update(ctx, s.b, u.Object, u.Version); !errors.Is(err, store.ErrConflict) {
			return
		}
	}
}
