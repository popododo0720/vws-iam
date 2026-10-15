package mfa

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// MaxLockout bounds how long renewals can keep one lockout running: a
// throttled attempt extends LockedUntil to now+LockoutDuration but never
// past LockedSince+MaxLockout (#48). After that the device unlocks, and
// only MaxFailedAttempts new wrong codes, each of which must pass the
// per-caller attempt limits and the caller's credentials, lock it again.
const MaxLockout = time.Hour

// RenewLock extends a running lockout of user's enabled device name after
// an attempt refused by the user's own attempt limit, so the lock lasts
// LockoutDuration from that attempt, capped at MaxLockout from the lock's
// start. It never starts a lockout: a throttled attempt checks no code,
// so it is no evidence against the device, and anyone who can trip the
// user's limit (a leaked key, or only a user name on console Login) must
// not be able to lock or keep locked a device without wrong codes. It
// reports whether it wrote.
func (s *Service) RenewLock(ctx context.Context, user, name string) (bool, error) {
	_, err := store.Mutate(ctx, s.b, name, func(d *iam.MfaDevice) error {
		if !d.Enabled || store.Fold(d.UserName) != store.Fold(user) {
			return errNoWrite
		}
		now := s.now().UTC()
		if !now.Before(d.LockedUntil) {
			return errNoWrite // not locked: renewal never starts a lock
		}
		since := d.LockedSince
		if since.IsZero() { // locked before LockedSince was stored
			since = d.LockedUntil.Add(-LockoutDuration)
		}
		until := now.Add(LockoutDuration)
		if limit := since.Add(MaxLockout); until.After(limit) {
			until = limit
		}
		if !until.After(d.LockedUntil) {
			return errNoWrite
		}
		d.LockedUntil, d.LockedSince = until, since
		return nil
	})
	switch {
	case errors.Is(err, errNoWrite), errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("mfa device %s: %w", name, err)
	}
	return true, nil
}
