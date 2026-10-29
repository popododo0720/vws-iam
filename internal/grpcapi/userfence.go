package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/sigv4"
	"github.com/popododo0720/vws-iam/internal/store"
)

// keyWriteTimeout bounds an access key write made under a user ARN lease.
const keyWriteTimeout = 10 * time.Second

// keyWriteLeaseTTL is how long a lease blocks path moves. The holder stops
// writing after keyWriteTimeout on its own clock; the extra sigv4.MaxSkew
// covers another replica's clock, which may run ahead by up to that much.
// A lease left by a crashed holder blocks path moves until it expires.
const keyWriteLeaseTTL = keyWriteTimeout + sigv4.MaxSkew

// withUserARNLease runs write, an access key write, while the key's parent
// user is pinned to expectedARN. The store has no multi-object
// transaction, so the pin is a lease on the user object: it is taken with a
// compare-and-swap on the user read that matched the ARN, and UpdateUser
// refuses to change the path while a live lease exists. A move that
// committed before the lease makes the lease's ARN check fail, and one
// that would commit after it is refused, so the write never lands against
// a replaced ARN. An empty expectedARN runs write without a lease.
func (s *Server) withUserARNLease(ctx context.Context, b store.Backend, expectedARN, project, userName string, write func(context.Context) error) error {
	if expectedARN == "" {
		return write(ctx)
	}
	account, path, user, err := parseExpectedUserARN(expectedARN)
	if err != nil {
		return err
	}
	if account != project || store.Fold(user) != store.Fold(userName) {
		return errUserARNMismatch()
	}
	token := iam.NewUID()
	start := s.now()
	_, err = store.Mutate(ctx, b, userName, func(u *iam.User) error {
		if iam.UserARN(project, *u) != iam.UserARN(project, iam.User{Name: u.Name, Path: path}) {
			return errUserARNMismatch()
		}
		u.KeyWriteLeases = append(liveLeases(u.KeyWriteLeases, s.now()), iam.KeyWriteLease{Token: token, Until: start.Add(keyWriteLeaseTTL).UTC()})
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return errUserARNMismatch()
	}
	if err != nil {
		return err
	}
	wctx, cancel := context.WithDeadline(ctx, start.Add(keyWriteTimeout))
	err = write(wctx)
	cancel()
	// A failed release only blocks path moves until the lease expires.
	rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), keyWriteTimeout)
	defer rcancel()
	if _, rerr := store.Mutate(rctx, b, userName, func(u *iam.User) error {
		u.KeyWriteLeases = slices.DeleteFunc(liveLeases(u.KeyWriteLeases, s.now()), func(l iam.KeyWriteLease) bool { return l.Token == token })
		return nil
	}); rerr != nil && !errors.Is(rerr, store.ErrNotFound) {
		slog.Default().LogAttrs(ctx, slog.LevelWarn, "user ARN lease release failed", slog.String("error", rerr.Error()))
	}
	return err
}

// liveLeases drops the leases that expired at now.
func liveLeases(ls []iam.KeyWriteLease, now time.Time) []iam.KeyWriteLease {
	return slices.DeleteFunc(slices.Clone(ls), func(l iam.KeyWriteLease) bool { return !now.Before(l.Until) })
}
