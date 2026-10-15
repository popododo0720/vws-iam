package sts

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// RevokeSessionsOnce is RevokeSessions keyed by requestID: the bump and
// the record of requestID happen in one compare-and-swap, so concurrent
// deliveries of one request bump the generation once, on any replica
// (#48). The operation record in grpcapi only answers later replays; it
// is written after the bump, so it cannot stop a racing duplicate. An
// empty requestID always bumps. Lost CAS races are retried while ctx
// lives, so a burst of revocations of one principal is not refused.
func (s *Service) RevokeSessionsOnce(ctx context.Context, kind authz.PrincipalKind, name, requestID string) error {
	now := s.now().UTC()
	apply := func(revoked *time.Time, gen *uint64, reqs *[]string) {
		if requestID != "" && slices.Contains(*reqs, requestID) {
			return
		}
		*revoked = later(*revoked, now)
		*gen++
		if requestID != "" {
			*reqs = append(*reqs, requestID)
			if n := len(*reqs) - iam.MaxRevokeRequests; n > 0 {
				*reqs = slices.Delete(*reqs, 0, n)
			}
		}
	}
	for {
		var err error
		switch kind {
		case authz.User:
			_, err = store.Mutate(ctx, s.b, name, func(u *iam.User) error {
				apply(&u.SessionsRevokedBefore, &u.SessionsRevokeGeneration, &u.SessionsRevokeRequests)
				return nil
			})
		case authz.Role:
			_, err = store.Mutate(ctx, s.b, name, func(r *iam.Role) error {
				apply(&r.SessionsRevokedBefore, &r.SessionsRevokeGeneration, &r.SessionsRevokeRequests)
				return nil
			})
		default:
			return fmt.Errorf("%w: principal kind %d", ErrInvalidRequest, kind)
		}
		if errors.Is(err, store.ErrConflict) && ctx.Err() == nil {
			continue
		}
		if err != nil {
			return fmt.Errorf("revoke sessions of %s: %w", name, err)
		}
		return nil
	}
}
