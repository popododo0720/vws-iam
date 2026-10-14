package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/sigv4"
	"github.com/popododo0720/vws-iam/internal/store"
)

// replayTTL is how long a used STS signature is remembered: past it the
// request's X-Amz-Date is outside sigv4.MaxSkew and fails on its own.
const replayTTL = 2 * sigv4.MaxSkew

// replayHash is the store key of a signed request. Only this digest is
// stored; the signature and the secret never are.
func replayHash(r *iamv1.AuthenticateRequest) string {
	h := sha256.Sum256([]byte(r.GetAccessKeyId() + "\n" + r.GetSignature()))
	return hex.EncodeToString(h[:])
}

// claimReplay records r as used, once across every replica sharing the
// backend: the IamReplayEntry create is atomic, so of two requests with
// the same signature exactly one gets past it. A store error fails
// closed.
func (s *Server) claimReplay(ctx context.Context, r *iamv1.AuthenticateRequest) error {
	now := s.now()
	s.stsSeen.Range(func(k, v any) bool {
		if t, ok := v.(time.Time); ok && now.After(t) {
			s.stsSeen.Delete(k)
		}
		return true
	})
	h := replayHash(r)
	if v, ok := s.stsSeen.Load(h); ok {
		if t, ok := v.(time.Time); ok && !now.After(t) {
			return replayed()
		}
	}
	exp := now.Add(replayTTL)
	for attempt := 0; ; attempt++ {
		_, err := store.Create(ctx, s.b, iam.ReplayEntry{Hash: h, Expires: exp})
		if err == nil {
			s.stsSeen.Store(h, exp)
			return nil
		}
		if !errors.Is(err, store.ErrExists) || attempt > 0 {
			return toStatus(ctx, err)
		}
		v, err := store.Get[iam.ReplayEntry](ctx, s.b, h)
		switch {
		case errors.Is(err, store.ErrNotFound):
			continue // collected between create and get
		case err != nil:
			return toStatus(ctx, err)
		case !now.After(v.Object.Expires):
			s.stsSeen.Store(h, v.Object.Expires)
			return replayed()
		}
		// Expired but not yet collected: remove it with its version, so a
		// concurrent claimer that already replaced it is not undone.
		if err := store.Delete[iam.ReplayEntry](ctx, s.b, h, v.Version); err != nil && !errors.Is(err, store.ErrNotFound) {
			if errors.Is(err, store.ErrConflict) {
				return replayed()
			}
			return toStatus(ctx, err)
		}
	}
}

func replayed() error { return accessDenied("this signed request was already used") }

// GCReplayEntries deletes expired replay entries and returns how many it
// removed. Every replica may run it; a lost race is not an error.
func (s *Server) GCReplayEntries(ctx context.Context) (int, error) {
	vs, err := store.List[iam.ReplayEntry](ctx, s.b)
	if err != nil {
		return 0, err
	}
	now, n := s.now(), 0
	for _, v := range vs {
		if !now.After(v.Object.Expires) {
			continue
		}
		err := store.Delete[iam.ReplayEntry](ctx, s.b, v.Object.Hash, v.Version)
		switch {
		case err == nil:
			n++
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrConflict):
		default:
			return n, err
		}
	}
	return n, nil
}
