package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// Per-caller attempt limits (#12): failed Login, MFA and STS-MFA attempts
// are counted per user, per access key and per source IP in a fixed
// window shared by every replica, on top of the per-device MFA lockout.
// A caller that reaches its limit is locked out for AttemptLockout; while
// locked, even correct credentials are refused (Throttling).
const (
	AttemptWindow    = 15 * time.Minute
	AttemptLockout   = 15 * time.Minute
	UserAttemptLimit = 10
	KeyAttemptLimit  = 10
	// IPAttemptLimit is higher: one address can be a shared NAT.
	IPAttemptLimit = 50
)

func attemptLimit(scope string) int {
	switch scope {
	case iam.AttemptUser:
		return UserAttemptLimit
	case iam.AttemptKey:
		return KeyAttemptLimit
	}
	return IPAttemptLimit
}

// subject is one counted caller. id is never stored, only its digests.
type subject struct{ scope, id string }

// counter is one stored IamAttemptCounter of a subject.
type counter struct{ scope, key string }

// counters are the store keys of cs: per subject, its keyed digest under
// every KEK of the ring (secret.Keyring.Digests), so a store reader
// without the KEK cannot brute-force an IP address or user name behind a
// key. A counter is kept under every KEK in the ring, so adding a KEK
// keeps every running lock; removing one drops only the counters under
// it, which the ring still holds under the other KEKs.
func (s *Server) counters(cs callers) []counter {
	var out []counter
	for _, j := range cs {
		for _, k := range s.keys.Digests("attempt", j.scope+"\n"+j.id) {
			out = append(out, counter{j.scope, k})
		}
	}
	return out
}

// callers are the subjects of one attempt.
type callers []subject

// userSubject counts a user of a project; names are case-insensitive.
func userSubject(project, user string) subject {
	return subject{iam.AttemptUser, project + "/" + store.Fold(user)}
}

// ipSubject counts a source IP. Trust: source_ip is set by the trusted
// front end (console-api, the SigV4 gateway) from the client connection;
// only those reach vws-iam. The gRPC peer is that front end, never the
// client, so it is not used. An empty source_ip adds no IP subject
// (Login counts it apart, loginCallers); an IPv6 address counts as its
// /64. A malformed one is counted as is.
func ipSubject(ip string) (subject, bool) {
	if ip == "" {
		return subject{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return subject{iam.AttemptIP, "invalid/" + ip}, true
	}
	a = a.Unmap()
	if a.Is6() {
		if p, err := a.Prefix(64); err == nil {
			return subject{iam.AttemptIP, p.String()}, true
		}
	}
	return subject{iam.AttemptIP, a.String()}, true
}

func (c callers) withIP(ip string) callers {
	if j, ok := ipSubject(ip); ok {
		return append(c, j)
	}
	return c
}

// loginCallers are the subjects of a console Login of j: the source IP
// first, so a locked IP is refused before j's counter is written. Each
// attempt then writes a user counter only while its IP is under
// IPAttemptLimit, which bounds the counters one IP can create with
// unknown user names per window. A Login without a source IP counts
// under one shared sentinel IP (console-api always sets it). Known and
// unknown names take the same path.
func loginCallers(j subject, sourceIP string) callers {
	ip, ok := ipSubject(sourceIP)
	if !ok {
		ip = subject{iam.AttemptIP, "none/"}
	}
	return callers{ip, j}
}

// errThrottled is a locked-out caller: RESOURCE_EXHAUSTED / Throttling.
var errThrottled = errors.New("too many failed attempts; try again later")

// throttleError is errThrottled with the scopes (iam.AttemptUser, Key,
// IP) whose limit refused the attempt, so a caller can tell a user over
// its limit from a shared IP or key over theirs (#44).
type throttleError struct{ scopes []string }

func (e *throttleError) Error() string { return errThrottled.Error() }

func (e *throttleError) Is(target error) bool { return target == errThrottled }

// throttled builds the error for the given scopes.
func throttled(scopes ...string) error { return &throttleError{scopes: scopes} }

// throttledBy reports whether err is a throttle in which scope's limit
// took part.
func throttledBy(err error, scope string) bool {
	var te *throttleError
	return errors.As(err, &te) && slices.Contains(te.scopes, scope)
}

// attemptsKey carries the access key and source IP subjects of an STS
// call to mfaVerifier, which adds the user.
type attemptsKey struct{}

func withAttempts(ctx context.Context, cs callers) context.Context {
	return context.WithValue(ctx, attemptsKey{}, cs)
}

// limitedVerify runs verify as one counted attempt of cs: refused while
// any subject is locked, reserved before verify, released on success.
// Every store error fails closed.
func (s *Server) limitedVerify(ctx context.Context, cs callers, verify func() error) error {
	if err := s.checkAttempts(ctx, cs); err != nil {
		return withErrorContext("check authentication attempts", err)
	}
	held, err := s.reserveAttempts(ctx, cs)
	if err != nil {
		return withErrorContext("reserve authentication attempts", err)
	}
	if err := verify(); err != nil {
		return withErrorContext("verify credentials", err)
	}
	// A failed release only leaves the attempt counted until the window
	// ends; the caller's credentials were right, so do not fail the call.
	if err := s.releaseAttempts(context.WithoutCancel(ctx), held); err != nil {
		slog.Default().LogAttrs(ctx, slog.LevelWarn, "attempt release failed", slog.String("error", err.Error()))
	}
	return nil
}

// checkAttempts refuses a caller that is locked out under any of its
// counters. It only reads.
func (s *Server) checkAttempts(ctx context.Context, cs callers) error {
	now := s.now()
	var scopes []string
	for _, c := range s.counters(cs) {
		v, err := store.Get[iam.AttemptCounter](ctx, s.b, c.key)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return withErrorContext("read attempt counter", err)
		case lockedOut(v.Object, now) && !slices.Contains(scopes, c.scope):
			scopes = append(scopes, c.scope)
		}
	}
	if len(scopes) > 0 {
		return throttled(scopes...)
	}
	return nil
}

// lockedOut reports a running lockout, or a window that already holds
// the limit, so the next attempt is refused before any credential check.
func lockedOut(c iam.AttemptCounter, now time.Time) bool {
	return now.Before(c.LockedUntil) ||
		(now.Before(c.WindowStart.Add(AttemptWindow)) && c.Failures >= attemptLimit(c.Scope))
}

// reserveAttempts counts one attempt on every counter of cs before the
// credentials are checked, so concurrent guesses cannot pass the limit:
// at most limit attempts per window reach the check. The attempt that
// would exceed the limit locks the counter and is refused, and later
// counters are not written. It returns the counters it bumped, which
// releaseAttempts gives back when the credentials were right.
func (s *Server) reserveAttempts(ctx context.Context, cs callers) ([]counter, error) {
	var held []counter
	for _, c := range s.counters(cs) {
		locked, err := s.bump(ctx, c, 1)
		if err != nil {
			return held, withErrorContext("reserve attempt counter", err)
		}
		if locked {
			return held, throttled(c.scope)
		}
		held = append(held, c)
	}
	return held, nil
}

func (s *Server) releaseAttempts(ctx context.Context, held []counter) error {
	var errs []error
	for _, c := range held {
		if _, err := s.bump(ctx, c, -1); err != nil {
			errs = append(errs, withErrorContext("release attempt counter", err))
		}
	}
	return errors.Join(errs...)
}

// bump applies delta to c with compare-and-swap and reports whether c is
// (now) locked out.
func (s *Server) bump(ctx context.Context, c counter, delta int) (bool, error) {
	now := s.now()
	if delta > 0 {
		_, err := store.Create(ctx, s.b, iam.AttemptCounter{Hash: c.key, Scope: c.scope, WindowStart: now})
		if err != nil && !errors.Is(err, store.ErrExists) {
			return false, withErrorContext("create attempt counter", err)
		}
	}
	var locked bool
	fn := func(v *iam.AttemptCounter) error {
		locked = false
		if now.Before(v.LockedUntil) {
			if delta > 0 {
				return errThrottled // no write while locked
			}
			return nil
		}
		if !now.Before(v.WindowStart.Add(AttemptWindow)) || !v.LockedUntil.IsZero() {
			// The window or the lockout is over: start a new window.
			v.Failures, v.WindowStart, v.LockedUntil = 0, now, time.Time{}
			if delta < 0 {
				return nil // the reservation was in an older window
			}
		}
		if delta > 0 && v.Failures >= attemptLimit(v.Scope) {
			v.LockedUntil = now.Add(AttemptLockout)
			locked = true
			return nil
		}
		v.Failures = max(v.Failures+delta, 0)
		return nil
	}
	// store.Mutate retries a lost race a few times; under heavy contention
	// keep going while the context allows, then fail closed.
	for {
		_, err := store.Mutate(ctx, s.b, c.key, fn)
		if errors.Is(err, errThrottled) {
			return true, nil
		}
		if errors.Is(err, store.ErrNotFound) && delta < 0 {
			return false, nil // collected
		}
		if !errors.Is(err, store.ErrConflict) || ctx.Err() != nil {
			return locked, withErrorContext("mutate attempt counter", err)
		}
	}
}

// GCAttemptCounters deletes counters whose window and lockout are over.
func (s *Server) GCAttemptCounters(ctx context.Context) (int, error) {
	now := s.now()
	return gcPaged(ctx, s, func(c iam.AttemptCounter) bool {
		return !now.Before(c.WindowStart.Add(AttemptWindow)) && !now.Before(c.LockedUntil)
	})
}
