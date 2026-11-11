// Package mfa manages virtual TOTP MFA devices. The seed is shown once at
// creation and stored only sealed. Enabling needs two consecutive codes.
// Each accepted code advances the device's last step, so a code is never
// accepted twice. Resync stores the drift of the device clock, around
// which codes are then checked. MaxFailedAttempts wrong codes in a row
// lock the device, first for LockoutDuration and then twice as long for
// each further lockout before an accepted code, up to MaxLockout; the
// counters are stored, so a restart does not reset them.
package mfa

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/totp"
)

// Errors.
var (
	ErrInvalidCode   = errors.New("InvalidAuthenticationCode")
	ErrEntityInUse   = errors.New("EntityAlreadyExists")
	ErrNotAssociated = errors.New("NoSuchEntity")
	// ErrLocked is returned while a device is locked out; even a correct
	// code is refused then.
	ErrLocked = errors.New("MFADeviceLocked")
)

// Skew is the accepted clock drift in steps, for Verify and for Enable.
const Skew = 1

// ResyncSkew is how far, in steps either side of now, Resync searches
// for two consecutive codes: 10 minutes. It also bounds the stored drift.
const ResyncSkew = 20

// Brute-force limits: a 6-digit code space of 10^6 with ±1 step allows
// about 3 hits per million guesses, so 5 tries per 15 minutes bounds an
// online attack to well under 1% per year.
const (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
)

// lockoutFor is how long the n-th lockout in a row (n >= 1) lasts:
// LockoutDuration doubled for each lockout before it, at most MaxLockout,
// so a guesser who waits out every lock gets 5 tries per hour, not per
// 15 minutes (#29).
func lockoutFor(n int) time.Duration {
	d := LockoutDuration
	for i := 1; i < n && d < MaxLockout; i++ {
		d *= 2
	}
	return min(d, MaxLockout)
}

// attempt runs check on device name under the lockout policy and persists
// the outcome: a failure counts (and may lock), a success resets. op names
// the operation in the lockout metric. owns, when set, runs before the
// lock is read, so a missing device, a device of another user and a locked
// device of another user all answer ErrNotAssociated alike.
func (s *Service) attempt(
	ctx context.Context, op, name string, owns func(iam.MfaDevice) bool, check func(d *iam.MfaDevice) (bool, error),
) error {
	return s.attemptIf(ctx, op, name, nil, owns, check)
}

// attemptIf is attempt whose device write commits only while pre is
// unchanged when pre is set; then a conflict is returned, not retried.
func (s *Service) attemptIf(
	ctx context.Context, op, name string, pre *store.Pre,
	owns func(iam.MfaDevice) bool, check func(d *iam.MfaDevice) (bool, error),
) error {
	var verr error
	locked := false
	err := mutateIf(ctx, s.b, name, pre, func(d *iam.MfaDevice) error {
		verr, locked = nil, false
		if owns != nil && !owns(*d) {
			return ErrNotAssociated
		}
		now := s.now().UTC()
		if now.Before(d.LockedUntil) {
			verr = ErrLocked
			return errNoWrite
		}
		ok, err := check(d)
		if err != nil {
			return err
		}
		if !d.LockedUntil.IsZero() { // lock expired
			d.LockedUntil, d.LockedSince, d.FailedAttempts = time.Time{}, time.Time{}, 0
		}
		if ok {
			d.FailedAttempts, d.Lockouts = 0, 0
			return nil
		}
		d.FailedAttempts++
		verr = ErrInvalidCode
		if d.FailedAttempts >= MaxFailedAttempts {
			d.Lockouts++
			d.LockedUntil, d.LockedSince, d.FailedAttempts = now.Add(lockoutFor(d.Lockouts)), now, 0
			verr, locked = ErrLocked, true
		}
		return nil
	})
	switch {
	case errors.Is(err, errNoWrite):
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("mfa device %s: %w", name, ErrNotAssociated)
	case err != nil:
		return fmt.Errorf("mfa device %s: %w", name, err)
	}
	if locked {
		countLockout(ctx, op, lockStarted)
	}
	if verr != nil {
		return fmt.Errorf("mfa device %s: %w", name, verr)
	}
	return nil
}

// errNoWrite ends a Mutate without writing.
var errNoWrite = errors.New("no write")

// mutateIf is store.Mutate on an MFA device; with pre the write is
// store.UpdateIf on pre and a conflict ends it.
func mutateIf(ctx context.Context, b store.Backend, name string, pre *store.Pre, fn func(*iam.MfaDevice) error) error {
	if pre == nil {
		_, err := store.Mutate(ctx, b, name, fn)
		return err
	}
	cur, err := store.Get[iam.MfaDevice](ctx, b, name)
	if err != nil {
		return err
	}
	if err := fn(&cur.Object); err != nil {
		return err
	}
	_, err = store.UpdateIf(ctx, b, cur.Object, cur.Version, *pre)
	return err
}

// Enrollment is returned once by CreateVirtual. Never log it.
type Enrollment struct {
	SerialNumber string
	Base32Seed   string
	URI          string // otpauth:// for a QR code
}

// String hides the seed.
func (e Enrollment) String() string { return "Enrollment{" + e.SerialNumber + " seed=REDACTED}" }

// Service manages devices.
type Service struct {
	b       store.Backend
	keys    *secret.Keyring
	account string
	now     func() time.Time
}

// New returns a Service. now may be nil.
func New(b store.Backend, keys *secret.Keyring, account string, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{b: b, keys: keys, account: account, now: now}
}

func aad(name string) string { return string(iam.KindMfaDevice) + "/" + store.Fold(name) }

// Serial is a device's serial number (ARN), including its path.
func (s *Service) Serial(d iam.MfaDevice) string { return iam.MfaDeviceARN(s.account, d) }

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// CreateVirtual makes an unassigned device at path and returns its seed,
// once. Path is part of the serial number and must be empty or end in "/".
// A name and path whose serial number is longer than
// iam.MaxSerialNumberLen are invalid: no call could name the device.
func (s *Service) CreateVirtual(ctx context.Context, name, path string) (_ Enrollment, err error) {
	ctx, end := start(ctx, "CreateVirtual")
	defer end(&err)
	if n := len(s.Serial(iam.MfaDevice{Name: name, Path: path})); n > iam.MaxSerialNumberLen {
		return Enrollment{}, fmt.Errorf("create mfa device %s: %w: serial number of %d characters, at most %d",
			name, iam.ErrInvalid, n, iam.MaxSerialNumberLen)
	}
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return Enrollment{}, fmt.Errorf("create mfa device %s: seed: %w", name, err)
	}
	sealed, err := s.keys.Seal(seed, aad(name))
	if err != nil {
		return Enrollment{}, fmt.Errorf("create mfa device %s: seal seed: %w", name, err)
	}
	d := iam.MfaDevice{Name: name, Path: path, Created: s.now().UTC(), Seed: sealed}
	if _, err := store.Create(ctx, s.b, d); err != nil {
		return Enrollment{}, fmt.Errorf("create mfa device %s: %w", name, err)
	}
	enc := b32.EncodeToString(seed)
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/VWS:" + name, RawQuery: url.Values{"secret": {enc}, "issuer": {"VWS"}, "period": {"30"}, "digits": {"6"}}.Encode()}
	return Enrollment{SerialNumber: s.Serial(d), Base32Seed: enc, URI: u.String()}, nil
}

func (s *Service) seed(d iam.MfaDevice) ([]byte, error) {
	seed, err := s.keys.Open(d.Seed, aad(d.Name))
	if err != nil {
		return nil, fmt.Errorf("open seed: %w", err)
	}
	return seed, nil
}

// maxEnableAttempts bounds how often Enable reads the user again after
// an unrelated change of the user beat its device write.
const maxEnableAttempts = 8

// Enable assigns device name to user after two consecutive codes. The
// device write commits only while the user is unchanged since it was
// read (store.UpdateIf), so it never lands after a rename or delete of
// that user (#134): the user gone is NotFound, renaming or replaced by
// another user under the name is ErrRenaming or ErrConflict.
func (s *Service) Enable(ctx context.Context, user, name, code1, code2 string) (err error) {
	return s.EnableChecked(ctx, user, name, code1, code2, nil)
}

// EnableChecked checks the user before the quota lease changes its version.
// The lease and slot claim carry that version forward by CAS, then UpdateIf
// commits the device on it. A guarded call never retries a conflicting write
// against a user version the caller did not authorize.
func (s *Service) EnableChecked(
	ctx context.Context, user, name, code1, code2 string, check func(store.Versioned[iam.User]) error,
) (err error) {
	ctx, end := start(ctx, "Enable")
	defer end(&err)
	locked, unlock, err := s.lockMFAChecked(ctx, user, check)
	if err != nil {
		return fmt.Errorf("enable mfa device %s: user %q: %w", name, user, err)
	}
	defer unlock()
	holder := locked.Object.MFARegistrationLease.Holder
	uid := ""
	for attempt := 0; ; attempt++ {
		u, err := store.Get[iam.User](ctx, s.b, user)
		if err != nil {
			return fmt.Errorf("enable mfa device %s: user %q: %w", name, user, err)
		}
		if u.Object.Renaming() {
			return fmt.Errorf("user %q: %w", user, store.ErrRenaming)
		}
		if check != nil && u.Version != locked.Version {
			return fmt.Errorf("enable mfa device %s: %w", name, store.ErrConflict)
		}
		if uid != "" && u.Object.UID != uid {
			return fmt.Errorf("user %q was replaced: %w", user, store.ErrConflict)
		}
		uid = u.Object.UID
		d, err := store.Get[iam.MfaDevice](ctx, s.b, name)
		if err != nil {
			return fmt.Errorf("enable mfa device %s: %w", name, err)
		}
		if d.Object.Enabled {
			return fmt.Errorf("enable mfa device %s: %w", name, ErrEntityInUse)
		}
		pre, err := s.claimMFASlot(ctx, u, holder, false)
		if errors.Is(err, store.ErrConflict) && check == nil && attempt+1 < maxEnableAttempts {
			continue
		}
		if err != nil {
			return fmt.Errorf("enable mfa device %s: %w", name, err)
		}
		err = s.enable(ctx, u.Object.Name, name, code1, code2, &pre)
		if errors.Is(err, store.ErrConflict) && check == nil && attempt+1 < maxEnableAttempts {
			continue
		}
		if err != nil {
			return err
		}
		return s.checkEnabledFor(ctx, user, uid, name)
	}
}

// checkEnabledFor undoes an Enable whose user is gone or another user
// under the same name by the time the device committed. A backend whose
// versions can repeat across a delete and create (the fake API server of
// the tests) would otherwise let the conditional write through.
func (s *Service) checkEnabledFor(ctx context.Context, user, uid, name string) error {
	u, err := store.Get[iam.User](ctx, s.b, user)
	if err == nil && u.Object.UID == uid && !u.Object.Renaming() {
		return nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("enable mfa device %s: recheck user %q: %w", name, user, err)
	}
	if derr := s.deactivate(context.WithoutCancel(ctx), user, name); derr != nil && !errors.Is(derr, ErrNotAssociated) {
		return errors.Join(fmt.Errorf("user %q changed: %w", user, store.ErrConflict), derr)
	}
	return fmt.Errorf("user %q changed: %w", user, store.ErrConflict)
}

func (s *Service) enable(ctx context.Context, user, name, code1, code2 string, pre *store.Pre) error {
	// Both codes must lie within ±Skew of now: code1 at step cur-1 or cur,
	// code2 at the next step.
	return s.attemptIf(ctx, "Enable", name, pre, nil, func(d *iam.MfaDevice) (bool, error) {
		if d.Enabled {
			return false, ErrEntityInUse
		}
		seed, err := s.seed(*d)
		if err != nil {
			return false, err
		}
		cur := totp.Step(s.now())
		first, ok := totp.Match(seed, code1, s.now(), Skew)
		if !ok || first+1 > cur+Skew || first+1 <= d.LastStep || !totp.Equal(totp.Code(seed, first+1, totp.Digits), code2) {
			return false, nil
		}
		d.UserName, d.Enabled, d.LastStep, d.EnableTime, d.Drift = user, true, first+1, s.now().UTC(), 0
		return true, nil
	})
}

// Deactivate unassigns an enabled device from user.
func (s *Service) Deactivate(ctx context.Context, user, name string) (err error) {
	ctx, end := start(ctx, "Deactivate")
	defer end(&err)
	return s.deactivate(ctx, user, name)
}

func (s *Service) deactivate(ctx context.Context, user, name string) error {
	_, err := store.Mutate(ctx, s.b, name, func(d *iam.MfaDevice) error {
		if !d.Enabled || store.Fold(d.UserName) != store.Fold(user) {
			return ErrNotAssociated
		}
		d.Enabled, d.UserName, d.EnableTime = false, "", time.Time{}
		return nil
	})
	if err != nil {
		return fmt.Errorf("deactivate mfa device %s: %w", name, err)
	}
	return nil
}

// Delete removes an unassigned device.
func (s *Service) Delete(ctx context.Context, name string) (err error) {
	ctx, end := start(ctx, "Delete")
	defer end(&err)
	d, err := store.Get[iam.MfaDevice](ctx, s.b, name)
	if err != nil {
		return fmt.Errorf("delete mfa device %s: %w", name, err)
	}
	if d.Object.Enabled {
		return fmt.Errorf("delete mfa device %s: %w", name, ErrEntityInUse)
	}
	if err := store.Delete[iam.MfaDevice](ctx, s.b, name, d.Version); err != nil {
		return fmt.Errorf("delete mfa device %s: %w", name, err)
	}
	return nil
}

// List returns user's enabled devices, or every device when user is "".
// Seeds are stripped.
func (s *Service) List(ctx context.Context, user string) (_ []iam.MfaDevice, err error) {
	ctx, end := start(ctx, "List")
	defer end(&err)
	return s.list(ctx, user)
}

func (s *Service) list(ctx context.Context, user string) ([]iam.MfaDevice, error) {
	all, err := store.List[iam.MfaDevice](ctx, s.b)
	if err != nil {
		return nil, fmt.Errorf("list mfa devices: %w", err)
	}
	var out []iam.MfaDevice
	for _, d := range all {
		if user == "" || (d.Object.Enabled && store.Fold(d.Object.UserName) == store.Fold(user)) {
			d.Object.Seed = iam.Sealed{}
			out = append(out, d.Object)
		}
	}
	return out, nil
}

// Verify checks code for user's enabled device and consumes its step. On
// success the request carries aws:MultiFactorAuthPresent=true.
func (s *Service) Verify(ctx context.Context, user, name, code string) (err error) {
	ctx, end := start(ctx, "Verify")
	defer end(&err)
	return s.attempt(ctx, "Verify", name, s.enabledFor(user, ""), func(d *iam.MfaDevice) (bool, error) {
		return s.verifyCode(code, d)
	})
}

// VerifySerial checks code for the device named by serial. serial must be
// exactly the device's ARN, including its path.
func (s *Service) VerifySerial(ctx context.Context, user, serial, code string) (err error) {
	ctx, end := start(ctx, "VerifySerial")
	defer end(&err)
	name, _, ok := iam.SplitMfaDeviceARN(s.account, serial)
	if !ok {
		return fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
	}
	return s.attempt(ctx, "VerifySerial", name, s.enabledFor(user, serial), func(d *iam.MfaDevice) (bool, error) {
		return s.verifyCode(code, d)
	})
}

// enabledFor reports whether a device is enabled for user and, when serial
// is set, has exactly that serial number.
func (s *Service) enabledFor(user, serial string) func(iam.MfaDevice) bool {
	return func(d iam.MfaDevice) bool {
		return d.Enabled && store.Fold(d.UserName) == store.Fold(user) && (serial == "" || s.Serial(d) == serial)
	}
}

func (s *Service) verifyCode(code string, d *iam.MfaDevice) (bool, error) {
	seed, err := s.seed(*d)
	if err != nil {
		return false, err
	}
	step, ok := totp.Match(seed, code, s.now().Add(time.Duration(d.Drift)*totp.Period), Skew)
	// Mutate rereads on a conflict, so two racing uses of one code
	// see each other's LastStep and only one wins.
	if !ok || step <= d.LastStep {
		return false, nil
	}
	d.LastStep = step
	return true, nil
}

// Resync is IAM ResyncMFADevice: it finds code1 and code2 as two
// consecutive codes within ±ResyncSkew steps of now and stores the
// device's drift, so Verify then checks codes around the device's clock.
// serial must be exactly the ARN of a device enabled for user, else
// ErrNotAssociated. The steps must be newer than the last accepted one,
// and the second becomes it, so a code is never accepted twice: a repeat
// of a request that succeeded is ErrInvalidCode, and of racing requests
// with the same codes only one succeeds. A wrong pair counts towards the
// lockout like a wrong Verify code. Never log the codes.
func (s *Service) Resync(ctx context.Context, user, serial, code1, code2 string) (err error) {
	ctx, end := start(ctx, "Resync")
	defer end(&err)
	name, _, ok := iam.SplitMfaDeviceARN(s.account, serial)
	if !ok {
		return fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
	}
	return s.attempt(ctx, "Resync", name, s.enabledFor(user, serial), func(d *iam.MfaDevice) (bool, error) {
		seed, err := s.seed(*d)
		if err != nil {
			return false, err
		}
		cur := totp.Step(s.now())
		first, ok := totp.MatchPair(seed, code1, code2, max(cur-ResyncSkew, d.LastStep+1), cur+ResyncSkew-1)
		if !ok {
			return false, nil
		}
		d.LastStep, d.Drift = first+1, first+1-cur
		return true, nil
	})
}

// Required reports whether user has an enabled device (login needs a code).
func (s *Service) Required(ctx context.Context, user string) (_ bool, err error) {
	ctx, end := start(ctx, "Required")
	defer end(&err)
	ds, err := s.list(ctx, user)
	return len(ds) > 0, err
}
