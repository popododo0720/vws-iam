// Package mfa manages virtual TOTP MFA devices. The seed is shown once at
// creation and stored only sealed. Enabling needs two consecutive codes.
// Each accepted code advances the device's last step, so a code is never
// accepted twice. MaxFailedAttempts wrong codes in a row lock the device
// for LockoutDuration; the counter is stored, so a restart does not reset it.
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

// Brute-force limits: a 6-digit code space of 10^6 with ±1 step allows
// about 3 hits per million guesses, so 5 tries per 15 minutes bounds an
// online attack to well under 1% per year.
const (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
)

// attempt runs check on device name under the lockout policy and persists
// the outcome: a failure counts (and may lock), a success resets.
func (s *Service) attempt(ctx context.Context, name string, check func(d *iam.MfaDevice) (bool, error)) error {
	return s.attemptIf(ctx, name, nil, check)
}

// attemptIf is attempt whose device write commits only while pre is
// unchanged when pre is set; then a conflict is returned, not retried.
func (s *Service) attemptIf(
	ctx context.Context, name string, pre *store.Pre, check func(d *iam.MfaDevice) (bool, error),
) error {
	var verr error
	err := mutateIf(ctx, s.b, name, pre, func(d *iam.MfaDevice) error {
		verr = nil
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
			d.FailedAttempts = 0
			return nil
		}
		d.FailedAttempts++
		verr = ErrInvalidCode
		if d.FailedAttempts >= MaxFailedAttempts {
			d.LockedUntil, d.LockedSince, d.FailedAttempts = now.Add(LockoutDuration), now, 0
			verr = ErrLocked
		}
		return nil
	})
	if errors.Is(err, errNoWrite) {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("mfa device %s: %w", name, err)
	}
	return verr
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
func (s *Service) CreateVirtual(ctx context.Context, name, path string) (Enrollment, error) {
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return Enrollment{}, fmt.Errorf("seed: %w", err)
	}
	sealed, err := s.keys.Seal(seed, aad(name))
	if err != nil {
		return Enrollment{}, err
	}
	d := iam.MfaDevice{Name: name, Path: path, Created: s.now().UTC(), Seed: sealed}
	if _, err := store.Create(ctx, s.b, d); err != nil {
		return Enrollment{}, err
	}
	enc := b32.EncodeToString(seed)
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/VWS:" + name, RawQuery: url.Values{"secret": {enc}, "issuer": {"VWS"}, "period": {"30"}, "digits": {"6"}}.Encode()}
	return Enrollment{SerialNumber: s.Serial(d), Base32Seed: enc, URI: u.String()}, nil
}

func (s *Service) seed(d iam.MfaDevice) ([]byte, error) { return s.keys.Open(d.Seed, aad(d.Name)) }

// maxEnableAttempts bounds how often Enable reads the user again after
// an unrelated change of the user beat its device write.
const maxEnableAttempts = 8

// Enable assigns device name to user after two consecutive codes. The
// device write commits only while the user is unchanged since it was
// read (store.UpdateIf), so it never lands after a rename or delete of
// that user (#134): the user gone is NotFound, renaming or replaced by
// another user under the name is ErrRenaming or ErrConflict.
func (s *Service) Enable(ctx context.Context, user, name, code1, code2 string) error {
	uid := ""
	for attempt := 0; ; attempt++ {
		u, err := store.Get[iam.User](ctx, s.b, user)
		if err != nil {
			return err
		}
		if u.Object.Renaming() {
			return fmt.Errorf("user %q: %w", user, store.ErrRenaming)
		}
		if uid != "" && u.Object.UID != uid {
			return fmt.Errorf("user %q was replaced: %w", user, store.ErrConflict)
		}
		uid = u.Object.UID
		pre := store.PreOf(u)
		err = s.enable(ctx, u.Object.Name, name, code1, code2, &pre)
		if errors.Is(err, store.ErrConflict) && attempt+1 < maxEnableAttempts {
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
		return err
	}
	if derr := s.Deactivate(context.WithoutCancel(ctx), user, name); derr != nil && !errors.Is(derr, ErrNotAssociated) {
		return errors.Join(fmt.Errorf("user %q changed: %w", user, store.ErrConflict), derr)
	}
	return fmt.Errorf("user %q changed: %w", user, store.ErrConflict)
}

func (s *Service) enable(ctx context.Context, user, name, code1, code2 string, pre *store.Pre) error {
	// Both codes must lie within ±Skew of now: code1 at step cur-1 or cur,
	// code2 at the next step.
	return s.attemptIf(ctx, name, pre, func(d *iam.MfaDevice) (bool, error) {
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
		d.UserName, d.Enabled, d.LastStep, d.EnableTime = user, true, first+1, s.now().UTC()
		return true, nil
	})
}

// Deactivate unassigns an enabled device from user.
func (s *Service) Deactivate(ctx context.Context, user, name string) error {
	_, err := store.Mutate(ctx, s.b, name, func(d *iam.MfaDevice) error {
		if !d.Enabled || store.Fold(d.UserName) != store.Fold(user) {
			return ErrNotAssociated
		}
		d.Enabled, d.UserName, d.EnableTime = false, "", time.Time{}
		return nil
	})
	return err
}

// Delete removes an unassigned device.
func (s *Service) Delete(ctx context.Context, name string) error {
	d, err := store.Get[iam.MfaDevice](ctx, s.b, name)
	if err != nil {
		return err
	}
	if d.Object.Enabled {
		return ErrEntityInUse
	}
	return store.Delete[iam.MfaDevice](ctx, s.b, name, d.Version)
}

// List returns user's enabled devices, or every device when user is "".
// Seeds are stripped.
func (s *Service) List(ctx context.Context, user string) ([]iam.MfaDevice, error) {
	all, err := store.List[iam.MfaDevice](ctx, s.b)
	if err != nil {
		return nil, err
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
func (s *Service) Verify(ctx context.Context, user, name, code string) error {
	return s.attempt(ctx, name, func(d *iam.MfaDevice) (bool, error) {
		return s.verifyCode(user, code, d)
	})
}

// VerifySerial checks code for the device named by serial. serial must be
// exactly the device's ARN, including its path.
func (s *Service) VerifySerial(ctx context.Context, user, serial, code string) error {
	name, _, ok := iam.SplitMfaDeviceARN(s.account, serial)
	if !ok {
		return ErrNotAssociated
	}
	return s.attempt(ctx, name, func(d *iam.MfaDevice) (bool, error) {
		if s.Serial(*d) != serial {
			return false, ErrNotAssociated
		}
		return s.verifyCode(user, code, d)
	})
}

func (s *Service) verifyCode(user, code string, d *iam.MfaDevice) (bool, error) {
	if !d.Enabled || store.Fold(d.UserName) != store.Fold(user) {
		return false, ErrNotAssociated
	}
	seed, err := s.seed(*d)
	if err != nil {
		return false, err
	}
	step, ok := totp.Match(seed, code, s.now(), Skew)
	// Mutate rereads on a conflict, so two racing uses of one code
	// see each other's LastStep and only one wins.
	if !ok || step <= d.LastStep {
		return false, nil
	}
	d.LastStep = step
	return true, nil
}

// Required reports whether user has an enabled device (login needs a code).
func (s *Service) Required(ctx context.Context, user string) (bool, error) {
	ds, err := s.List(ctx, user)
	return len(ds) > 0, err
}
