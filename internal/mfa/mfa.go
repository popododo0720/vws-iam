// Package mfa manages virtual TOTP MFA devices. The seed is shown once at
// creation and stored only sealed. Enabling needs two consecutive codes.
// Each accepted code advances the device's last step, so a code is never
// accepted twice.
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
)

// Skew is the accepted clock drift in steps.
const Skew = 1

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

// Serial is a device's serial number (ARN).
func (s *Service) Serial(name string) string { return iam.ARN("iam", "", s.account, "mfa/"+name) }

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// CreateVirtual makes an unassigned device and returns its seed, once.
func (s *Service) CreateVirtual(ctx context.Context, name string) (Enrollment, error) {
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return Enrollment{}, fmt.Errorf("seed: %w", err)
	}
	sealed, err := s.keys.Seal(seed, aad(name))
	if err != nil {
		return Enrollment{}, err
	}
	d := iam.MfaDevice{Name: name, Created: s.now().UTC(), Seed: sealed}
	if _, err := store.Create(ctx, s.b, d); err != nil {
		return Enrollment{}, err
	}
	enc := b32.EncodeToString(seed)
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/VWS:" + name, RawQuery: url.Values{"secret": {enc}, "issuer": {"VWS"}, "period": {"30"}, "digits": {"6"}}.Encode()}
	return Enrollment{SerialNumber: s.Serial(name), Base32Seed: enc, URI: u.String()}, nil
}

func (s *Service) seed(d iam.MfaDevice) ([]byte, error) { return s.keys.Open(d.Seed, aad(d.Name)) }

// Enable assigns device name to user after two consecutive codes.
func (s *Service) Enable(ctx context.Context, user, name, code1, code2 string) error {
	u, err := store.Get[iam.User](ctx, s.b, user)
	if err != nil {
		return err
	}
	_, err = store.Mutate(ctx, s.b, name, func(d *iam.MfaDevice) error {
		if d.Enabled {
			return ErrEntityInUse
		}
		seed, err := s.seed(*d)
		if err != nil {
			return err
		}
		first, ok := totp.Match(seed, code1, s.now(), Skew+1)
		if !ok || !totp.Equal(totp.Code(seed, first+1, totp.Digits), code2) || first+1 > totp.Step(s.now())+Skew || first+1 <= d.LastStep {
			return ErrInvalidCode
		}
		d.UserName, d.Enabled, d.LastStep = u.Object.Name, true, first+1
		return nil
	})
	return err
}

// Deactivate unassigns an enabled device from user.
func (s *Service) Deactivate(ctx context.Context, user, name string) error {
	_, err := store.Mutate(ctx, s.b, name, func(d *iam.MfaDevice) error {
		if !d.Enabled || store.Fold(d.UserName) != store.Fold(user) {
			return ErrNotAssociated
		}
		d.Enabled, d.UserName = false, ""
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
	_, err := store.Mutate(ctx, s.b, name, func(d *iam.MfaDevice) error {
		if !d.Enabled || store.Fold(d.UserName) != store.Fold(user) {
			return ErrNotAssociated
		}
		seed, err := s.seed(*d)
		if err != nil {
			return err
		}
		step, ok := totp.Match(seed, code, s.now(), Skew)
		// Mutate rereads on a conflict, so two racing uses of one code
		// see each other's LastStep and only one wins.
		if !ok || step <= d.LastStep {
			return ErrInvalidCode
		}
		d.LastStep = step
		return nil
	})
	return err
}

// Required reports whether user has an enabled device (login needs a code).
func (s *Service) Required(ctx context.Context, user string) (bool, error) {
	ds, err := s.List(ctx, user)
	return len(ds) > 0, err
}
