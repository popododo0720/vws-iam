package mfa

import (
	"context"
	"errors"
	"fmt"
	"maps"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// FidoCredential is a WebAuthn credential whose registration ceremony
// (challenge, origin, attestation) was already verified by the caller.
// RegisterFido stores it as given; it does not verify an attestation.
type FidoCredential struct {
	ID        []byte
	PublicKey []byte // COSE_Key, public
	AAGUID    string
	SignCount uint32
	// Certifications are the FIDO Alliance MDS levels of the
	// authenticator model, reported by GetFido.
	Certifications map[string]string
}

// FidoSerial is a FIDO device's serial number (ARN).
func (s *Service) FidoSerial(d iam.FidoDevice) string { return iam.FidoDeviceARN(s.account, d) }

// RegisterFido registers credential c to user under label. The device id
// is derived from the credential id, so registering one credential twice
// in an account is ErrEntityInUse, also after a restart and when two
// registrations race (the store create admits one). A missing user is
// ErrNotAssociated; invalid input is iam.ErrInvalid and stores nothing.
func (s *Service) RegisterFido(ctx context.Context, user, label string, c FidoCredential) (iam.FidoDevice, error) {
	u, err := store.Get[iam.User](ctx, s.b, user)
	if errors.Is(err, store.ErrNotFound) {
		return iam.FidoDevice{}, fmt.Errorf("user %q: %w", user, ErrNotAssociated)
	}
	if err != nil {
		return iam.FidoDevice{}, fmt.Errorf("register fido device: %w", err)
	}
	d := iam.FidoDevice{
		ID: iam.FidoID(c.ID), UserName: u.Object.Name, Label: label,
		CredentialID: c.ID, PublicKey: c.PublicKey, AAGUID: c.AAGUID, SignCount: c.SignCount,
		EnableTime: s.now().UTC(), Certifications: maps.Clone(c.Certifications),
	}
	d.UID, d.Generation = iam.NewUID(), 1
	if _, err := store.Create(ctx, s.b, d); err != nil {
		if errors.Is(err, store.ErrExists) {
			return iam.FidoDevice{}, fmt.Errorf("fido credential already registered: %w", ErrEntityInUse)
		}
		return iam.FidoDevice{}, fmt.Errorf("register fido device: %w", err)
	}
	return d, nil
}

// GetFido returns the FIDO device named by serial, as AWS GetMFADevice.
// serial must be exactly the device's serial number. When user is not
// empty the device must be registered to that user (names compare case
// insensitively, as IAM names do). Every miss, a malformed or virtual
// (mfa/) serial included, is ErrNotAssociated (AWS NoSuchEntity).
func (s *Service) GetFido(ctx context.Context, serial, user string) (iam.FidoDevice, error) {
	owner, id, ok := iam.SplitFidoDeviceARN(s.account, serial)
	if !ok || (user != "" && store.Fold(user) != store.Fold(owner)) {
		return iam.FidoDevice{}, fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
	}
	v, err := store.Get[iam.FidoDevice](ctx, s.b, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && s.FidoSerial(v.Object) != serial) {
		return iam.FidoDevice{}, fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
	}
	if err != nil {
		return iam.FidoDevice{}, fmt.Errorf("get fido device: %w", err)
	}
	return v.Object, nil
}

// ListFido returns user's FIDO devices, or every one when user is "".
func (s *Service) ListFido(ctx context.Context, user string) ([]iam.FidoDevice, error) {
	all, err := store.List[iam.FidoDevice](ctx, s.b)
	if err != nil {
		return nil, fmt.Errorf("list fido devices: %w", err)
	}
	var out []iam.FidoDevice
	for _, v := range all {
		if user == "" || store.Fold(v.Object.UserName) == store.Fold(user) {
			out = append(out, v.Object)
		}
	}
	return out, nil
}

// DeactivateFido removes user's FIDO device serial, as AWS
// DeactivateMFADevice does for a security key: it is deleted, not kept
// unassigned. A device of another user or a missing one is
// ErrNotAssociated; a stale read is store.ErrConflict and deletes nothing.
func (s *Service) DeactivateFido(ctx context.Context, user, serial string) error {
	owner, id, ok := iam.SplitFidoDeviceARN(s.account, serial)
	if !ok || store.Fold(user) != store.Fold(owner) {
		return fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
	}
	v, err := store.Get[iam.FidoDevice](ctx, s.b, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && s.FidoSerial(v.Object) != serial) {
		return fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
	}
	if err != nil {
		return fmt.Errorf("deactivate fido device: %w", err)
	}
	if err := store.Delete[iam.FidoDevice](ctx, s.b, id, v.Version); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
		}
		return fmt.Errorf("deactivate fido device: %w", err)
	}
	return nil
}
