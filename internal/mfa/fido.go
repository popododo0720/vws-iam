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
// registrations race (the store create admits one). The device is bound
// to the user's UID and committed by a write to the user (claimUser): a
// DeleteUser that checked the user's keys before that write fails its
// versioned delete, and if the user is deleted first the device is
// removed again and the call is ErrNotAssociated. A device left by a
// crash in that window belongs to nobody (see owned). A missing user is
// ErrNotAssociated; invalid input is iam.ErrInvalid and stores nothing.
func (s *Service) RegisterFido(ctx context.Context, user, label string, c FidoCredential) (iam.FidoDevice, error) {
	u, err := store.Get[iam.User](ctx, s.b, user)
	if errors.Is(err, store.ErrNotFound) {
		return iam.FidoDevice{}, fmt.Errorf("user %q: %w", user, ErrNotAssociated)
	}
	if err != nil {
		return iam.FidoDevice{}, fmt.Errorf("register fido device: %w", err)
	}
	if u.Object.UID == "" {
		return iam.FidoDevice{}, fmt.Errorf("register fido device: user %q has no uid", user)
	}
	d := iam.FidoDevice{
		ID: iam.FidoID(c.ID), UserName: u.Object.Name, UserUID: u.Object.UID, Label: label,
		CredentialID: c.ID, PublicKey: c.PublicKey, AAGUID: c.AAGUID, SignCount: c.SignCount,
		EnableTime: s.now().UTC(), Certifications: maps.Clone(c.Certifications),
	}
	d.UID, d.Generation = iam.NewUID(), 1
	if err := d.Validate(); err != nil {
		return iam.FidoDevice{}, err
	}
	v, err := s.createFido(ctx, d)
	if err != nil {
		return iam.FidoDevice{}, err
	}
	// Commit by writing the user. A DeleteUser that listed this user's
	// keys before the create deletes at the version it read, so it either
	// deletes first (claim sees the user gone and the create is undone)
	// or loses its versioned delete to this write.
	if err := s.claimUser(ctx, d, u); err != nil {
		if derr := store.Delete[iam.FidoDevice](ctx, s.b, d.ID, v); derr != nil && !errors.Is(derr, store.ErrNotFound) {
			return iam.FidoDevice{}, fmt.Errorf("register fido device: undo: %w", derr)
		}
		return iam.FidoDevice{}, err
	}
	return d, nil
}

// maxClaimAttempts bounds the user writes of one registration when other
// updates of the same user keep winning.
const maxClaimAttempts = 8

// claimUser bumps the FIDO registration count of d's user, starting from
// u, the version read before d was created. The user must still exist
// with d's UID, else ErrNotAssociated. A write that loses to an unrelated
// update of the user reads it again and retries.
func (s *Service) claimUser(ctx context.Context, d iam.FidoDevice, u store.Versioned[iam.User]) error {
	for attempt := 1; ; attempt++ {
		if u.Object.UID != d.UserUID {
			return fmt.Errorf("user %q: %w", d.UserName, ErrNotAssociated)
		}
		u.Object.FidoRegistrations++
		_, err := store.Update(ctx, s.b, u.Object, u.Version)
		if err == nil {
			return nil
		}
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("user %q: %w", d.UserName, ErrNotAssociated)
		}
		if !errors.Is(err, store.ErrConflict) || attempt == maxClaimAttempts {
			return fmt.Errorf("register fido device: %w", err)
		}
		u, err = store.Get[iam.User](ctx, s.b, d.UserName)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("user %q: %w", d.UserName, ErrNotAssociated)
		}
		if err != nil {
			return fmt.Errorf("register fido device: %w", err)
		}
	}
}

// createFido stores d. A device already stored under d's id that belongs
// to nobody (its user is gone or was created again) is replaced; one that
// is owned is ErrEntityInUse.
func (s *Service) createFido(ctx context.Context, d iam.FidoDevice) (string, error) {
	for range 4 {
		v, err := store.Create(ctx, s.b, d)
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, store.ErrExists) {
			return "", fmt.Errorf("register fido device: %w", err)
		}
		cur, err := store.Get[iam.FidoDevice](ctx, s.b, d.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("register fido device: %w", err)
		}
		ok, err := s.owned(ctx, cur.Object)
		if err != nil {
			return "", fmt.Errorf("register fido device: %w", err)
		}
		if ok {
			return "", fmt.Errorf("fido credential already registered: %w", ErrEntityInUse)
		}
		if err := store.Delete[iam.FidoDevice](ctx, s.b, d.ID, cur.Version); err != nil &&
			!errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrConflict) {
			return "", fmt.Errorf("register fido device: remove orphan: %w", err)
		}
	}
	return "", fmt.Errorf("register fido device %q: %w", d.ID, store.ErrConflict)
}

// owned reports whether d's user still exists and is the user d was
// registered to (same UID). A device that is not owned is treated as
// absent: a user deleted and created again under the same name does not
// inherit it.
func (s *Service) owned(ctx context.Context, d iam.FidoDevice) (bool, error) {
	u, err := store.Get[iam.User](ctx, s.b, d.UserName)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return u.Object.UID == d.UserUID, nil
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
	if ok, err := s.owned(ctx, v.Object); err != nil {
		return iam.FidoDevice{}, fmt.Errorf("get fido device: %w", err)
	} else if !ok {
		return iam.FidoDevice{}, fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
	}
	return v.Object, nil
}

// ListFido returns user's FIDO devices, or every one when user is "".
// Devices that belong to nobody (see owned) are skipped.
func (s *Service) ListFido(ctx context.Context, user string) ([]iam.FidoDevice, error) {
	all, err := store.List[iam.FidoDevice](ctx, s.b)
	if err != nil {
		return nil, fmt.Errorf("list fido devices: %w", err)
	}
	owners := map[string]string{} // folded user name -> current UID, "" if none
	var out []iam.FidoDevice
	for _, v := range all {
		d := v.Object
		if user != "" && store.Fold(d.UserName) != store.Fold(user) {
			continue
		}
		uid, seen := owners[store.Fold(d.UserName)]
		if !seen {
			u, err := store.Get[iam.User](ctx, s.b, d.UserName)
			switch {
			case err == nil:
				uid = u.Object.UID
			case !errors.Is(err, store.ErrNotFound):
				return nil, fmt.Errorf("list fido devices: %w", err)
			}
			owners[store.Fold(d.UserName)] = uid
		}
		if uid != "" && uid == d.UserUID {
			out = append(out, d)
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
	if ok, err := s.owned(ctx, v.Object); err != nil {
		return fmt.Errorf("deactivate fido device: %w", err)
	} else if !ok {
		return fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
	}
	if err := store.Delete[iam.FidoDevice](ctx, s.b, id, v.Version); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("mfa device %q: %w", serial, ErrNotAssociated)
		}
		return fmt.Errorf("deactivate fido device: %w", err)
	}
	return nil
}
