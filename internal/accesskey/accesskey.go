// Package accesskey manages long-term access keys. The secret is returned
// once by Create and stored only sealed; GetSigningCredential opens it for
// SigV4 verification and refuses inactive keys.
package accesskey

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
)

// MaxPerUser is the AWS limit of access keys per user.
const MaxPerUser = 2

// Errors.
var (
	ErrLimitExceeded = errors.New("access key limit exceeded")
	ErrInactive      = errors.New("access key is inactive")
	ErrNoSuchUser    = errors.New("no such user")
)

// Credential is a key and its plaintext secret. Never log it.
type Credential struct {
	AccessKeyID string
	Secret      string
	UserName    string
	Root        bool
}

// String hides the secret from %v and slog.
func (c Credential) String() string {
	return "Credential{" + c.AccessKeyID + " user=" + c.UserName + " secret=REDACTED}"
}

// Service manages access keys.
type Service struct {
	b store.Backend
	// index is the unscoped backend holding the key id -> project index.
	index   store.Backend
	project string
	keys    *secret.Keyring
	now     func() time.Time
}

// New returns the service of project. b is the project's scoped view and
// index the unscoped backend. now may be nil for time.Now.
func New(b, index store.Backend, project string, keys *secret.Keyring, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{b: b, index: index, project: project, keys: keys, now: now}
}

// ProjectOf finds the project of a long-term key id from the index.
func ProjectOf(ctx context.Context, index store.Backend, id string) (string, error) {
	x, err := store.Get[iam.KeyIndex](ctx, index, id)
	if err != nil {
		return "", err
	}
	return x.Object.Project, nil
}

func aad(id string) string { return string(iam.KindAccessKey) + "/" + id }

var idEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewKeyID returns prefix (AKIA or ASIA) and 16 random base32 characters.
func NewKeyID(prefix string) (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("key id: %w", err)
	}
	return prefix + idEnc.EncodeToString(b), nil
}

// NewSecret returns a 40-character secret access key.
func NewSecret() (string, error) {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Create makes an active key for user and returns its secret, once. It
// does not hold the AccessKeysPerUser count against concurrent creates;
// CreateAccessKey uses CreatePending and Activate under a quota lock.
func (s *Service) Create(ctx context.Context, user string) (Credential, error) {
	name, err := s.checkLimit(ctx, user)
	if err != nil {
		return Credential{}, err
	}
	return s.Import(ctx, name, "", "", false)
}

// CreatePending is Create that stores the key as KeyPending, so it
// authenticates nothing and is not counted until Activate commits it. It
// returns the key's version for Activate. requestID, when not empty, is
// stored with the key for ByRequestID.
func (s *Service) CreatePending(ctx context.Context, user, requestID string) (Credential, string, error) {
	name, err := s.checkLimit(ctx, user)
	if err != nil {
		return Credential{}, "", err
	}
	return s.put(ctx, name, "", "", false, iam.KeyPending, requestID)
}

// ByRequestID returns the id of user's committed (active or inactive) key
// created with requestID, if there is one. Pending keys are left out: one
// is never activated once its writer's quota lock hold has ended, and the
// next create removes it.
func (s *Service) ByRequestID(ctx context.Context, user, requestID string) (string, bool, error) {
	all, err := store.List[iam.AccessKey](ctx, s.b)
	if err != nil {
		return "", false, err
	}
	for _, k := range all {
		o := k.Object
		if !o.Root && o.Status != iam.KeyPending && o.RequestID == requestID && store.Fold(o.UserName) == store.Fold(user) {
			return o.ID, true, nil
		}
	}
	return "", false, nil
}

// Activate makes the pending key id, still at version, active only while
// pre holds (store.UpdateIf). If pre moved, the key stays pending and the
// error is store.ErrConflict.
func (s *Service) Activate(ctx context.Context, id, version string, pre store.Pre) error {
	k, err := store.Get[iam.AccessKey](ctx, s.b, id)
	if err != nil {
		return err
	}
	if k.Version != version || k.Object.Status != iam.KeyPending {
		return store.ErrConflict
	}
	k.Object.Status = iam.KeyActive
	k.Object.Reserved = false
	_, err = store.UpdateIf(ctx, s.b, k.Object, k.Version, pre)
	return err
}

// Reserve marks the pending key id, still at version, reserved while pre
// holds (store.UpdateIf) and returns its new version. The key stays
// pending, so Activate can then commit it under another precondition. If
// pre moved, the key is unchanged and the error is store.ErrConflict.
func (s *Service) Reserve(ctx context.Context, id, version string, pre store.Pre) (string, error) {
	k, err := store.Get[iam.AccessKey](ctx, s.b, id)
	if err != nil {
		return "", err
	}
	if k.Version != version || k.Object.Status != iam.KeyPending {
		return "", store.ErrConflict
	}
	k.Object.Reserved = true
	return store.UpdateIf(ctx, s.b, k.Object, k.Version, pre)
}

// SweepPending removes user's pending keys and their index entries while
// pre holds. The caller holds the quota lock pre names: a pending key
// that exists then was written under an older hold, so Activate can never
// commit it. Pending keys are never counted, so the sweep is housekeeping:
// only store.ErrConflict (pre moved) is returned; other failures leave the
// key for the next sweep.
func (s *Service) SweepPending(ctx context.Context, user string, pre store.Pre) error {
	all, err := store.List[iam.AccessKey](ctx, s.b)
	if err != nil {
		return err
	}
	for _, k := range all {
		if k.Object.Status != iam.KeyPending || k.Object.Root || store.Fold(k.Object.UserName) != store.Fold(user) {
			continue
		}
		if err := s.DeletePending(ctx, k.Object.ID, k.Version, &pre); errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return nil
}

// DeletePending removes the pending key id at version and its index
// entry; with pre, only while pre holds. A key already gone is not an
// error.
func (s *Service) DeletePending(ctx context.Context, id, version string, pre *store.Pre) error {
	var err error
	if pre != nil {
		err = store.DeleteIf[iam.AccessKey](ctx, s.b, id, version, *pre)
	} else {
		err = store.Delete[iam.AccessKey](ctx, s.b, id, version)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("remove pending key: %w", err)
	}
	if err := store.Delete[iam.KeyIndex](ctx, s.index, id, ""); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("remove pending key index: %w", err)
	}
	return nil
}

// checkLimit returns user's stored name if it has fewer than MaxPerUser
// keys.
func (s *Service) checkLimit(ctx context.Context, user string) (string, error) {
	u, err := store.Get[iam.User](ctx, s.b, user)
	if errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("%q: %w", user, ErrNoSuchUser)
	}
	if err != nil {
		return "", err
	}
	n, err := s.count(ctx, u.Object.Name)
	if err != nil {
		return "", err
	}
	if n >= MaxPerUser {
		return "", ErrLimitExceeded
	}
	return u.Object.Name, nil
}

// Import stores a key with a given id and secret (bootstrap of the
// existing console-api credential), or generates both when empty. A root
// key has no user. The index entry is written first, so a crash leaves at
// worst an index entry without a key, which authenticates nothing.
func (s *Service) Import(ctx context.Context, user, id, sec string, root bool) (Credential, error) {
	cred, _, err := s.put(ctx, user, id, sec, root, iam.KeyActive, "")
	return cred, err
}

func (s *Service) put(
	ctx context.Context, user, id, sec string, root bool, st iam.KeyStatus, requestID string,
) (Credential, string, error) {
	var err error
	if id == "" {
		if id, err = NewKeyID("AKIA"); err != nil {
			return Credential{}, "", err
		}
	}
	if sec == "" {
		if sec, err = NewSecret(); err != nil {
			return Credential{}, "", err
		}
	}
	sealed, err := s.keys.Seal([]byte(sec), aad(id))
	if err != nil {
		return Credential{}, "", err
	}
	k := iam.AccessKey{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1, RequestID: requestID}, ID: id, UserName: user, Root: root,
		Status: st, Created: s.now().UTC(), Secret: sealed,
	}
	if err := k.Validate(); err != nil {
		return Credential{}, "", err
	}
	if _, err := store.Create(ctx, s.index, iam.KeyIndex{ID: id, Project: s.project}); err != nil {
		return Credential{}, "", err
	}
	v, err := store.Create(ctx, s.b, k)
	if err != nil {
		return Credential{}, "", err
	}
	return Credential{AccessKeyID: id, Secret: sec, UserName: user}, v, nil
}

func (s *Service) count(ctx context.Context, user string) (int, error) {
	ks, err := s.List(ctx, user)
	return len(ks), err
}

// List returns user's keys, sealed secrets stripped. Pending keys are
// left out.
func (s *Service) List(ctx context.Context, user string) ([]iam.AccessKey, error) {
	all, err := store.List[iam.AccessKey](ctx, s.b)
	if err != nil {
		return nil, err
	}
	var out []iam.AccessKey
	for _, k := range all {
		if !k.Object.Root && k.Object.Status != iam.KeyPending && store.Fold(k.Object.UserName) == store.Fold(user) {
			k.Object.Secret = iam.Sealed{}
			out = append(out, k.Object)
		}
	}
	return out, nil
}

func (s *Service) owned(ctx context.Context, user, id string) (store.Versioned[iam.AccessKey], error) {
	k, err := store.Get[iam.AccessKey](ctx, s.b, id)
	if err != nil {
		return k, err
	}
	if k.Object.Root || k.Object.Status == iam.KeyPending || store.Fold(k.Object.UserName) != store.Fold(user) {
		return k, store.ErrNotFound
	}
	return k, nil
}

// SetStatus makes a key Active or Inactive.
func (s *Service) SetStatus(ctx context.Context, user, id string, st iam.KeyStatus) error {
	if _, err := s.owned(ctx, user, id); err != nil {
		return err
	}
	_, err := store.Mutate(ctx, s.b, id, func(k *iam.AccessKey) error {
		if k.Status != st {
			k.Status = st
			k.Generation++
			k.Updated = s.now().UTC()
		}
		return nil
	})
	return err
}

// Delete removes a key of user.
func (s *Service) Delete(ctx context.Context, user, id string) error {
	return s.DeleteChecked(ctx, user, id, nil)
}

// DeleteChecked removes a key of user like Delete. check, when not nil,
// runs on the read of the key that guards the delete; an error from it
// deletes nothing. A precondition it returns (ok) is committed with the
// delete (store.DeleteIf), so the object check read cannot change in
// between.
func (s *Service) DeleteChecked(
	ctx context.Context, user, id string, check func(iam.AccessKey) (pre store.Pre, ok bool, err error),
) error {
	k, err := s.owned(ctx, user, id)
	if err != nil {
		return err
	}
	var (
		pre store.Pre
		ok  bool
	)
	if check != nil {
		if pre, ok, err = check(k.Object); err != nil {
			return err
		}
	}
	if ok {
		err = store.DeleteIf[iam.AccessKey](ctx, s.b, id, k.Version, pre)
	} else {
		err = store.Delete[iam.AccessKey](ctx, s.b, id, k.Version)
	}
	if err != nil {
		return err
	}
	if err := store.Delete[iam.KeyIndex](ctx, s.index, id, ""); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// Get returns one key of user without its sealed secret.
func (s *Service) Get(ctx context.Context, user, id string) (store.Versioned[iam.AccessKey], error) {
	k, err := s.owned(ctx, user, id)
	k.Object.Secret = iam.Sealed{}
	return k, err
}

// MarkUsed records the last use of a key. Errors are not fatal to callers.
func (s *Service) MarkUsed(ctx context.Context, id, service, region string) error {
	_, err := store.Mutate(ctx, s.b, id, func(k *iam.AccessKey) error {
		k.LastUsed, k.LastUsedService, k.LastUsedRegion = s.now().UTC().Truncate(time.Second), service, region
		return nil
	})
	return err
}

// GetSigningCredential returns the secret for SigV4 verification. An
// unknown or inactive key is refused. A key sealed under an older KEK is
// resealed with the active one.
func (s *Service) GetSigningCredential(ctx context.Context, id string) (Credential, error) {
	k, err := store.Get[iam.AccessKey](ctx, s.b, id)
	if err != nil {
		return Credential{}, err
	}
	if k.Object.Status != iam.KeyActive {
		return Credential{}, ErrInactive
	}
	plain, err := s.keys.Open(k.Object.Secret, aad(k.Object.ID))
	if err != nil {
		return Credential{}, err
	}
	if s.keys.NeedsRewrap(k.Object.Secret) {
		if sealed, err := s.keys.Seal(plain, aad(k.Object.ID)); err == nil {
			k.Object.Secret = sealed
			// A lost race only delays the rewrap to the next read.
			if _, err := store.Update(ctx, s.b, k.Object, k.Version); err != nil && !errors.Is(err, store.ErrConflict) {
				return Credential{}, err
			}
		}
	}
	return Credential{AccessKeyID: k.Object.ID, Secret: string(plain), UserName: k.Object.UserName, Root: k.Object.Root}, nil
}
