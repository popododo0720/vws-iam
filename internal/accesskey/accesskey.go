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
		return "", fmt.Errorf("access key index: %w", err)
	}
	return x.Object.Project, nil
}

// AccountOf returns the project that owns the key id, of any project,
// for STS GetAccessKeyInfo. It reads the key id -> project index. For a
// long-term key it then reads the key itself, so an index entry left by a
// crash or a key that is still pending (never handed out) is
// store.ErrNotFound, as is an unknown or deleted key. Active and inactive
// keys are both answered: the key's state is not reported (AWS
// semantics). A temporary key of an STS session has only its index entry
// (#188), which answers until the session expires at now, whether or not
// the session was revoked.
func AccountOf(ctx context.Context, index store.Backend, id string, now time.Time) (string, error) {
	x, err := store.Get[iam.KeyIndex](ctx, index, id)
	if err != nil {
		return "", fmt.Errorf("access key index: %w", err)
	}
	pid := x.Object.Project
	if x.Object.Session() {
		if now.After(x.Object.Expires) {
			return "", fmt.Errorf("session key expired: %w", store.ErrNotFound)
		}
		return pid, nil
	}
	k, err := store.Get[iam.AccessKey](ctx, store.Scoped(index, pid), id)
	if err != nil {
		return "", fmt.Errorf("access key: %w", err)
	}
	if k.Object.Status == iam.KeyPending {
		return "", fmt.Errorf("access key is pending: %w", store.ErrNotFound)
	}
	return pid, nil
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
func (s *Service) Create(ctx context.Context, user string) (_ Credential, err error) {
	ctx, end := start(ctx, "Create")
	defer end(&err)
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
func (s *Service) CreatePending(ctx context.Context, user, requestID string) (_ Credential, _ string, err error) {
	ctx, end := start(ctx, "CreatePending")
	defer end(&err)
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
		return "", false, fmt.Errorf("list access keys: %w", err)
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
func (s *Service) Activate(ctx context.Context, id, version string, pre store.Pre) (err error) {
	ctx, end := start(ctx, "Activate")
	defer end(&err)
	k, err := store.Get[iam.AccessKey](ctx, s.b, id)
	if err != nil {
		return fmt.Errorf("activate access key %s: %w", id, err)
	}
	if k.Version != version || k.Object.Status != iam.KeyPending {
		return fmt.Errorf("activate access key %s: not pending at version %s: %w", id, version, store.ErrConflict)
	}
	k.Object.Status = iam.KeyActive
	k.Object.Reserved = false
	if _, err = store.UpdateIf(ctx, s.b, k.Object, k.Version, pre); err != nil {
		return fmt.Errorf("activate access key %s: %w", id, err)
	}
	return nil
}

// Reserve marks the pending key id, still at version, reserved while pre
// holds (store.UpdateIf) and returns its new version. The key stays
// pending, so Activate can then commit it under another precondition. If
// pre moved, the key is unchanged and the error is store.ErrConflict.
func (s *Service) Reserve(ctx context.Context, id, version string, pre store.Pre) (_ string, err error) {
	ctx, end := start(ctx, "Reserve")
	defer end(&err)
	k, err := store.Get[iam.AccessKey](ctx, s.b, id)
	if err != nil {
		return "", fmt.Errorf("reserve access key %s: %w", id, err)
	}
	if k.Version != version || k.Object.Status != iam.KeyPending {
		return "", fmt.Errorf("reserve access key %s: not pending at version %s: %w", id, version, store.ErrConflict)
	}
	k.Object.Reserved = true
	v, err := store.UpdateIf(ctx, s.b, k.Object, k.Version, pre)
	if err != nil {
		return "", fmt.Errorf("reserve access key %s: %w", id, err)
	}
	return v, nil
}

// SweepPending removes user's pending keys and their index entries while
// pre holds. The caller holds the quota lock pre names: a pending key
// that exists then was written under an older hold. A reserved one can
// still be activated under its user's precondition (#139), so the caller
// may count and create only once every pending key is gone. Any failure
// to remove one is returned, store.ErrConflict when pre moved; a key
// already gone is not a failure.
func (s *Service) SweepPending(ctx context.Context, user string, pre store.Pre) (err error) {
	ctx, end := start(ctx, "SweepPending")
	defer end(&err)
	all, err := store.List[iam.AccessKey](ctx, s.b)
	if err != nil {
		return fmt.Errorf("list access keys: %w", err)
	}
	for _, k := range all {
		if k.Object.Status != iam.KeyPending || k.Object.Root || store.Fold(k.Object.UserName) != store.Fold(user) {
			continue
		}
		if err := s.DeletePending(ctx, k.Object.ID, k.Version, &pre); err != nil {
			return err
		}
	}
	return nil
}

// DeletePending removes the pending key id at version and its index
// entry; with pre, only while pre holds. A key already gone is not an
// error.
func (s *Service) DeletePending(ctx context.Context, id, version string, pre *store.Pre) (err error) {
	ctx, end := start(ctx, "DeletePending")
	defer end(&err)
	if pre != nil {
		err = store.DeleteIf[iam.AccessKey](ctx, s.b, id, version, *pre)
	} else {
		err = store.Delete[iam.AccessKey](ctx, s.b, id, version)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("remove pending key %s: %w", id, err)
	}
	if err := store.Delete[iam.KeyIndex](ctx, s.index, id, ""); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("remove pending key index %s: %w", id, err)
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
		return "", fmt.Errorf("user %q: %w", user, err)
	}
	if u.Object.Renaming() {
		// A key made now could name the old user after the rename moved
		// its references (#134).
		return "", fmt.Errorf("user %q: %w", user, store.ErrRenaming)
	}
	n, err := s.count(ctx, u.Object.Name)
	if err != nil {
		return "", fmt.Errorf("count access keys of %q: %w", user, err)
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
func (s *Service) Import(ctx context.Context, user, id, sec string, root bool) (_ Credential, err error) {
	ctx, end := start(ctx, "Import")
	defer end(&err)
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
		return Credential{}, "", fmt.Errorf("seal access key %s: %w", id, err)
	}
	k := iam.AccessKey{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1, RequestID: requestID}, ID: id, UserName: user, Root: root,
		Status: st, Created: s.now().UTC(), Secret: sealed,
	}
	if err := k.Validate(); err != nil {
		return Credential{}, "", fmt.Errorf("access key %s: %w", id, err)
	}
	if _, err := store.Create(ctx, s.index, iam.KeyIndex{ID: id, Project: s.project}); err != nil {
		return Credential{}, "", fmt.Errorf("create access key index %s: %w", id, err)
	}
	v, err := store.Create(ctx, s.b, k)
	if err != nil {
		return Credential{}, "", fmt.Errorf("create access key %s: %w", id, err)
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
		return nil, fmt.Errorf("list access keys: %w", err)
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
		if errors.Is(err, store.ErrNotFound) {
			// Match the ownership refusal below, regardless of backend context.
			err = store.ErrNotFound
		}
		return k, fmt.Errorf("access key %s: %w", id, err)
	}
	if k.Object.Root || k.Object.Status == iam.KeyPending || store.Fold(k.Object.UserName) != store.Fold(user) {
		// The same answer as a missing key, so it reveals no other owner's key.
		return k, fmt.Errorf("access key %s: %w", id, store.ErrNotFound)
	}
	return k, nil
}

// SetStatus makes a key Active or Inactive.
func (s *Service) SetStatus(ctx context.Context, user, id string, st iam.KeyStatus) (err error) {
	ctx, end := start(ctx, "SetStatus")
	defer end(&err)
	if _, err := s.owned(ctx, user, id); err != nil {
		return err
	}
	_, err = store.Mutate(ctx, s.b, id, func(k *iam.AccessKey) error {
		if k.Status != st {
			k.Status = st
			k.Generation++
			k.Updated = s.now().UTC()
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("set access key %s status: %w", id, err)
	}
	return nil
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
) (err error) {
	ctx, end := start(ctx, "Delete")
	defer end(&err)
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
		return fmt.Errorf("delete access key %s: %w", id, err)
	}
	if err := store.Delete[iam.KeyIndex](ctx, s.index, id, ""); err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("delete access key index %s: %w", id, err)
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
func (s *Service) MarkUsed(ctx context.Context, id, service, region string) (err error) {
	ctx, end := start(ctx, "MarkUsed")
	defer end(&err)
	_, err = store.Mutate(ctx, s.b, id, func(k *iam.AccessKey) error {
		k.LastUsed, k.LastUsedService, k.LastUsedRegion = s.now().UTC().Truncate(time.Second), service, region
		return nil
	})
	if err != nil {
		return fmt.Errorf("mark access key %s used: %w", id, err)
	}
	return nil
}

// GetSigningCredential returns the secret for SigV4 verification. An
// unknown or inactive key is refused. A key sealed under an older KEK is
// resealed with the active one.
func (s *Service) GetSigningCredential(ctx context.Context, id string) (_ Credential, err error) {
	ctx, end := start(ctx, "GetSigningCredential")
	defer end(&err)
	k, err := store.Get[iam.AccessKey](ctx, s.b, id)
	if err != nil {
		return Credential{}, fmt.Errorf("access key %s: %w", id, err)
	}
	if k.Object.Status != iam.KeyActive {
		return Credential{}, fmt.Errorf("access key %s: %w", id, ErrInactive)
	}
	plain, err := s.keys.Open(k.Object.Secret, aad(k.Object.ID))
	if err != nil {
		return Credential{}, fmt.Errorf("open access key %s: %w", id, err)
	}
	if s.keys.NeedsRewrap(k.Object.Secret) {
		// A failed seal only delays the rewrap to the next read.
		if sealed, serr := s.keys.Seal(plain, aad(k.Object.ID)); serr != nil {
			countRewrap(ctx, "seal_failed")
		} else if err := s.rewrap(ctx, k, sealed); err != nil {
			return Credential{}, err
		}
	}
	return Credential{AccessKeyID: k.Object.ID, Secret: string(plain), UserName: k.Object.UserName, Root: k.Object.Root}, nil
}

// rewrap stores k with its secret resealed under the active KEK. A lost
// race only delays the rewrap to the next read; a store failure is
// returned.
func (s *Service) rewrap(ctx context.Context, k store.Versioned[iam.AccessKey], sealed iam.Sealed) error {
	k.Object.Secret = sealed
	_, err := store.Update(ctx, s.b, k.Object, k.Version)
	switch {
	case err == nil:
		countRewrap(ctx, "ok")
	case errors.Is(err, store.ErrConflict):
		countRewrap(ctx, "conflict")
	default:
		countRewrap(ctx, "error")
		return fmt.Errorf("rewrap access key %s: %w", k.Object.ID, err)
	}
	return nil
}
