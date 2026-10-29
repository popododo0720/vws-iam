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

// Create makes an active key for user and returns its secret, once.
func (s *Service) Create(ctx context.Context, user string) (Credential, error) {
	u, err := store.Get[iam.User](ctx, s.b, user)
	if errors.Is(err, store.ErrNotFound) {
		return Credential{}, fmt.Errorf("%q: %w", user, ErrNoSuchUser)
	}
	if err != nil {
		return Credential{}, err
	}
	n, err := s.count(ctx, u.Object.Name)
	if err != nil {
		return Credential{}, err
	}
	if n >= MaxPerUser {
		return Credential{}, ErrLimitExceeded
	}
	return s.Import(ctx, u.Object.Name, "", "", false)
}

// Import stores a key with a given id and secret (bootstrap of the
// existing console-api credential), or generates both when empty. A root
// key has no user. The index entry is written first, so a crash leaves at
// worst an index entry without a key, which authenticates nothing.
func (s *Service) Import(ctx context.Context, user, id, sec string, root bool) (Credential, error) {
	var err error
	if id == "" {
		if id, err = NewKeyID("AKIA"); err != nil {
			return Credential{}, err
		}
	}
	if sec == "" {
		if sec, err = NewSecret(); err != nil {
			return Credential{}, err
		}
	}
	sealed, err := s.keys.Seal([]byte(sec), aad(id))
	if err != nil {
		return Credential{}, err
	}
	k := iam.AccessKey{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, ID: id, UserName: user, Root: root, Status: iam.KeyActive, Created: s.now().UTC(), Secret: sealed}
	if err := k.Validate(); err != nil {
		return Credential{}, err
	}
	if _, err := store.Create(ctx, s.index, iam.KeyIndex{ID: id, Project: s.project}); err != nil {
		return Credential{}, err
	}
	if _, err := store.Create(ctx, s.b, k); err != nil {
		return Credential{}, err
	}
	return Credential{AccessKeyID: id, Secret: sec, UserName: user}, nil
}

func (s *Service) count(ctx context.Context, user string) (int, error) {
	ks, err := s.List(ctx, user)
	return len(ks), err
}

// List returns user's keys, sealed secrets stripped.
func (s *Service) List(ctx context.Context, user string) ([]iam.AccessKey, error) {
	all, err := store.List[iam.AccessKey](ctx, s.b)
	if err != nil {
		return nil, err
	}
	var out []iam.AccessKey
	for _, k := range all {
		if !k.Object.Root && store.Fold(k.Object.UserName) == store.Fold(user) {
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
	if k.Object.Root || store.Fold(k.Object.UserName) != store.Fold(user) {
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

// Delete removes a key of user. check, when not nil, runs on the same read
// that guards the delete, so a failed check deletes nothing.
func (s *Service) Delete(ctx context.Context, user, id string, check func(iam.AccessKey) error) error {
	k, err := s.owned(ctx, user, id)
	if err != nil {
		return err
	}
	if check != nil {
		if err := check(k.Object); err != nil {
			return err
		}
	}
	if err := store.Delete[iam.AccessKey](ctx, s.b, id, k.Version); err != nil {
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
