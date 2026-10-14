// Package secret seals secret material with AES-256-GCM under a key
// encryption key (KEK). Every Sealed value records its KEK id, so a rotated
// keyring still opens values sealed under an older KEK. The associated data
// binds a ciphertext to the object it belongs to, so it cannot be moved.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// Errors.
var (
	ErrUnknownKEK = errors.New("unknown KEK id")
	ErrOpen       = errors.New("cannot open sealed value")
)

var kidRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Keyring holds KEKs by id and seals with the active one.
type Keyring struct {
	active string
	aeads  map[string]cipher.AEAD
}

// NewKeyring builds a keyring from 32-byte keys. active must be among them.
func NewKeyring(active string, keys map[string][]byte) (*Keyring, error) {
	k := &Keyring{active: active, aeads: map[string]cipher.AEAD{}}
	for id, key := range keys {
		if !kidRE.MatchString(id) {
			return nil, fmt.Errorf("KEK id %q is invalid", id)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("KEK %q is %d bytes, want 32", id, len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("KEK %q: %w", id, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("KEK %q: %w", id, err)
		}
		k.aeads[id] = aead
	}
	if _, ok := k.aeads[active]; !ok {
		return nil, fmt.Errorf("active KEK %q: %w", active, ErrUnknownKEK)
	}
	return k, nil
}

// LoadDir reads a mounted Secret: one file per KEK id holding the base64
// of 32 random bytes, and a file named "active" holding the active id.
// Key bytes never appear in an error.
func LoadDir(dir string) (*Keyring, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("KEK dir: %w", err)
	}
	keys := map[string][]byte{}
	var active string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("KEK %q: %w", name, err)
		}
		s := strings.TrimSpace(string(b))
		if name == "active" {
			active = s
			continue
		}
		key, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("KEK %q is not base64", name)
		}
		keys[name] = key
	}
	return NewKeyring(active, keys)
}

// Active is the id new values are sealed with.
func (k *Keyring) Active() string { return k.active }

// Seal encrypts plaintext with the active KEK; aad names the owner.
func (k *Keyring) Seal(plaintext []byte, aad string) (iam.Sealed, error) {
	aead := k.aeads[k.active]
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return iam.Sealed{}, fmt.Errorf("nonce: %w", err)
	}
	return iam.Sealed{KeyID: k.active, Ciphertext: aead.Seal(nonce, nonce, plaintext, []byte(k.active+"\x00"+aad))}, nil
}

// Open decrypts s with the KEK it names; aad must match the Seal call.
func (k *Keyring) Open(s iam.Sealed, aad string) ([]byte, error) {
	aead, ok := k.aeads[s.KeyID]
	if !ok {
		return nil, fmt.Errorf("%q: %w", s.KeyID, ErrUnknownKEK)
	}
	n := aead.NonceSize()
	if len(s.Ciphertext) < n+aead.Overhead() {
		return nil, ErrOpen
	}
	p, err := aead.Open(nil, s.Ciphertext[:n], s.Ciphertext[n:], []byte(s.KeyID+"\x00"+aad))
	if err != nil {
		return nil, ErrOpen
	}
	return p, nil
}

// NeedsRewrap reports whether s is sealed under an older KEK.
func (k *Keyring) NeedsRewrap(s iam.Sealed) bool { return s.KeyID != k.active }
