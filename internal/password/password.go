// Package password hashes passwords with argon2id in PHC string form.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters (RFC 9106 second recommended option, 64 MiB).
const (
	memory  = 64 * 1024
	time    = 3
	threads = 4
	keyLen  = 32
	saltLen = 16
)

// ErrMismatch is a wrong password.
var ErrMismatch = errors.New("password mismatch")

var b64 = base64.RawStdEncoding

// Hash returns $argon2id$v=19$m=..,t=..,p=..$salt$hash.
func Hash(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("salt: %w", err)
	}
	h := argon2.IDKey([]byte(pw), salt, time, memory, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, memory, time, threads, b64.EncodeToString(salt), b64.EncodeToString(h)), nil
}

// Verify checks pw against a Hash result in constant time.
func Verify(pw, phc string) error {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("not an argon2id hash")
	}
	var v int
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return errors.New("unsupported argon2 version")
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || m == 0 || m > 1<<21 || t == 0 || t > 16 || p == 0 {
		return errors.New("bad argon2 parameters")
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return errors.New("bad argon2 salt")
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return errors.New("bad argon2 hash")
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrMismatch
	}
	return nil
}
