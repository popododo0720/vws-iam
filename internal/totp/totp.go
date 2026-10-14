// Package totp implements RFC 6238 time-based one-time passwords (HOTP of
// RFC 4226 over 30-second steps). It is pure.
package totp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default and what authenticator apps use
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"time"
)

// Period is the time step.
const Period = 30 * time.Second

// Digits of a code.
const Digits = 6

// Step is the time step containing t.
func Step(t time.Time) int64 { return t.Unix() / int64(Period/time.Second) }

// Code is the HOTP value of seed at step with n digits.
func Code(seed []byte, step int64, n int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range n {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", n, v%mod)
}

// Equal compares codes in constant time.
func Equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// Match returns the step within ±skew of now whose code is code, preferring
// the earliest, or false.
func Match(seed []byte, code string, now time.Time, skew int64) (int64, bool) {
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	for s := cur - skew; s <= cur+skew; s++ {
		if Equal(Code(seed, s, Digits), code) {
			return s, true
		}
	}
	return 0, false
}
