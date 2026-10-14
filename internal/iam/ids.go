package iam

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
)

// NewUniqueID returns prefix (AIDA, AGPA, AROA, ANPA) and 17 random
// uppercase letters and digits, the AWS unique id shape.
func NewUniqueID(prefix string) string {
	b := make([]byte, 11)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	return prefix + base32.StdEncoding.EncodeToString(b)[:17]
}

// NewUID returns a random UUID v4.
func NewUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand: %v", err))
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
