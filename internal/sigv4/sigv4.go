// Package sigv4 checks an AWS Signature Version 4 inside vws-iam. The
// caller sends the canonical request and the string to sign; the secret
// never leaves this process. It is pure.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Algorithm is the only supported signing algorithm.
const Algorithm = "AWS4-HMAC-SHA256"

// MaxSkew is the allowed distance between X-Amz-Date and the server clock.
const MaxSkew = 15 * time.Minute

// Errors. All are InvalidCredentials on the wire except ErrSkew, which AWS
// reports as RequestTimeTooSkewed (still UNAUTHENTICATED).
var (
	ErrMalformed = errors.New("malformed string to sign")
	ErrScope     = errors.New("credential scope does not match")
	ErrHash      = errors.New("canonical request hash does not match")
	ErrSkew      = errors.New("request time too skewed")
	ErrSignature = errors.New("signature does not match")
)

// Request is what console-api sends (vws.iam.v1.AuthenticateRequest).
type Request struct {
	Date, Region, Service string
	CanonicalRequest      string
	StringToSign          string
	Signature             string
}

// Check validates the string to sign against the request and the clock,
// then compares the signature computed with secret in constant time.
func Check(secret []byte, r Request, now time.Time) error {
	lines := strings.Split(r.StringToSign, "\n")
	if len(lines) != 4 || lines[0] != Algorithm {
		return ErrMalformed
	}
	amzDate, scope, hash := lines[1], lines[2], lines[3]
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return ErrMalformed
	}
	if len(r.Date) != 8 || !strings.HasPrefix(amzDate, r.Date) || r.Region == "" || r.Service == "" ||
		scope != r.Date+"/"+r.Region+"/"+r.Service+"/aws4_request" {
		return ErrScope
	}
	sum := sha256.Sum256([]byte(r.CanonicalRequest))
	if !hmac.Equal([]byte(hex.EncodeToString(sum[:])), []byte(hash)) {
		return ErrHash
	}
	if d := now.Sub(t); d > MaxSkew || d < -MaxSkew {
		return ErrSkew
	}
	key := mac(append([]byte("AWS4"), secret...), r.Date)
	key = mac(key, r.Region)
	key = mac(key, r.Service)
	key = mac(key, "aws4_request")
	want := hex.EncodeToString(mac(key, r.StringToSign))
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(r.Signature))) {
		return ErrSignature
	}
	return nil
}

func mac(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// Sign returns the signature for a string to sign; tests and clients use it.
func Sign(secret []byte, date, region, service, stringToSign string) string {
	key := mac(append([]byte("AWS4"), secret...), date)
	key = mac(key, region)
	key = mac(key, service)
	key = mac(key, "aws4_request")
	return hex.EncodeToString(mac(key, stringToSign))
}
