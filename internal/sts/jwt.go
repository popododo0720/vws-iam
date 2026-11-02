package sts

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256 for RS256 and ES256
	_ "crypto/sha512" // registers SHA-384 and SHA-512
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// MinOIDCRSABits is the smallest RSA key accepted for an ID token
// signature.
const MinOIDCRSABits = 2048

// OIDCKey is a public signing key of an OIDC provider: one entry of its
// JSON Web Key Set.
type OIDCKey struct {
	// ID is the JWK "kid"; a token naming a kid is checked only against
	// the key with that ID.
	ID string
	// Key is an *rsa.PublicKey or an *ecdsa.PublicKey.
	Key crypto.PublicKey
}

// jwtAlg is a JWS algorithm AssumeRoleWithWebIdentity accepts: RS256,
// RS384, RS512, ES256, ES384 or ES512, as the AWS API reference lists.
type jwtAlg struct {
	hash  crypto.Hash
	curve elliptic.Curve // nil for RSA
}

var jwtAlgs = map[string]jwtAlg{
	"RS256": {hash: crypto.SHA256}, "RS384": {hash: crypto.SHA384}, "RS512": {hash: crypto.SHA512},
	"ES256": {crypto.SHA256, elliptic.P256()}, "ES384": {crypto.SHA384, elliptic.P384()},
	"ES512": {crypto.SHA512, elliptic.P521()},
}

// jwt is a compact JWS whose header and payload are decoded but whose
// signature is not yet checked.
type jwt struct {
	alg    string
	kid    string
	claims map[string]json.RawMessage
	signed []byte // header "." payload, as received
	sig    []byte
}

var integerRE = regexp.MustCompile(`^-?[0-9]{1,18}$`)

// parseJWT decodes a compact JWS (three base64url parts without
// padding, no CR or LF: Go's base64 decoder skips line breaks even in
// strict mode). An encrypted token (JWE), a duplicated or unknown critical
// header, a duplicated claim, or an algorithm outside jwtAlgs is
// InvalidIdentityToken.
func parseJWT(s string) (jwt, error) {
	if strings.ContainsAny(s, "\r\n") {
		return jwt{}, fmt.Errorf("%w: the token is not base64url", ErrInvalidIdentityToken)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return jwt{}, fmt.Errorf("%w: the token is not a signed JWT", ErrInvalidIdentityToken)
	}
	var raw [3][]byte
	for i, p := range parts {
		b, err := base64.RawURLEncoding.Strict().DecodeString(p)
		if err != nil || len(b) == 0 {
			return jwt{}, fmt.Errorf("%w: the token is not base64url", ErrInvalidIdentityToken)
		}
		raw[i] = b
	}
	header, err := jsonObject(raw[0])
	if err != nil {
		return jwt{}, fmt.Errorf("%w: token header: %w", ErrInvalidIdentityToken, err)
	}
	if _, ok := header["crit"]; ok {
		return jwt{}, fmt.Errorf("%w: critical header parameters are not supported", ErrInvalidIdentityToken)
	}
	alg, err := jsonString(header, "alg")
	if _, ok := jwtAlgs[alg]; err != nil || !ok {
		return jwt{}, fmt.Errorf("%w: unsupported signing algorithm %q", ErrInvalidIdentityToken, alg)
	}
	kid, err := jsonString(header, "kid")
	if err != nil {
		return jwt{}, fmt.Errorf("%w: token header: %w", ErrInvalidIdentityToken, err)
	}
	claims, err := jsonObject(raw[1])
	if err != nil {
		return jwt{}, fmt.Errorf("%w: token claims: %w", ErrInvalidIdentityToken, err)
	}
	return jwt{
		alg: alg, kid: kid, claims: claims,
		signed: []byte(parts[0] + "." + parts[1]), sig: raw[2],
	}, nil
}

// verify checks the signature against keys: the key named by kid when
// the token has one, else every key of the algorithm's type.
func (t jwt) verify(keys []OIDCKey) error {
	alg := jwtAlgs[t.alg]
	h := alg.hash.New()
	h.Write(t.signed)
	digest := h.Sum(nil)
	for _, k := range keys {
		if t.kid != "" && k.ID != t.kid {
			continue
		}
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			if alg.curve == nil && pub.N.BitLen() >= MinOIDCRSABits &&
				rsa.VerifyPKCS1v15(pub, alg.hash, digest, t.sig) == nil {
				return nil
			}
		case *ecdsa.PublicKey:
			if alg.curve != nil && pub.Curve == alg.curve && verifyES(pub, digest, t.sig) {
				return nil
			}
		}
	}
	return fmt.Errorf("%w: the token signature does not match a key of the provider", ErrInvalidIdentityToken)
}

// verifyES checks a JWS ECDSA signature: R and S as fixed-size
// big-endian integers (RFC 7518 3.4).
func verifyES(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	n := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*n {
		return false
	}
	r, s := new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])
	return ecdsa.Verify(pub, digest, r, s)
}

// jsonObject decodes one JSON object and refuses a duplicated member,
// so no two parsers can read different values from one token.
func jsonObject(b []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return nil, errors.New("not a JSON object")
		}
		k, ok := t.(string)
		if !ok {
			return nil, errors.New("not a JSON object")
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, errors.New("not a JSON object")
		}
		if _, dup := m[k]; dup {
			return nil, fmt.Errorf("member %q appears twice", k)
		}
		m[k] = v
	}
	if t, err := d.Token(); err != nil || t != json.Delim('}') {
		return nil, errors.New("not a JSON object")
	}
	// Only a clean end of input may follow: a syntax error after the
	// object is data after it too.
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the JSON object")
	}
	return m, nil
}

// jsonString reads an optional string member; absent is "".
func jsonString(m map[string]json.RawMessage, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return "", fmt.Errorf("%s is not a string", key)
	}
	return s, nil
}

// jsonStrings reads an optional member that is a string or an array of
// strings; absent is nil.
func jsonStrings(m map[string]json.RawMessage, key string) ([]string, error) {
	v, ok := m[key]
	if !ok {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return []string{s}, nil
	}
	var l []string
	if err := json.Unmarshal(v, &l); err != nil {
		return nil, fmt.Errorf("%s is not a string or an array of strings", key)
	}
	return l, nil
}

// jsonInt reads an optional NumericDate member, which AWS requires to be
// an integer; ok is false when it is absent.
func jsonInt(m map[string]json.RawMessage, key string) (n int64, ok bool, err error) {
	v, ok := m[key]
	if !ok {
		return 0, false, nil
	}
	if !integerRE.Match(v) {
		return 0, true, fmt.Errorf("%s is not an integer", key)
	}
	n, err = strconv.ParseInt(string(v), 10, 64)
	if err != nil {
		return 0, true, fmt.Errorf("%s is not an integer", key)
	}
	return n, true, nil
}

// ParseJWKS reads the signing keys of a JSON Web Key Set (RFC 7517): RSA
// keys of at least MinOIDCRSABits and EC keys on P-256, P-384 or P-521.
// Keys for another use than "sig", of another type or too weak are
// skipped; a malformed key or document is an error, as is a set with no
// usable key.
func ParseJWKS(doc []byte) ([]OIDCKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	var keys []OIDCKey
	for i, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		var pub crypto.PublicKey
		var err error
		switch k.Kty {
		case "RSA":
			pub, err = jwkRSA(k.N, k.E)
		case "EC":
			pub, err = jwkEC(k.Crv, k.X, k.Y)
		default:
			continue
		}
		if errors.Is(err, errSkipKey) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("jwks key %d: %w", i, err)
		}
		keys = append(keys, OIDCKey{ID: k.Kid, Key: pub})
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks: no usable signing key")
	}
	return keys, nil
}

// errSkipKey is a well-formed key ParseJWKS does not use: an RSA key
// under MinOIDCRSABits or an EC key on another curve.
var errSkipKey = errors.New("key skipped")

// jwkRSA builds an RSA key; one under MinOIDCRSABits is errSkipKey.
func jwkRSA(n64, e64 string) (crypto.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(n64)
	if err != nil || len(n) == 0 {
		return nil, errors.New("bad RSA modulus")
	}
	e, err := base64.RawURLEncoding.DecodeString(e64)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.New("bad RSA exponent")
	}
	exp := new(big.Int).SetBytes(e).Int64()
	if exp < 3 || exp%2 == 0 {
		return nil, errors.New("bad RSA exponent")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp)}
	if pub.N.BitLen() < MinOIDCRSABits {
		return nil, errSkipKey
	}
	return pub, nil
}

// jwkEC builds an EC key and checks that the point is on the curve.
func jwkEC(crv, x64, y64 string) (crypto.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, errSkipKey
	}
	size := (curve.Params().BitSize + 7) / 8
	x, errX := base64.RawURLEncoding.DecodeString(x64)
	y, errY := base64.RawURLEncoding.DecodeString(y64)
	if errX != nil || errY != nil || len(x) != size || len(y) != size {
		return nil, errors.New("bad EC coordinates")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, errors.New("EC point is not on the curve")
	}
	return pub, nil
}
