// Package oidctest is a test OpenID Connect identity provider: it issues
// ID tokens (compact JWS) signed with its own keys, as an IdP does for
// AWS STS AssumeRoleWithWebIdentity, and serves its provider to
// sts.WithOIDC. It is for tests only.
package oidctest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // registers SHA-256
	_ "crypto/sha512" // registers SHA-384 and SHA-512
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// IdP is a test identity provider with one RSA key and one key on each
// of P-256, P-384 and P-521; each key's ID is its algorithm family name.
type IdP struct {
	Issuer string
	rsa    *rsa.PrivateKey
	ec     map[string]*ecdsa.PrivateKey // by alg
}

// New returns an IdP with fresh keys.
func New(issuer string) (*IdP, error) {
	return NewWithRSABits(issuer, 2048)
}

// NewWithRSABits is New with an RSA key of the given size.
func NewWithRSABits(issuer string, bits int) (*IdP, error) {
	r, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("idp rsa key: %w", err)
	}
	p := &IdP{Issuer: issuer, rsa: r, ec: map[string]*ecdsa.PrivateKey{}}
	curves := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}
	for alg, c := range curves {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("idp ec key: %w", err)
		}
		p.ec[alg] = k
	}
	return p, nil
}

// kid is the key ID of the key that signs alg.
func kid(alg string) string {
	if alg[0] == 'R' {
		return "rsa"
	}
	return alg
}

// Keys are the IdP's public keys, as sts.ParseJWKS reads them.
func (p *IdP) Keys() []sts.OIDCKey {
	keys := []sts.OIDCKey{{ID: "rsa", Key: &p.rsa.PublicKey}}
	for _, alg := range []string{"ES256", "ES384", "ES512"} {
		keys = append(keys, sts.OIDCKey{ID: alg, Key: &p.ec[alg].PublicKey})
	}
	return keys
}

// JWKS is the IdP's JSON Web Key Set document.
func (p *IdP) JWKS() ([]byte, error) {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	keys := []map[string]string{{
		"kty": "RSA", "use": "sig", "kid": "rsa", "n": b64(p.rsa.N.Bytes()),
		"e": b64(big.NewInt(int64(p.rsa.E)).Bytes()),
	}}
	for alg, crv := range map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"} {
		k := p.ec[alg]
		size := (k.Curve.Params().BitSize + 7) / 8
		pt, err := k.PublicKey.Bytes()
		if err != nil {
			return nil, fmt.Errorf("jwks: %w", err)
		}
		keys = append(keys, map[string]string{
			"kty": "EC", "use": "sig", "kid": alg, "crv": crv, "x": b64(pt[1 : 1+size]), "y": b64(pt[1+size:]),
		})
	}
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	return b, nil
}

// Provider is the IdP as the IAM OIDC provider arn accepting clientIDs.
func (p *IdP) Provider(arn string, clientIDs ...string) sts.OIDCProvider {
	return sts.OIDCProvider{ARN: arn, URL: p.Issuer, ClientIDs: clientIDs, Keys: p.Keys()}
}

// Token signs claims with alg (RS256, RS384, RS512, ES256, ES384 or
// ES512) and the IdP's key for it, naming that key in kid.
func (p *IdP) Token(alg string, claims map[string]any) (string, error) {
	return p.TokenWithHeader(map[string]any{"alg": alg, "typ": "JWT", "kid": kid(alg)}, claims)
}

// TokenWithHeader signs claims under header with the IdP's key for
// header["alg"].
func (p *IdP) TokenWithHeader(header, claims map[string]any) (string, error) {
	alg, _ := header["alg"].(string) //nolint:errcheck // a missing alg fails below
	var key crypto.Signer = p.rsa
	if k, ok := p.ec[alg]; ok {
		key = k
	}
	return Sign(alg, key, header, claims)
}

// SignRaw signs the header and claims JSON as given (duplicate members,
// trailing data) with the IdP's key for alg.
func (p *IdP) SignRaw(alg string, header, claims []byte) (string, error) {
	var key crypto.Signer = p.rsa
	if k, ok := p.ec[alg]; ok {
		key = k
	}
	return SignRaw(alg, key, header, claims)
}

// hashes are the digests of each algorithm.
var hashes = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
	"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512,
}

// Sign builds a compact JWS of header and claims signed with key under
// alg's digest, whatever header says.
func Sign(alg string, key crypto.Signer, header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("claims: %w", err)
	}
	return SignRaw(alg, key, h, c)
}

// SignRaw is Sign with the header and claims JSON as given.
func SignRaw(alg string, key crypto.Signer, header, claims []byte) (string, error) {
	hash, ok := hashes[alg]
	if !ok {
		return "", fmt.Errorf("unsupported alg %q", alg)
	}
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	d := hash.New()
	d.Write([]byte(signed))
	digest := d.Sum(nil)
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		s, err := rsa.SignPKCS1v15(rand.Reader, k, hash, digest)
		if err != nil {
			return "", fmt.Errorf("sign: %w", err)
		}
		sig = s
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return "", fmt.Errorf("sign: %w", err)
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		sig = make([]byte, 2*n)
		r.FillBytes(sig[:n])
		s.FillBytes(sig[n:])
	default:
		return "", fmt.Errorf("unsupported key %T", key)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Providers serves providers by ARN to sts.WithOIDC; Err, when set, is
// returned for every lookup.
type Providers struct {
	ByARN map[string]sts.OIDCProvider
	Err   error
}

// OIDCProvider implements sts.OIDCProviders.
func (p Providers) OIDCProvider(_ context.Context, arn string) (sts.OIDCProvider, error) {
	if p.Err != nil {
		return sts.OIDCProvider{}, p.Err
	}
	v, ok := p.ByARN[arn]
	if !ok {
		return sts.OIDCProvider{}, store.ErrNotFound
	}
	return v, nil
}
