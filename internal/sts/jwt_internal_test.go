package sts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
)

// TestParseJWKS: RSA (at least 2048 bits) and EC (P-256, P-384, P-521)
// signing keys are read; keys for encryption, of other types or too weak
// are skipped; a point off the curve or a malformed key is an error, and
// so is a set without a usable key.
func TestParseJWKS(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := ec.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	x, y := b64(pt[1:49]), b64(pt[49:])
	e := b64(big.NewInt(65537).Bytes())
	rsaJWK := func(kid string, k *rsa.PrivateKey, use string) string {
		return `{"kty":"RSA","kid":"` + kid + `","use":"` + use + `","n":"` + b64(k.N.Bytes()) + `","e":"` + e + `"}`
	}
	doc := `{"keys":[` + strings.Join([]string{
		rsaJWK("strong", strong, "sig"), rsaJWK("weak", weak, "sig"), rsaJWK("enc", strong, "enc"),
		`{"kty":"EC","kid":"ec","crv":"P-384","x":"` + x + `","y":"` + y + `"}`,
		`{"kty":"oct","kid":"hmac","k":"c2VjcmV0"}`,
		`{"kty":"EC","kid":"k1","crv":"secp256k1","x":"AA","y":"AA"}`,
	}, ",") + `]}`
	keys, err := ParseJWKS([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].ID != "strong" || keys[1].ID != "ec" {
		t.Fatalf("keys %+v", keys)
	}
	if k, ok := keys[0].Key.(*rsa.PublicKey); !ok || !k.Equal(&strong.PublicKey) {
		t.Fatalf("rsa key %+v", keys[0].Key)
	}
	if k, ok := keys[1].Key.(*ecdsa.PublicKey); !ok || !k.Equal(&ec.PublicKey) {
		t.Fatalf("ec key %+v", keys[1].Key)
	}
	offCurve := b64(append(make([]byte, 47), 1))
	for name, bad := range map[string]string{
		"not json":     `{`,
		"no key":       `{"keys":[]}`,
		"only weak":    `{"keys":[` + rsaJWK("weak", weak, "sig") + `]}`,
		"off curve":    `{"keys":[{"kty":"EC","crv":"P-384","x":"` + offCurve + `","y":"` + offCurve + `"}]}`,
		"short x":      `{"keys":[{"kty":"EC","crv":"P-384","x":"AA","y":"` + y + `"}]}`,
		"even e":       `{"keys":[{"kty":"RSA","n":"` + b64(strong.N.Bytes()) + `","e":"Ag"}]}`,
		"bad modulus":  `{"keys":[{"kty":"RSA","n":"%%","e":"` + e + `"}]}`,
		"huge e bytes": `{"keys":[{"kty":"RSA","n":"` + b64(strong.N.Bytes()) + `","e":"AQAAAAAB"}]}`,
	} {
		if _, err := ParseJWKS([]byte(bad)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
