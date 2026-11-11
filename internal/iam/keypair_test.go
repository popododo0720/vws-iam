package iam

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	keyPairTestPublic      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
	keyPairTestFingerprint = "6db5e9b8a1bace1cdd9a7c6adb9e9396acc5073465d9fe8e3a0ef6d9c60d6d4f"
)

func testKeyPair() KeyPair {
	return KeyPair{
		ID: "key-0123456789abcdef", Name: "My laptop", Region: "ap-northeast-2",
		PublicKey: keyPairTestPublic, FingerprintSHA256: keyPairTestFingerprint, KeyType: KeyPairED25519,
		Created: time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC), Meta: Meta{UID: "kp-1", Generation: 1},
	}
}

func TestKeyPairValidate(t *testing.T) {
	p := testKeyPair()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.Kind() != Kind("IamKeyPair") || p.Key() != p.ID || !slices.Contains(Kinds, p.Kind()) {
		t.Fatalf("kind %q, key %q, registered kinds %v", p.Kind(), p.Key(), Kinds)
	}
	for name, edit := range map[string]func(*KeyPair){
		"missing id":          func(p *KeyPair) { p.ID = "" },
		"wrong id prefix":     func(p *KeyPair) { p.ID = "kp-123" },
		"empty hex":           func(p *KeyPair) { p.ID = "key-" },
		"upper hex":           func(p *KeyPair) { p.ID = "key-AB" },
		"bad hex":             func(p *KeyPair) { p.ID = "key-gg" },
		"id over 63":          func(p *KeyPair) { p.ID = "key-" + strings.Repeat("a", 60) },
		"empty name":          func(p *KeyPair) { p.Name = "" },
		"name over 255":       func(p *KeyPair) { p.Name = strings.Repeat("a", 256) },
		"non ASCII name":      func(p *KeyPair) { p.Name = "\xc3\xa9" },
		"missing region":      func(p *KeyPair) { p.Region = "" },
		"bad region":          func(p *KeyPair) { p.Region = "Region_1" },
		"digit region":        func(p *KeyPair) { p.Region = "1region" },
		"region over 63":      func(p *KeyPair) { p.Region = strings.Repeat("a", 64) },
		"missing create time": func(p *KeyPair) { p.Created = time.Time{} },
		"wrong type":          func(p *KeyPair) { p.KeyType = KeyPairRSA },
		"missing type":        func(p *KeyPair) { p.KeyType = "" },
		"wrong fingerprint":   func(p *KeyPair) { p.FingerprintSHA256 = strings.Repeat("a", 64) },
		"upper fingerprint":   func(p *KeyPair) { p.FingerprintSHA256 = strings.ToUpper(p.FingerprintSHA256) },
		"missing public key":  func(p *KeyPair) { p.PublicKey = "" },
		"private key":         func(p *KeyPair) { p.PublicKey = "-----BEGIN PRIVATE KEY-----\nsecret\n" },
		"bad base64":          func(p *KeyPair) { p.PublicKey = "ssh-ed25519 !@#$" },
		"wrong algorithm":     func(p *KeyPair) { p.PublicKey = strings.Replace(p.PublicKey, "ssh-ed25519", "ssh-rsa", 1) },
		"two keys one line":   func(p *KeyPair) { p.PublicKey += " " + p.PublicKey },
		"two key lines":       func(p *KeyPair) { p.PublicKey += "\n" + p.PublicKey },
		"base64 newline":      func(p *KeyPair) { p.PublicKey += "\n" },
		"DER base64 only":     func(p *KeyPair) { p.PublicKey = strings.TrimPrefix(p.PublicKey, "ssh-ed25519 ") },
		"comment":             func(p *KeyPair) { p.PublicKey += " secret comment" },
		"options":             func(p *KeyPair) { p.PublicKey = "restrict " + p.PublicKey },
		"bad request token":   func(p *KeyPair) { p.Requests = []string{"bad token"} },
		"too many requests":   func(p *KeyPair) { p.Requests = make([]string, MaxRequests+1) },
	} {
		t.Run(name, func(t *testing.T) {
			p := testKeyPair()
			edit(&p)
			err := p.Validate()
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "key pair") {
				t.Fatalf("got %v, want key pair ErrInvalid", err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), keyPairTestPublic) {
				t.Fatalf("validation error leaks public-key field: %v", err)
			}
		})
	}
}

func TestKeyPairBoundaries(t *testing.T) {
	for _, n := range []int{1, 255} {
		p := testKeyPair()
		p.Name = strings.Repeat("A", n)
		p.Region = strings.Repeat("a", 63)
		p.ID = "key-" + strings.Repeat("f", 59)
		if err := p.Validate(); err != nil {
			t.Fatalf("name length %d: %v", n, err)
		}
	}
	for _, name := range []string{"My Key", "my key", "a/b", "!@#$%^&*()"} {
		p := testKeyPair()
		p.Name = name
		if err := p.Validate(); err != nil || p.Name != name {
			t.Fatalf("name %q was changed or refused: %v", name, err)
		}
	}
}

func TestKeyPairRSAStoredRange(t *testing.T) {
	for _, bits := range []int{768, 1023, 1024, 2048, 3072, 4096, 4097, 8192} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			// Only the public wire shape matters; no random private key is needed.
			n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
			n.Add(n, big.NewInt(1))
			pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: 65537})
			if err != nil {
				t.Fatal(err)
			}
			p := testKeyPair()
			p.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
			p.KeyType = KeyPairRSA
			sum := sha256.Sum256(pub.Marshal())
			p.FingerprintSHA256 = hex.EncodeToString(sum[:])
			err = p.Validate()
			if valid := bits >= 1024 && bits <= 4096; valid != (err == nil) {
				t.Fatalf("bits %d: %v", bits, err)
			}
		})
	}
}

func FuzzKeyPairValidate(f *testing.F) {
	for _, public := range []string{keyPairTestPublic, "", "ssh-rsa !", "-----BEGIN PRIVATE KEY-----"} {
		f.Add(public)
	}
	f.Fuzz(func(t *testing.T, public string) {
		p := testKeyPair()
		p.PublicKey = public
		err := p.Validate()
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		fields := strings.Split(public, " ")
		if len(fields) != 2 {
			t.Fatal("accepted a non-canonical line")
		}
		blob, err := base64.StdEncoding.Strict().DecodeString(fields[1])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(blob)
		if hex.EncodeToString(sum[:]) != p.FingerprintSHA256 {
			t.Fatal("accepted a fingerprint mismatch")
		}
	})
}
