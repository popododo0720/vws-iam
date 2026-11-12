package iam

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// KeyPairType is the algorithm of an EC2-compatible SSH public key.
type KeyPairType string

const (
	KeyPairRSA     KeyPairType = "RSA"
	KeyPairED25519 KeyPairType = "ED25519"
)

var (
	keyPairIDRE     = regexp.MustCompile(`^key-[0-9a-f]{1,59}$`)
	keyPairRegionRE = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// KeyPair holds only public material. Its key is the server-minted ID,
// scoped by store.Scoped to a project; Region is the regional scope.
// PublicKey is canonical OpenSSH (algorithm and base64 blob, no comment),
// so arbitrary comment text cannot persist private material.
type KeyPair struct {
	Meta
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	Region            string      `json:"region"`
	PublicKey         string      `json:"publicKey"`
	FingerprintSHA256 string      `json:"fingerprintSha256"`
	KeyType           KeyPairType `json:"keyType"`
	Created           time.Time   `json:"created"`
	Pending           bool        `json:"pending,omitempty"`
	Deleted           time.Time   `json:"deleted,omitempty"`
}

func (KeyPair) Kind() Kind    { return KindKeyPair }
func (p KeyPair) Key() string { return p.ID }

// ValidKeyPairName applies the EC2 KeyName bounds: 1 to 255 ASCII bytes.
// Names retain their case; they are not IAM user names or store keys.
func ValidKeyPairName(name string) bool {
	if len(name) < 1 || len(name) > 255 {
		return false
	}
	for i := range len(name) {
		if name[i] > 127 {
			return false
		}
	}
	return true
}

// ValidKeyPairRegion applies the ResourceId grammar to a regional scope.
func ValidKeyPairRegion(region string) bool { return keyPairRegionRE.MatchString(region) }

func (p KeyPair) Validate() error {
	switch {
	case !keyPairIDRE.MatchString(p.ID):
		return invalid("key pair id")
	case !ValidKeyPairName(p.Name):
		return invalid("key pair %q name", p.ID)
	case !ValidKeyPairRegion(p.Region):
		return invalid("key pair %q region", p.ID)
	case p.Created.IsZero():
		return invalid("key pair %q created time", p.ID)
	}
	if err := p.validRequests("key pair", p.ID); err != nil {
		return err
	}
	fields := strings.Split(p.PublicKey, " ")
	if len(fields) != 2 {
		return invalid("key pair %q public key must be canonical OpenSSH", p.ID)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(fields[1])
	if err != nil || fields[1] != base64.StdEncoding.EncodeToString(blob) {
		return invalid("key pair %q public key base64", p.ID)
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil || fields[0] != pub.Type() || !bytes.Equal(blob, pub.Marshal()) {
		return invalid("key pair %q public key encoding", p.ID)
	}
	var typ KeyPairType
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		typ = KeyPairED25519
	case ssh.KeyAlgoRSA:
		ck, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return invalid("key pair %q public key RSA encoding", p.ID)
		}
		rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rk.N.Sign() <= 0 || rk.N.BitLen() < 1024 || rk.N.BitLen() > 4096 {
			return invalid("key pair %q public key RSA size must be 1024 to 4096 bits", p.ID)
		}
		typ = KeyPairRSA
	default:
		return invalid("key pair %q public key algorithm must be RSA or ED25519", p.ID)
	}
	sum := sha256.Sum256(blob)
	if p.KeyType != typ || p.FingerprintSHA256 != hex.EncodeToString(sum[:]) {
		return invalid("key pair %q public key type or fingerprint", p.ID)
	}
	return nil
}
