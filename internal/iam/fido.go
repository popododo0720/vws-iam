package iam

import (
	"crypto/sha256"
	"encoding/base32"
	"regexp"
	"strings"
	"time"
)

// FIDO security key limits. AWS GetMFADevice bounds a serial number to 256
// characters and a certification key to 128 and value to 32 characters of
// [\u0020-\u00FF]. WebAuthn bounds a credential id to 1023 bytes.
const (
	MaxFidoSerialLen        = 256
	MaxFidoCredentialIDLen  = 1023
	MinFidoCredentialIDLen  = 16
	MaxFidoPublicKeyLen     = 1024
	MaxFidoCertifications   = 16
	MaxFidoCertificationKey = 128
	MaxFidoCertificationVal = 32
	// FidoIDLen is the length of the random-looking id that ends a FIDO
	// device name: base32 of the SHA-256 of the credential id, so one
	// credential maps to one id.
	FidoIDLen = 26
)

var (
	fidoIDRE   = regexp.MustCompile(`^[A-Z2-7]{26}$`)
	aaguidRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	certTextRE = regexp.MustCompile(`^[\x{0020}-\x{00FF}]+$`)
)

// FidoDevice is a FIDO security key (a WebAuthn credential) registered to
// a user. Unlike a virtual device it is always assigned: it exists only
// while it is registered to its user. Its serial number is
// arn:vws:iam::{account}:u2f/user/{user}/{label}-{id}, as AWS
// u2f/user/{user}/{name}-{id}. Key is the id alone, so a credential can be
// registered once per account and a retried registration is ErrExists.
// Nothing here is secret: PublicKey is the credential's public COSE key.
type FidoDevice struct {
	Meta
	// ID is FidoID(CredentialID).
	ID string `json:"id"`
	// UserName is the user the key is registered to.
	UserName string `json:"userName"`
	// Label is the friendly name given at registration.
	Label        string    `json:"label"`
	CredentialID []byte    `json:"credentialId"`
	PublicKey    []byte    `json:"publicKey"`
	AAGUID       string    `json:"aaguid,omitempty"`
	SignCount    uint32    `json:"signCount,omitempty"`
	EnableTime   time.Time `json:"enableTime"`
	// Certifications are the FIDO Alliance MDS certification levels
	// (for example "FIDO": "L1"), as AWS GetMFADevice Certifications.
	Certifications map[string]string `json:"certifications,omitempty"`
}

func (FidoDevice) Kind() Kind    { return KindFidoDevice }
func (d FidoDevice) Key() string { return d.ID }

// DeviceName is the last segment of the serial number: label-id.
func (d FidoDevice) DeviceName() string { return d.Label + "-" + d.ID }

func (d FidoDevice) Validate() error {
	if !fidoIDRE.MatchString(d.ID) {
		return invalid("fido device id %q", d.ID)
	}
	if !ValidName(d.UserName) {
		return invalid("fido device %q user name %q", d.ID, d.UserName)
	}
	if !ValidName(d.Label) {
		return invalid("fido device %q label %q", d.ID, d.Label)
	}
	if n := len(d.CredentialID); n < MinFidoCredentialIDLen || n > MaxFidoCredentialIDLen {
		return invalid("fido device %q credential id is %d bytes", d.ID, n)
	}
	if d.ID != FidoID(d.CredentialID) {
		return invalid("fido device %q id does not match its credential", d.ID)
	}
	if n := len(d.PublicKey); n == 0 || n > MaxFidoPublicKeyLen {
		return invalid("fido device %q public key is %d bytes", d.ID, n)
	}
	if d.AAGUID != "" && !aaguidRE.MatchString(d.AAGUID) {
		return invalid("fido device %q aaguid %q", d.ID, d.AAGUID)
	}
	if d.EnableTime.IsZero() {
		return invalid("fido device %q has no enable time", d.ID)
	}
	if err := checkCertifications(d.Certifications); err != nil {
		return invalid("fido device %q: %v", d.ID, err)
	}
	return nil
}

func checkCertifications(c map[string]string) error {
	if len(c) > MaxFidoCertifications {
		return invalid("%d certifications", len(c))
	}
	for k, v := range c {
		if len(k) > MaxFidoCertificationKey || !certTextRE.MatchString(k) {
			return invalid("certification key %q", k)
		}
		if len(v) > MaxFidoCertificationVal || !certTextRE.MatchString(v) {
			return invalid("certification %q value %q", k, v)
		}
	}
	return nil
}

// FidoDeviceARN is the serial number of a FIDO security key in account.
func FidoDeviceARN(account string, d FidoDevice) string {
	return ARN("iam", "", account, "u2f/user/"+d.UserName+"/"+d.DeviceName())
}

// SplitFidoDeviceARN splits a FIDO serial number
// arn:vws:iam::{account}:u2f/user/{user}/{label}-{id} in account into the
// user name and the device id. ok is false when serial is not a user FIDO
// serial in account. A root u2f/root/... serial is not ok: VWS root has no
// FIDO devices.
func SplitFidoDeviceARN(account, serial string) (user, id string, ok bool) {
	if len(serial) > MaxFidoSerialLen {
		return "", "", false
	}
	rest, ok := strings.CutPrefix(serial, ARN("iam", "", account, "u2f/user/"))
	if !ok {
		return "", "", false
	}
	user, dev, ok := strings.Cut(rest, "/")
	if !ok || !ValidName(user) {
		return "", "", false
	}
	i := strings.LastIndexByte(dev, '-')
	if i < 1 || !ValidName(dev[:i]) || !fidoIDRE.MatchString(dev[i+1:]) {
		return "", "", false
	}
	return user, dev[i+1:], true
}

var fidoB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// FidoID is the device id of a credential: the first FidoIDLen characters
// of the base32 SHA-256 of its id.
func FidoID(credentialID []byte) string {
	sum := sha256.Sum256(credentialID)
	return fidoB32.EncodeToString(sum[:])[:FidoIDLen]
}
