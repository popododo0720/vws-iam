package iam

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// SAML provider limits. AWS bounds the name to 1 to 128 characters of
// [\w._-] and the metadata document to 1000 to 10,000,000 characters.
// MaxSAMLProviderEncodedLen is a VWS limit: a provider is stored as one
// custom resource, which must stay under the etcd request limit
// (about 1.5 MiB), so its JSON encoding is bounded below that.
const (
	MaxSAMLProviderNameLen    = 128
	MinSAMLMetadataLen        = 1000
	MaxSAMLMetadataLen        = 10_000_000
	MaxSAMLProviderTags       = 50
	MaxSAMLProviderEncodedLen = 1 << 20
)

// ErrSAMLProviderTooLarge is a SAML provider whose stored encoding would
// pass MaxSAMLProviderEncodedLen. It also wraps ErrInvalid.
var ErrSAMLProviderTooLarge = errors.New("SAML provider too large to store")

// SAMLProviderNamePattern is the AWS SAML provider name rule: 1 to
// MaxSAMLProviderNameLen characters of [A-Za-z0-9_.-].
func SAMLProviderNamePattern() string {
	return fmt.Sprintf("[A-Za-z0-9_.-]{1,%d}", MaxSAMLProviderNameLen)
}

var samlProviderNameRE = regexp.MustCompile("^" + SAMLProviderNamePattern() + "$")

// ValidSAMLProviderName reports whether s is a SAML provider name.
func ValidSAMLProviderName(s string) bool { return samlProviderNameRE.MatchString(s) }

// SAMLProvider is an IAM SAML identity provider (#196). MetadataDocument
// is the document as given: it holds public certificates only. What the
// document means is read from it with ParseSAMLMetadata where it is
// used, so there is one authoritative value.
type SAMLProvider struct {
	Meta
	Name             string            `json:"name"`
	Created          time.Time         `json:"created"`
	MetadataDocument string            `json:"metadataDocument"`
	Tags             map[string]string `json:"tags,omitempty"`
}

func (SAMLProvider) Kind() Kind    { return KindSAMLProvider }
func (p SAMLProvider) Key() string { return p.Name }

// Validate checks the name, the length of the document, the tags, that the
// stored encoding fits MaxSAMLProviderEncodedLen (ErrSAMLProviderTooLarge)
// and that the document parses (ErrSAMLMetadata). It does not read a
// clock. No error carries the document.
func (p SAMLProvider) Validate() error {
	if !ValidSAMLProviderName(p.Name) {
		return invalid("SAML provider name %q", p.Name)
	}
	if n := utf8.RuneCountInString(p.MetadataDocument); n < MinSAMLMetadataLen || n > MaxSAMLMetadataLen {
		return invalid("SAML provider %q metadata document is %d characters, want %d to %d",
			p.Name, n, MinSAMLMetadataLen, MaxSAMLMetadataLen)
	}
	if len(p.Tags) > MaxSAMLProviderTags {
		return invalid("SAML provider %q has %d tags, at most %d", p.Name, len(p.Tags), MaxSAMLProviderTags)
	}
	if err := CheckTags(p.Tags); err != nil {
		return invalid("SAML provider %q tags: %v", p.Name, err)
	}
	// A document longer in bytes than the limit never fits; the check
	// spares encoding it.
	if len(p.MetadataDocument) > MaxSAMLProviderEncodedLen {
		return fmt.Errorf("%w: %w: SAML provider %q", ErrInvalid, ErrSAMLProviderTooLarge, p.Name)
	}
	enc, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode SAML provider %q: %w", p.Name, err)
	}
	if len(enc) > MaxSAMLProviderEncodedLen {
		return fmt.Errorf("%w: %w: SAML provider %q encodes to %d bytes, at most %d",
			ErrInvalid, ErrSAMLProviderTooLarge, p.Name, len(enc), MaxSAMLProviderEncodedLen)
	}
	if _, err := ParseSAMLMetadata(p.MetadataDocument); err != nil {
		return fmt.Errorf("%w: SAML provider %q: %w", ErrInvalid, p.Name, err)
	}
	return nil
}
