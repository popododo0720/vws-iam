package iam

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// OpenID Connect provider limits of AWS CreateOpenIDConnectProvider: the
// URL is 1 to 255 characters, a client id 1 to 255, a provider holds at
// most 100 client ids and 5 thumbprints, and a thumbprint is the
// 40-character hex SHA-1 of a certificate.
const (
	MaxOIDCProviderURLLen = 255
	MaxOIDCClientIDLen    = 255
	MaxOIDCClientIDs      = 100
	OIDCThumbprintLen     = 40
	MaxOIDCThumbprints    = 5
	MaxOIDCProviderTags   = 50
)

// OIDCProvider is an IAM OpenID Connect identity provider (#208). URL is
// the issuer as given (https, host and optional path); its key is the URL
// without the scheme, which is also the ARN resource, so one issuer is
// registered once per project. The store folds keys, so two URLs that
// differ only in case are the same provider. ClientIDs are the audiences
// a web identity token may carry. Thumbprints are the hex SHA-1 of the
// server certificates the IdP serves its keys with; none is allowed, as in
// AWS. Nothing here is secret.
type OIDCProvider struct {
	Meta
	URL         string            `json:"url"`
	ClientIDs   []string          `json:"clientIds,omitempty"`
	Thumbprints []string          `json:"thumbprints,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Created     time.Time         `json:"created"`
}

func (OIDCProvider) Kind() Kind    { return KindOIDCProvider }
func (p OIDCProvider) Key() string { return OIDCProviderResource(p.URL) }

// OIDCProviderResource is the ARN resource and store key of an OIDC
// provider URL: the URL without its https:// scheme.
func OIDCProviderResource(url string) string {
	return strings.TrimPrefix(url, oidcScheme)
}

const oidcScheme = "https://"

// ErrOIDCProviderURL is an OIDC provider URL that is not an https issuer.
var ErrOIDCProviderURL = errors.New("OIDC provider URL is not usable")

// CheckOIDCProviderURL checks the form of an issuer URL of 1 to
// MaxOIDCProviderURLLen characters: https://, a host of DNS labels with no
// port or user info, and an optional path of printable ASCII, with no
// query or fragment (OpenID Connect Discovery 1.0, section 2). Every fault
// is ErrOIDCProviderURL with a fixed reason that never carries the URL.
func CheckOIDCProviderURL(url string) error {
	rest, ok := strings.CutPrefix(url, oidcScheme)
	if !ok {
		return fmt.Errorf("%w: it must begin with https://", ErrOIDCProviderURL)
	}
	for i := range len(rest) {
		if c := rest[i]; c <= ' ' || c > '~' {
			return fmt.Errorf("%w: it must be printable ASCII without spaces", ErrOIDCProviderURL)
		}
	}
	if strings.ContainsAny(rest, "?#") {
		return fmt.Errorf("%w: it must not have a query or fragment", ErrOIDCProviderURL)
	}
	host, _, _ := strings.Cut(rest, "/")
	switch {
	case strings.Contains(host, "@"):
		return fmt.Errorf("%w: it must not have user info", ErrOIDCProviderURL)
	case strings.Contains(host, ":"):
		return fmt.Errorf("%w: it must not have a port", ErrOIDCProviderURL)
	case !validHost(host):
		return fmt.Errorf("%w: its host must be DNS labels of [A-Za-z0-9-]", ErrOIDCProviderURL)
	}
	return nil
}

const hostChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

// validHost reports whether h is dot-separated labels of 1 to 63
// characters of [A-Za-z0-9-] that neither start nor end with a hyphen.
func validHost(h string) bool {
	if h == "" {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		if strings.TrimLeft(label, hostChars) != "" {
			return false
		}
	}
	return true
}

// ValidOIDCClientID reports whether id is a client id AWS accepts: 1 to
// MaxOIDCClientIDLen characters of valid UTF-8 (AWS defines no format).
func ValidOIDCClientID(id string) bool {
	n := utf8.RuneCountInString(id)
	return utf8.ValidString(id) && n >= 1 && n <= MaxOIDCClientIDLen
}

// ValidOIDCThumbprint reports whether tp is OIDCThumbprintLen hex digits
// (either case).
func ValidOIDCThumbprint(tp string) bool {
	_, err := hex.DecodeString(tp)
	return len(tp) == OIDCThumbprintLen && err == nil
}

// Validate checks the URL (length and CheckOIDCProviderURL), the client
// ids and thumbprints (form, count, no repeat; thumbprints compare case
// folded) and the tags.
func (p OIDCProvider) Validate() error {
	if n := utf8.RuneCountInString(p.URL); n < 1 || n > MaxOIDCProviderURLLen {
		return invalid("OIDC provider URL is %d characters, want 1 to %d", n, MaxOIDCProviderURLLen)
	}
	if err := CheckOIDCProviderURL(p.URL); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	key := p.Key()
	if len(p.ClientIDs) > MaxOIDCClientIDs {
		return invalid("OIDC provider %q has %d client ids, at most %d", key, len(p.ClientIDs), MaxOIDCClientIDs)
	}
	seen := make(map[string]bool, len(p.ClientIDs))
	for _, id := range p.ClientIDs {
		if !ValidOIDCClientID(id) {
			return invalid("OIDC provider %q has a client id outside 1 to %d characters", key, MaxOIDCClientIDLen)
		}
		if seen[id] {
			return invalid("OIDC provider %q repeats a client id", key)
		}
		seen[id] = true
	}
	if len(p.Thumbprints) > MaxOIDCThumbprints {
		return invalid("OIDC provider %q has %d thumbprints, at most %d", key, len(p.Thumbprints), MaxOIDCThumbprints)
	}
	seen = make(map[string]bool, len(p.Thumbprints))
	for _, tp := range p.Thumbprints {
		if !ValidOIDCThumbprint(tp) {
			return invalid("OIDC provider %q has a thumbprint that is not %d hex digits", key, OIDCThumbprintLen)
		}
		f := strings.ToLower(tp)
		if seen[f] {
			return invalid("OIDC provider %q repeats a thumbprint", key)
		}
		seen[f] = true
	}
	if len(p.Tags) > MaxOIDCProviderTags {
		return invalid("OIDC provider %q has %d tags, at most %d", key, len(p.Tags), MaxOIDCProviderTags)
	}
	if err := CheckTags(p.Tags); err != nil {
		return invalid("OIDC provider %q tags: %v", key, err)
	}
	return nil
}
