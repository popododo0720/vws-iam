package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// maxSAMLValueLen bounds -saml-audience and -saml-sign-in-url.
const maxSAMLValueLen = 1024

// samlFlags registers the AssumeRoleWithSAML service provider flags on fs.
func samlFlags(fs *flag.FlagSet, sp *sts.SAMLServiceProvider) {
	fs.StringVar(&sp.Audience, "saml-audience", "", "SAML service provider entity id that every "+
		"AudienceRestriction of an AssumeRoleWithSAML assertion must name (AWS: urn:amazon:webservices); "+
		"needs -saml-sign-in-url. Empty with it refuses every AssumeRoleWithSAML")
	fs.StringVar(&sp.SignInURL, "saml-sign-in-url", "", "https SAML sign-in URL (assertion consumer service): "+
		"the Recipient and Destination of an assertion and the SAML:aud trust-policy key "+
		"(AWS: https://signin.aws.amazon.com/saml); needs -saml-audience")
}

// checkSAML accepts both values or neither: an absolute URI audience (a
// urn: or a URL) and an https sign-in URL with a host and no user info,
// "?" or "#", each at most maxSAMLValueLen bytes without spaces or control
// characters. The values are kept exactly as given, because assertions
// are compared with them byte for byte.
func checkSAML(sp sts.SAMLServiceProvider) error {
	switch {
	case sp == (sts.SAMLServiceProvider{}):
		return nil
	case sp.Audience == "" || sp.SignInURL == "":
		return errors.New("AssumeRoleWithSAML needs both -saml-audience and -saml-sign-in-url")
	}
	if err := plainSAMLValue("-saml-audience", sp.Audience); err != nil {
		return err
	}
	if err := plainSAMLValue("-saml-sign-in-url", sp.SignInURL); err != nil {
		return err
	}
	if u, err := url.Parse(sp.Audience); err != nil || u.Scheme == "" || u.Opaque == "" && u.Host == "" {
		return errors.New("-saml-audience must be an absolute URI, such as urn:vws:iam or https://vws.example")
	}
	u, err := url.Parse(sp.SignInURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		strings.ContainsAny(sp.SignInURL, "?#") {
		return errors.New("-saml-sign-in-url must be an https URL with a host and no user info, ? or #")
	}
	return nil
}

// plainSAMLValue refuses a value over maxSAMLValueLen bytes or with a
// space, a control character or invalid UTF-8.
func plainSAMLValue(flag, v string) error {
	if len(v) > maxSAMLValueLen || !utf8.ValidString(v) || strings.ContainsFunc(v, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return fmt.Errorf("%s must be at most %d bytes of UTF-8 without spaces or control characters", flag, maxSAMLValueLen)
	}
	return nil
}

// apiOptions are the grpcapi.Server options cfg sets.
func apiOptions(cfg config) []grpcapi.Option {
	if cfg.saml == (sts.SAMLServiceProvider{}) {
		return nil
	}
	return []grpcapi.Option{grpcapi.WithStoredSAML(cfg.saml)}
}
