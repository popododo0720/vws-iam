package iam

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// ErrSAMLMetadata wraps every fault of a SAML metadata document. It is
// not an ErrInvalid: the gRPC edge answers it with the AWS InvalidInput
// code, as AWS does for metadata it cannot use. No message carries
// document content.
var ErrSAMLMetadata = errors.New("invalid SAML metadata")

// utf8BOM may start a document.
const utf8BOM = "\xef\xbb\xbf"

const (
	samlMetadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"
	xmlDSigNS      = "http://www.w3.org/2000/09/xmldsig#"
	// maxSAMLMetadataDepth bounds element nesting.
	maxSAMLMetadataDepth = 64
)

// samlCertPath is where a signing certificate sits in an IdP's metadata.
var samlCertPath = [...]xml.Name{
	{Space: samlMetadataNS, Local: "EntityDescriptor"},
	{Space: samlMetadataNS, Local: "IDPSSODescriptor"},
	{Space: samlMetadataNS, Local: "KeyDescriptor"},
	{Space: xmlDSigNS, Local: "KeyInfo"},
	{Space: xmlDSigNS, Local: "X509Data"},
	{Space: xmlDSigNS, Local: "X509Certificate"},
}

// SAMLMetadata is what a SAML provider's metadata document says that
// matters to AssumeRoleWithSAML. It is parsed from the stored document
// on use and never stored.
type SAMLMetadata struct {
	EntityID string
	// Certificates are the distinct signing certificates of the IdP, in
	// document order.
	Certificates []*x509.Certificate
	// ValidUntil is the earliest validUntil of the entity and its IdP
	// descriptors, zero when none is set. A time already passed is not an
	// error here: the document is checked against a clock where it is
	// used.
	ValidUntil time.Time
}

func samlMetadataFault(what string) error { return fmt.Errorf("%w: %s", ErrSAMLMetadata, what) }

// ParseSAMLMetadata reads the metadata of one SAML identity provider: a
// single EntityDescriptor in the SAML 2.0 metadata namespace with a
// non-empty entityID and at least one IDPSSODescriptor. It returns the
// signing certificates found only at
// IDPSSODescriptor/KeyDescriptor/KeyInfo/X509Data/X509Certificate (a
// KeyDescriptor with use "signing" or none; "encryption" is skipped), each
// a base64 DER X.509 certificate, an exact duplicate dropped. A DTD or
// entity declaration, an EntitiesDescriptor or any other root, a second
// root, content after the root, nesting deeper than 64 elements, a
// malformed validUntil and a document with no signing certificate are
// errors. Element names are matched with their namespace, so a prefix
// bound to another namespace does not count.
func ParseSAMLMetadata(doc string) (SAMLMetadata, error) {
	d := xml.NewDecoder(strings.NewReader(strings.TrimPrefix(doc, utf8BOM)))
	var (
		md       SAMLMetadata
		path     []xml.Name
		rooted   bool
		sawIDP   bool
		signing  bool
		capture  bool
		pem      strings.Builder
		seen     = map[string]bool{}
		fail     = func(what string) (SAMLMetadata, error) { return SAMLMetadata{}, samlMetadataFault(what) }
		validity = func(e xml.StartElement) error {
			for _, a := range e.Attr {
				if a.Name.Space != "" || a.Name.Local != "validUntil" {
					continue
				}
				t, err := time.Parse(time.RFC3339, strings.TrimSpace(a.Value))
				if err != nil {
					return samlMetadataFault("validUntil is not an xs:dateTime")
				}
				if md.ValidUntil.IsZero() || t.Before(md.ValidUntil) {
					md.ValidUntil = t
				}
			}
			return nil
		}
	)
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail("the document is not well-formed XML")
		}
		switch t := tok.(type) {
		case xml.Directive:
			return fail("a DTD or entity declaration is not allowed")
		case xml.CharData:
			switch {
			case len(path) == 0 && len(bytes.TrimSpace(t)) > 0:
				return fail("text outside the root element")
			case capture && len(path) == len(samlCertPath):
				pem.Write(t)
			}
		case xml.StartElement:
			if len(path) == 0 {
				if rooted {
					return fail("more than one root element")
				}
				rooted = true
				if t.Name != samlCertPath[0] {
					return fail("the root element is not an EntityDescriptor in the SAML metadata namespace")
				}
			}
			if len(path) >= maxSAMLMetadataDepth {
				return fail("elements are nested too deeply")
			}
			path = append(path, t.Name)
			onPath := len(path) <= len(samlCertPath) && slices.Equal(path, samlCertPath[:len(path)])
			switch {
			case len(path) == 1:
				for _, a := range t.Attr {
					if a.Name.Space == "" && a.Name.Local == "entityID" {
						md.EntityID = a.Value
					}
				}
				if err := validity(t); err != nil {
					return SAMLMetadata{}, err
				}
			case len(path) == 2 && onPath:
				sawIDP = true
				if err := validity(t); err != nil {
					return SAMLMetadata{}, err
				}
			case len(path) == 3 && onPath:
				signing = true
				for _, a := range t.Attr {
					if a.Name.Space != "" || a.Name.Local != "use" {
						continue
					}
					switch a.Value {
					case "signing":
					case "encryption":
						signing = false
					default:
						return fail("a KeyDescriptor use is neither signing nor encryption")
					}
				}
			case len(path) == len(samlCertPath) && onPath && signing:
				capture = true
				pem.Reset()
			}
		case xml.EndElement:
			if capture && len(path) == len(samlCertPath) {
				capture = false
				cert, err := decodeSAMLCertificate(pem.String())
				if err != nil {
					return SAMLMetadata{}, err
				}
				if key := string(cert.Raw); !seen[key] {
					seen[key] = true
					md.Certificates = append(md.Certificates, cert)
				}
			}
			path = path[:len(path)-1]
		}
	}
	switch {
	case !rooted:
		return fail("no EntityDescriptor")
	case strings.TrimSpace(md.EntityID) == "":
		return fail("the EntityDescriptor has no entityID")
	case !sawIDP:
		return fail("the EntityDescriptor has no IDPSSODescriptor")
	case len(md.Certificates) == 0:
		return fail("the IDPSSODescriptor has no signing certificate")
	}
	return md, nil
}

// decodeSAMLCertificate reads an X509Certificate element's text: base64
// DER with whitespace allowed anywhere.
func decodeSAMLCertificate(text string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
	if err != nil {
		return nil, samlMetadataFault("an X509Certificate is not base64")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, samlMetadataFault("an X509Certificate is not a DER X.509 certificate")
	}
	return cert, nil
}
