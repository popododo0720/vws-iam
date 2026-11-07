package iam_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

const (
	mdNS = "urn:oasis:names:tc:SAML:2.0:metadata"
	dsNS = "http://www.w3.org/2000/09/xmldsig#"
	// canary is planted in every hostile document; no error may carry it.
	canary = "SECRETCANARY"
)

// testCert returns a fresh self-signed certificate and its base64 DER.
func testCert(t *testing.T, cn string) (*x509.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<33, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, base64.StdEncoding.EncodeToString(der)
}

// keyDesc is a md:KeyDescriptor holding the certificates. use "-" leaves
// the attribute out.
func keyDesc(use string, certs ...string) string {
	attr := ""
	if use != "-" {
		attr = ` use="` + use + `"`
	}
	var b strings.Builder
	for _, c := range certs {
		b.WriteString("<ds:X509Certificate>" + c + "</ds:X509Certificate>")
	}
	return "<md:KeyDescriptor" + attr + "><ds:KeyInfo><ds:X509Data>" + b.String() +
		"</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
}

// idp is an md:IDPSSODescriptor with attrs and children.
func idp(attrs, children string) string {
	return "<md:IDPSSODescriptor " + attrs + ` protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		children + "</md:IDPSSODescriptor>"
}

// entity is an md:EntityDescriptor with attrs and children, the md and ds
// prefixes bound, carrying the canary in an attribute of its own.
func entity(attrs, children string) string {
	return `<md:EntityDescriptor xmlns:md="` + mdNS + `" xmlns:ds="` + dsNS + `" data-x="` + canary + `" ` +
		attrs + ">" + children + "</md:EntityDescriptor>"
}

func TestParseSAMLMetadata(t *testing.T) {
	certA, a := testCert(t, "a")
	certB, b := testCert(t, "b")
	_, enc := testCert(t, "enc")
	const id = `entityID="https://idp.example/saml"`
	signingIDP := idp("", keyDesc("signing", a))

	good := []struct {
		name  string
		doc   string
		certs []*x509.Certificate
		until string
	}{
		{"single", entity(id, signingIDP), []*x509.Certificate{certA}, ""},
		{
			"two signing and one encryption", entity(id, idp("",
				keyDesc("signing", a)+keyDesc("encryption", enc)+keyDesc("signing", b))),
			[]*x509.Certificate{certA, certB},
			"",
		},
		{"use absent counts as signing", entity(id, idp("", keyDesc("-", a))), []*x509.Certificate{certA}, ""},
		{
			"duplicate certificate dropped", entity(id, idp("", keyDesc("signing", a, b)+keyDesc("-", a))),
			[]*x509.Certificate{certA, certB},
			"",
		},
		{"whitespace in base64", entity(id, idp("", keyDesc("signing",
			"\n  "+a[:40]+"\r\n\t"+a[40:]+"  \n"))), []*x509.Certificate{certA}, ""},
		{
			"two IDP descriptors", entity(id, idp("", keyDesc("signing", a))+idp("", keyDesc("signing", b))),
			[]*x509.Certificate{certA, certB},
			"",
		},
		{
			"validUntil on the entity", entity(id+` validUntil="2030-01-02T03:04:05Z"`, signingIDP),
			[]*x509.Certificate{certA},
			"2030-01-02T03:04:05Z",
		},
		{
			"earliest validUntil wins", entity(id+` validUntil="2030-01-02T03:04:05Z"`,
				idp(`validUntil="2028-06-01T00:00:00.5Z"`, keyDesc("signing", a))+idp(`validUntil="2029-01-01T00:00:00Z"`, "")),
			[]*x509.Certificate{certA},
			"2028-06-01T00:00:00.5Z",
		},
		{
			"validUntil on the IDP with an offset",
			entity(id, idp(`validUntil="2028-06-01T02:00:00+02:00"`, keyDesc("signing", a))),
			[]*x509.Certificate{certA},
			"2028-06-01T00:00:00Z",
		},
		{
			"validUntil without a time zone is UTC",
			entity(id+` validUntil="2030-01-02T03:04:05.5"`, signingIDP),
			[]*x509.Certificate{certA},
			"2030-01-02T03:04:05.5Z",
		},
		{
			"expired validUntil is accepted", entity(id+` validUntil="2001-01-01T00:00:00Z"`, signingIDP),
			[]*x509.Certificate{certA},
			"2001-01-01T00:00:00Z",
		},
		{"declaration, comments and BOM", "\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- c -->\n" +
			entity(id, "<!-- x -->"+signingIDP) + "\n<!-- end -->\n \n", []*x509.Certificate{certA}, ""},
		{"default namespaces", `<EntityDescriptor xmlns="` + mdNS + `" ` + id + `><IDPSSODescriptor><KeyDescriptor>` +
			`<KeyInfo xmlns="` + dsNS + `"><X509Data><X509Certificate>` + a + `</X509Certificate></X509Data></KeyInfo>` +
			`</KeyDescriptor></IDPSSODescriptor></EntityDescriptor>`, []*x509.Certificate{certA}, ""},
		{
			"other elements are ignored", entity(id, "<md:Organization/>"+idp("",
				"<md:ArtifactResolutionService/>"+keyDesc("signing", a)+"<md:SingleSignOnService/>")+"<md:ContactPerson/>"),
			[]*x509.Certificate{certA},
			"",
		},
	}
	for _, c := range good {
		t.Run(c.name, func(t *testing.T) {
			got, err := iam.ParseSAMLMetadata(c.doc)
			if err != nil {
				t.Fatal(err)
			}
			if got.EntityID != "https://idp.example/saml" {
				t.Fatalf("EntityID = %q", got.EntityID)
			}
			if len(got.Certificates) != len(c.certs) {
				t.Fatalf("%d certificates, want %d", len(got.Certificates), len(c.certs))
			}
			for i, cert := range c.certs {
				if !got.Certificates[i].Equal(cert) {
					t.Fatalf("certificate %d is not the expected one", i)
				}
			}
			var want time.Time
			if c.until != "" {
				var err error
				if want, err = time.Parse(time.RFC3339, c.until); err != nil {
					t.Fatal(err)
				}
			}
			if !got.ValidUntil.Equal(want) {
				t.Fatalf("ValidUntil = %v, want %v", got.ValidUntil, want)
			}
		})
	}

	bad := []struct{ name, doc string }{
		{"not XML", "this is " + canary + " not xml"},
		{"empty", ""},
		{"truncated", entity(id, signingIDP)[:80]},
		{"mismatched tags", `<md:EntityDescriptor xmlns:md="` + mdNS + `"><` + canary + `></md:EntityDescriptor>`},
		{"DTD", `<!DOCTYPE ` + canary + ` [<!ENTITY x "y">]>` + entity(id, signingIDP)},
		{"entity declaration inside", `<!DOCTYPE a [<!ENTITY ` + canary + ` "v">]>` + entity(id, signingIDP)},
		{"undefined entity reference", entity(id, signingIDP+"&"+canary+";")},
		{"EntitiesDescriptor root", `<md:EntitiesDescriptor xmlns:md="` + mdNS + `">` + entity(id, signingIDP) +
			`</md:EntitiesDescriptor>`},
		{"other root", `<` + canary + ` xmlns="` + mdNS + `"/>`},
		{"two roots", entity(id, signingIDP) + entity(id, signingIDP)},
		{"text after the root", entity(id, signingIDP) + " " + canary},
		{"text before the root", canary + entity(id, signingIDP)},
		{"wrong namespace", strings.Replace(entity(id, signingIDP), mdNS, "urn:"+canary, 1)},
		{"unbound prefix", `<md:EntityDescriptor ` + id + `><md:IDPSSODescriptor/></md:EntityDescriptor>`},
		{"descriptor in another namespace", entity(id,
			`<x:IDPSSODescriptor xmlns:x="urn:other">`+keyDesc("signing", a)+`</x:IDPSSODescriptor>`)},
		{"certificate in another namespace", entity(id, idp("", `<md:KeyDescriptor><ds:KeyInfo><ds:X509Data>`+
			`<x:X509Certificate xmlns:x="urn:other">`+a+`</x:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`))},
		{"no IDPSSODescriptor", entity(id, "<md:SPSSODescriptor>"+keyDesc("signing", a)+"</md:SPSSODescriptor>")},
		{"certificate under a service provider only", entity(id, "<md:SPSSODescriptor>"+keyDesc("signing", a)+
			"</md:SPSSODescriptor>"+idp("", ""))},
		{"certificate in a signature, not a KeyDescriptor", entity(id, "<ds:Signature><ds:KeyInfo><ds:X509Data>"+
			"<ds:X509Certificate>"+a+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"+idp("", ""))},
		{
			"certificate nested one level too deep",
			entity(id, idp("", "<md:Extensions>"+keyDesc("signing", a)+"</md:Extensions>")),
		},
		{"empty entityID", entity(`entityID=""`, signingIDP)},
		{"blank entityID", entity(`entityID="  "`, signingIDP)},
		{"no entityID", entity("", signingIDP)},
		{"no signing certificate", entity(id, idp("", ""))},
		{"only an encryption certificate", entity(id, idp("", keyDesc("encryption", a)))},
		{"no X509Certificate", entity(id, idp("", keyDesc("signing")))},
		{"unknown use", entity(id, idp("", keyDesc("whatever", a)))},
		{"empty use", entity(id, idp("", keyDesc("", a)))},
		{"bad base64", entity(id, idp("", keyDesc("signing", "!!!"+canary+"!!!")))},
		{
			"DER that is not a certificate",
			entity(id, idp("", keyDesc("signing", base64.StdEncoding.EncodeToString([]byte(canary))))),
		},
		{"empty certificate", entity(id, idp("", keyDesc("signing", " ")))},
		{"a good and a bad certificate", entity(id, idp("", keyDesc("signing", a, "AAAA")))},
		{"malformed validUntil on the entity", entity(id+` validUntil="`+canary+`"`, signingIDP)},
		{"zero validUntil", entity(id+` validUntil="0001-01-01T00:00:00Z"`,
			idp(`validUntil="2099-01-01T00:00:00Z"`, keyDesc("signing", a)))},
		{"duplicate entityID", `<md:EntityDescriptor xmlns:md="` + mdNS + `" xmlns:ds="` + dsNS +
			`" entityID="https://` + canary + `/" ` + id + `>` + signingIDP + `</md:EntityDescriptor>`},
		{"duplicate attribute through two prefixes", entity(id+` xmlns:p="urn:x" xmlns:q="urn:x" p:a="1" q:a="2"`,
			signingIDP)},
		{"duplicate use", entity(id, idp("", strings.Replace(keyDesc("encryption", a), `use="encryption"`,
			`use="encryption" use="signing"`, 1)))},
		{"invalid UTF-8 in a comment", entity(id, "<!--\xff "+canary+"-->"+signingIDP)},
		{"invalid UTF-8 in a certificate", entity(id, idp("", keyDesc("signing", a[:8]+"\xff"+a[8:])))},
		{"declaration after a comment", "<!-- c -->" + `<?xml version="1.0"?>` + entity(id, signingIDP)},
		{"two declarations", `<?xml version="1.0"?><?xml version="1.0"?>` + entity(id, signingIDP)},
		{"declaration inside the root", entity(id, `<?xml version="1.0"?>`+signingIDP)},
		{"declaration in another case", `<?XML version="1.0"?>` + entity(id, signingIDP)},
		{"non-XML space after the root", entity(id, signingIDP) + "\u00a0\u2028"},
		{"element inside a certificate", entity(id, idp("", keyDesc("signing", a[:8]+"<md:x/>"+a[8:])))},
		{"non-XML space inside a certificate", entity(id, idp("", keyDesc("signing", a[:8]+"\u00a0"+a[8:])))},
		{"malformed validUntil on the IDP", entity(id, idp(`validUntil="tomorrow"`, keyDesc("signing", a)))},
		{"too deep", entity(id, signingIDP+strings.Repeat("<md:a>", 70)+strings.Repeat("</md:a>", 70))},
		{"not UTF-8", `<?xml version="1.0" encoding="ISO-8859-1"?>` + entity(id, signingIDP)},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			got, err := iam.ParseSAMLMetadata(c.doc)
			if err == nil {
				t.Fatalf("accepted: %+v", got)
			}
			if !errors.Is(err, iam.ErrSAMLMetadata) || errors.Is(err, iam.ErrInvalid) {
				t.Fatalf("error %v: want ErrSAMLMetadata and not ErrInvalid", err)
			}
			if strings.Contains(err.Error(), canary) || len(err.Error()) > 200 {
				t.Fatalf("error carries document content: %q", err)
			}
			if got.EntityID != "" || got.Certificates != nil {
				t.Fatalf("partial result with an error: %+v", got)
			}
		})
	}
}

func TestParseSAMLMetadataDepthBoundary(t *testing.T) {
	_, a := testCert(t, "a")
	// The entity is level 1 and the IDP level 2, so n more elements nest to
	// level 2+n; the limit is 64 levels.
	nest := func(n int) string {
		return entity(`entityID="e"`, idp("", keyDesc("signing", a)+strings.Repeat("<md:a>", n)+strings.Repeat("</md:a>", n)))
	}
	if _, err := iam.ParseSAMLMetadata(nest(62)); err != nil {
		t.Fatalf("nesting at the limit: %v", err)
	}
	if _, err := iam.ParseSAMLMetadata(nest(63)); err == nil {
		t.Fatal("nesting past the limit was accepted")
	}
}
