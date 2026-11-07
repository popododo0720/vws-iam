package storetest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// samlSampleCert is a fixed self-signed public certificate (base64 DER),
// valid for a hundred years. storetest may import only iam, so the
// metadata around it is built by hand.
const samlSampleCert = "MIIBJDCBy6ADAgECAgEBMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMTEGlkcC5leGFtcGxlLnRlc3QwIBcNMjYwMTAxMD" +
	"AwMDAwWhgPMjEyNjAxMDEwMDAwMDBaMBsxGTAXBgNVBAMTEGlkcC5leGFtcGxlLnRlc3QwWTATBgcqhkjOPQIBBggq" +
	"hkjOPQMBBwNCAARYMk0+b+qSouanAp7zlLmao9TZKt39gHhN0fbq27I86cJ/P4u5LCKiUIyw8YLFQUhdTpixHZQH3e" +
	"vjsU0IqiMbMAoGCCqGSM49BAMCA0gAMEUCIB6GZ9wApyL6tBmg9JN8wVtmXHmUq5NKmqmmw92HUtKoAiEA/vpgrZ0l" +
	"Aq8x50gr/uNO1hXvxB6kyGVVz3rBNUcytIM="

// SAMLMetadata is valid IdP metadata for a fixed certificate with comment
// as an XML comment in the entity, which pads the document. Without a
// comment it is a little under iam.MinSAMLMetadataLen characters.
func SAMLMetadata(comment string) string {
	return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test/saml">
<!--` + comment + `-->
<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>
<ds:X509Certificate>` + samlSampleCert + `</ds:X509Certificate>
</ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
 Location="https://idp.example.test/saml/sso"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>
`
}

// samlSampleProvider is a valid SAML provider with a document of at least
// iam.MinSAMLMetadataLen characters.
func samlSampleProvider(created time.Time) iam.SAMLProvider {
	return iam.SAMLProvider{
		Name: "corp-idp", Created: created, Meta: iam.Meta{UID: "s-1", Generation: 1},
		MetadataDocument: SAMLMetadata(strings.Repeat(" sample", 150)),
		Tags:             map[string]string{"team": "a"},
	}
}

// largestSAMLProvider is a provider whose JSON encoding is exactly
// iam.MaxSAMLProviderEncodedLen bytes, padded with characters that JSON
// escapes to six bytes each, so the stored size is far above the
// document's own.
func largestSAMLProvider(t *testing.T) iam.SAMLProvider {
	t.Helper()
	p := samlSampleProvider(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	size := func(comment string) int {
		p.MetadataDocument = SAMLMetadata(comment)
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	const unit, wide = "<&>", 18
	room := iam.MaxSAMLProviderEncodedLen - size("")
	comment := strings.Repeat(unit, room/wide) + strings.Repeat("x", room%wide)
	if got := size(comment); got != iam.MaxSAMLProviderEncodedLen {
		t.Fatalf("largest provider encodes to %d bytes, want %d", got, iam.MaxSAMLProviderEncodedLen)
	}
	return p
}

// samlProviderLargestRoundTrip stores a provider at the encoded size limit
// and reads it back unchanged: the backend holds one object that large.
func samlProviderLargestRoundTrip(t *testing.T, b store.Backend) {
	ctx := context.Background()
	p := largestSAMLProvider(t)
	if err := p.Validate(); err != nil {
		t.Fatalf("the largest provider is invalid: %v", err)
	}
	if _, err := store.Create(ctx, b, p); err != nil {
		t.Fatalf("create at the limit: %v", err)
	}
	got, err := store.Get[iam.SAMLProvider](ctx, b, "CORP-IDP")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Object.MetadataDocument != p.MetadataDocument || got.Object.Name != p.Name {
		t.Fatalf("the document changed in storage: %d bytes, want %d",
			len(got.Object.MetadataDocument), len(p.MetadataDocument))
	}
	got.Object.Tags = map[string]string{"team": "b"}
	if _, err := store.Update(ctx, b, got.Object, got.Version); err != nil {
		t.Fatalf("update at the limit: %v", err)
	}
	over := p
	over.Name = "over"
	over.MetadataDocument = SAMLMetadata(strings.Repeat("<&>", iam.MaxSAMLProviderEncodedLen/18+1))
	if _, err := store.Create(ctx, b, over); err == nil {
		t.Fatal("a provider over the encoded limit was stored")
	}
}
