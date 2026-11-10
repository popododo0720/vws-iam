package sts_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

// samlSeedDir holds the seed corpus of FuzzVerifySAMLResponse: the IdP
// certificate and responses it signed at samlFuzzNow (its key is not
// kept), the attack shapes built from them, and AWS documentation
// examples. -update-saml-seeds writes it again with a new key.
const samlSeedDir = "testdata/fuzz/saml"

var (
	updateSAMLSeeds = flag.Bool("update-saml-seeds", false, "rewrite "+samlSeedDir)
	samlFuzzNow     = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
)

// samlFuzzClaims are the claims of every signed seed.
func samlFuzzClaims() samltest.Assertion {
	return samltest.Assertion{
		Issuer: samlIssuer, Audience: samlSPID, Recipient: samlAud, Destination: samlAud,
		NameID: "alice@corp.test", NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		Roles:       []string{samlIdpARN + "," + samlRoleARN},
		SessionName: "alice@corp.test", SourceIdentity: "alice", SessionDuration: "1800",
		NotBefore: samlFuzzNow.Add(-time.Minute), NotOnOrAfter: samlFuzzNow.Add(5 * time.Minute),
		ConfirmNotOnOrAfter: samlFuzzNow.Add(5 * time.Minute),
		Attributes:          map[string][]string{"urn:oid:1.3.6.1.4.1.5923.1.1.1.1": {"staff", "member"}},
	}
}

// awsDocResponse is an unsigned response made of the IAM User Guide
// examples (Configure SAML assertions for the authentication response,
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_saml_assertions.html).
const awsDocResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
	`xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0">` +
	`<Issuer>https://idp.corp.test/saml</Issuer>` +
	`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
	`<Assertion ID="_a" Version="2.0"><Issuer>https://idp.corp.test/saml</Issuer><Subject>` +
	`<NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">` +
	`_cbb88bf52c2510eabe00c1642d4643f41430fe25e3</NameID>` +
	`<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
	`<SubjectConfirmationData NotOnOrAfter="2026-01-01T00:05:00Z" Recipient="https://signin.vws.test/saml"/>` +
	`</SubjectConfirmation></Subject>` +
	`<Conditions NotOnOrAfter="2026-01-01T00:05:00Z"><AudienceRestriction><Audience>urn:amazon:webservices</Audience>` +
	`</AudienceRestriction></Conditions><AttributeStatement>` +
	`<Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">` +
	`<AttributeValue>` + samlRoleARN + `,` + samlIdpARN + `</AttributeValue></Attribute>` +
	`<Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">` +
	`<AttributeValue>user-id-name</AttributeValue></Attribute>` +
	`<Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">` +
	`<AttributeValue>1800</AttributeValue></Attribute>` +
	`<Attribute Name="https://aws.amazon.com/SAML/Attributes/SourceIdentity">` +
	`<AttributeValue>Diego</AttributeValue></Attribute>` +
	`</AttributeStatement></Assertion></samlp:Response>`

// TestWriteSAMLSeeds writes the seed corpus with -update-saml-seeds.
func TestWriteSAMLSeeds(t *testing.T) {
	if !*updateSAMLSeeds {
		t.Skip("-update-saml-seeds not set")
	}
	idp, err := samltest.New(samlIssuer, samlFuzzNow)
	if err != nil {
		t.Fatal(err)
	}
	seeds := map[string]string{"aws-doc-unsigned": awsDocResponse}
	for name, sign := range map[string]samltest.Sign{
		"signed-assertion": samltest.SignAssertion, "signed-response": samltest.SignResponse,
		"signed-both": samltest.SignBoth, "unsigned": samltest.SignNone,
	} {
		if seeds[name], err = idp.ResponseXML(samlFuzzClaims(), sign); err != nil {
			t.Fatal(err)
		}
	}
	for name, xml := range samlAttacks(t, idp, samlFuzzClaims()) {
		seeds["attack-"+strings.NewReplacer(" ", "-", ":", "", ",", "").Replace(name)] = xml
	}
	if err := os.RemoveAll(samlSeedDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(samlSeedDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idp.Cert.Raw})
	if err := os.WriteFile(filepath.Join(samlSeedDir, "idp.pem"), cert, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, xml := range seeds {
		if err := os.WriteFile(filepath.Join(samlSeedDir, name+".xml"), []byte(xml), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// FuzzVerifySAMLResponse: no response panics, a refused one is
// InvalidIdentityToken, IDPRejectedClaim or ExpiredToken, and an accepted
// one has exactly the claims the IdP signed. The fuzzer cannot sign, so
// any other accepted claims were read from content no valid signature
// covers (#381).
func FuzzVerifySAMLResponse(f *testing.F) {
	pemBytes, err := os.ReadFile(filepath.Join(samlSeedDir, "idp.pem"))
	if err != nil {
		f.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		f.Fatal("idp.pem holds no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		f.Fatal(err)
	}
	prov := sts.SAMLProvider{ARN: samlIdpARN, EntityID: samlIssuer, Certificates: []*x509.Certificate{cert}}
	verify := func(xml []byte) (sts.SAMLClaims, error) {
		return sts.VerifySAMLResponse(base64.StdEncoding.EncodeToString(xml), prov, samlSP, samlFuzzNow)
	}
	seeds, err := filepath.Glob(filepath.Join(samlSeedDir, "*.xml"))
	if err != nil || len(seeds) == 0 {
		f.Fatalf("no seeds in %s: %v", samlSeedDir, err)
	}
	for _, s := range seeds {
		xml, err := os.ReadFile(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(xml)
	}
	signed, err := os.ReadFile(filepath.Join(samlSeedDir, "signed-assertion.xml"))
	if err != nil {
		f.Fatal(err)
	}
	want, err := verify(signed)
	if err != nil {
		f.Fatalf("the signed seed is refused: %v", err)
	}
	f.Fuzz(func(t *testing.T, xml []byte) {
		got, err := verify(xml)
		if err != nil {
			if !errors.Is(err, sts.ErrInvalidIdentityToken) && !errors.Is(err, sts.ErrIDPRejectedClaim) &&
				!errors.Is(err, sts.ErrExpired) {
				t.Fatalf("refused with %v, not an AssumeRoleWithSAML error", err)
			}
			return
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("accepted claims %+v, the IdP signed %+v", got, want)
		}
	})
}
