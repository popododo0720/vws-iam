package sts_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

const samlRoleAttr = "https://aws.amazon.com/SAML/Attributes/Role"

// samlAttacks are the known SAML attack shapes against a valid claims set
// a, as raw response XML: each is built from responses the IdP signed, so
// only the edit makes it hostile.
func samlAttacks(t *testing.T, idp *samltest.IdP, a samltest.Assertion) map[string]string {
	t.Helper()
	xml := func(a samltest.Assertion, sign samltest.Sign) string {
		out, err := idp.ResponseXML(a, sign)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	edit := func(xml, old, repl string) string {
		out, err := samltest.Replace(xml, old, repl)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	assertionOf := func(xml string) string {
		return xml[strings.Index(xml, "<saml:Assertion"):strings.Index(xml, "</samlp:Response>")]
	}
	evil := a
	evil.SessionName = "mallory"
	signed := xml(a, samltest.SignAssertion)
	// The IdP signs the attacker's own NameID; a comment splits it so a
	// reader of the first text node only would see the victim's.
	split := a
	split.NameID = "alice@corp.test.evil.test"
	// Two Role attributes: AWS reads one Role attribute with every pair as
	// a value, so a second one is not a list to merge.
	dupRole := a
	dupRole.Attributes = map[string][]string{samlRoleAttr: {a.Roles[0]}}
	return map[string]string{
		"wrapped: signed assertion after an unsigned one": edit(signed, "<saml:Assertion",
			assertionOf(xml(evil, samltest.SignNone))+"<saml:Assertion"),
		"wrapped: unsigned assertion after a signed response": edit(xml(a, samltest.SignResponse),
			"</samlp:Response>", assertionOf(xml(evil, samltest.SignNone))+"</samlp:Response>"),
		"two signed Assertion elements": edit(signed, "</samlp:Response>",
			assertionOf(xml(evil, samltest.SignAssertion))+"</samlp:Response>"),
		"comment inside NameID": edit(xml(split, samltest.SignAssertion),
			">alice@corp.test.evil.test<", ">alice@corp.test<!---->.evil.test<"),
		"comment outside the assertion": edit(signed, "<samlp:Status>", "<!-- note --><samlp:Status>"),
		"duplicate Role attribute":      xml(dupRole, samltest.SignAssertion),
		"duplicate XML attribute": edit(signed, `<saml:SubjectConfirmationData `,
			`<saml:SubjectConfirmationData Recipient="https://evil.test/saml" `),
		"DOCTYPE with an entity": `<!DOCTYPE r [<!ENTITY who "mallory">]>` +
			edit(signed, ">alice@corp.test</saml:AttributeValue>", ">&who;</saml:AttributeValue>"),
		"DOCTYPE with an external entity": `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` + signed,
		"entity without DOCTYPE": edit(signed, ">alice@corp.test</saml:AttributeValue>",
			">&who;</saml:AttributeValue>"),
	}
}

// TestAssumeRoleWithSAMLRefusesAttackShapes: signature wrapping, two
// assertions, a comment in the response, a duplicate attribute (SAML or
// XML), and a DTD or entity are each InvalidIdentityToken (#381).
func TestAssumeRoleWithSAMLRefusesAttackShapes(t *testing.T) {
	e := samlSetup(t)
	attacks := samlAttacks(t, e.idp, e.claims())
	duplicateSourceIdentity := e.claims()
	duplicateSourceIdentity.Attributes = map[string][]string{
		"https://aws.amazon.com/SAML/Attributes/SourceIdentity": nil,
	}
	xml, err := e.idp.ResponseXML(duplicateSourceIdentity, samltest.SignAssertion)
	if err != nil {
		t.Fatal(err)
	}
	attacks["duplicate SourceIdentity attribute without a value"] = xml
	for name, xml := range attacks {
		_, err := e.svc.AssumeRoleWithSAML(context.Background(), samlReq(samltest.Encode(xml)))
		if !errors.Is(err, sts.ErrInvalidIdentityToken) {
			t.Errorf("%s: %v, want InvalidIdentityToken", name, err)
		}
	}
}
