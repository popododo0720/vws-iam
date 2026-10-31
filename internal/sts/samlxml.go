package sts

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// SAML 2.0 namespaces and values.
const (
	nsSAMLProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsSAMLAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsXMLDSig       = "http://www.w3.org/2000/09/xmldsig#"
	samlSuccess     = "urn:oasis:names:tc:SAML:2.0:status:Success"
	samlBearer      = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
)

// samlClaims are the values AssumeRoleWithSAML reads from a verified
// assertion.
type samlClaims struct {
	issuer, subject, subjectType, recipient string
	// roles are the (role ARN, provider ARN) pairs of the Role attribute.
	roles               [][2]string
	sessionName         string
	sessionDuration     time.Duration
	sourceIdentity      string
	sessionNotOnOrAfter time.Time
}

// grants reports whether the Role attribute names roleARN with
// providerARN.
func (c samlClaims) grants(roleARN, providerARN string) bool {
	for _, p := range c.roles {
		if p[0] == roleARN && p[1] == providerARN {
			return true
		}
	}
	return false
}

func invalidSAML(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidIdentityToken}, a...)...)
}

// verifySAMLResponse decodes a base64 SAML response, checks its XML
// signature against the provider's certificates, and returns the claims
// of its one assertion. Claims are read only from the element whose
// signature was verified (the response or the assertion), so content
// outside the signed element cannot change them (signature wrapping).
func verifySAMLResponse(b64 string, prov SAMLProvider, audience string, now time.Time) (samlClaims, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return samlClaims{}, invalidSAML("SAMLAssertion is not base64")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return samlClaims{}, invalidSAML("SAMLAssertion is not XML")
	}
	for _, t := range doc.Child {
		if _, ok := t.(*etree.Directive); ok {
			return samlClaims{}, invalidSAML("SAMLAssertion has a DTD")
		}
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != nsSAMLProtocol {
		return samlClaims{}, invalidSAML("SAMLAssertion is not a SAML 2.0 Response")
	}
	vctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: prov.Certificates})
	vctx.Clock = dsig.NewFakeClockAt(now)
	signed := false
	resp := root
	if len(children(root, nsXMLDSig, "Signature")) > 0 {
		if resp, err = vctx.Validate(root); err != nil {
			return samlClaims{}, invalidSAML("response signature is not valid")
		}
		signed = true
	}
	if d := resp.SelectAttrValue("Destination", ""); d != "" && d != audience {
		return samlClaims{}, invalidSAML("response Destination is not this service")
	}
	if status, err := one(resp, nsSAMLProtocol, "Status"); err != nil {
		return samlClaims{}, err
	} else if code, err := one(status, nsSAMLProtocol, "StatusCode"); err != nil {
		return samlClaims{}, err
	} else if code.SelectAttrValue("Value", "") != samlSuccess {
		return samlClaims{}, fmt.Errorf("%w: the identity provider did not report success", ErrIDPRejectedClaim)
	}
	if len(children(resp, nsSAMLAssertion, "EncryptedAssertion")) > 0 {
		return samlClaims{}, invalidSAML("encrypted assertions are not supported")
	}
	a, err := one(resp, nsSAMLAssertion, "Assertion")
	if err != nil {
		return samlClaims{}, err
	}
	if len(children(a, nsXMLDSig, "Signature")) > 0 {
		nsCtx, err := etreeutils.NSBuildParentContext(a)
		if err != nil {
			return samlClaims{}, invalidSAML("assertion namespaces")
		}
		detached, err := etreeutils.NSDetatch(nsCtx, a)
		if err != nil {
			return samlClaims{}, invalidSAML("assertion namespaces")
		}
		if a, err = vctx.Validate(detached); err != nil {
			return samlClaims{}, invalidSAML("assertion signature is not valid")
		}
		signed = true
	}
	if !signed {
		return samlClaims{}, invalidSAML("neither the response nor the assertion is signed")
	}
	return assertionClaims(a, prov.EntityID, audience, now)
}

// assertionClaims checks a verified assertion's issuer, validity window,
// audience and bearer confirmation, and reads its attributes.
func assertionClaims(a *etree.Element, entityID, audience string, now time.Time) (samlClaims, error) {
	var cl samlClaims
	iss, err := one(a, nsSAMLAssertion, "Issuer")
	if err != nil {
		return samlClaims{}, err
	}
	if cl.issuer = strings.TrimSpace(iss.Text()); cl.issuer != entityID {
		return samlClaims{}, invalidSAML("Issuer is not the provider's entity id")
	}
	cond, err := one(a, nsSAMLAssertion, "Conditions")
	if err != nil {
		return samlClaims{}, err
	}
	if err := checkWindow(cond, now); err != nil {
		return samlClaims{}, err
	}
	if !hasAudience(cond, audience) {
		return samlClaims{}, invalidSAML("an AudienceRestriction does not name this service")
	}
	subj, err := one(a, nsSAMLAssertion, "Subject")
	if err != nil {
		return samlClaims{}, err
	}
	nameID, err := one(subj, nsSAMLAssertion, "NameID")
	if err != nil {
		return samlClaims{}, err
	}
	cl.subject = strings.TrimSpace(nameID.Text())
	cl.subjectType = strings.TrimPrefix(nameID.SelectAttrValue("Format", ""), nameIDFormatPrefix)
	if cl.subject == "" {
		return samlClaims{}, invalidSAML("NameID is empty")
	}
	if cl.recipient, err = bearerRecipient(subj, audience, now); err != nil {
		return samlClaims{}, err
	}
	for _, as := range children(a, nsSAMLAssertion, "AuthnStatement") {
		if v := as.SelectAttrValue("SessionNotOnOrAfter", ""); v != "" {
			t, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return samlClaims{}, invalidSAML("SessionNotOnOrAfter is not a time")
			}
			if cl.sessionNotOnOrAfter.IsZero() || t.Before(cl.sessionNotOnOrAfter) {
				cl.sessionNotOnOrAfter = t
			}
		}
	}
	if err := cl.readAttributes(a); err != nil {
		return samlClaims{}, err
	}
	return cl, nil
}

// checkWindow checks Conditions NotBefore (with SAMLClockSkew) and
// NotOnOrAfter (ExpiredToken once reached).
func checkWindow(el *etree.Element, now time.Time) error {
	if v := el.SelectAttrValue("NotBefore", ""); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return invalidSAML("NotBefore is not a time")
		}
		if now.Add(SAMLClockSkew).Before(t) {
			return invalidSAML("the assertion is not valid yet")
		}
	}
	if v := el.SelectAttrValue("NotOnOrAfter", ""); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return invalidSAML("NotOnOrAfter is not a time")
		}
		if !now.Before(t) {
			return fmt.Errorf("%w: the SAML assertion has expired", ErrExpired)
		}
	}
	return nil
}

// hasAudience reports whether every AudienceRestriction of cond names
// audience, and there is at least one. SAML 2.0 core 2.5.1.4: the
// Audience values of one restriction combine with OR, the restrictions
// with AND.
func hasAudience(cond *etree.Element, audience string) bool {
	rs := children(cond, nsSAMLAssertion, "AudienceRestriction")
	for _, r := range rs {
		if !slices.ContainsFunc(children(r, nsSAMLAssertion, "Audience"), func(au *etree.Element) bool {
			return strings.TrimSpace(au.Text()) == audience
		}) {
			return false
		}
	}
	return len(rs) > 0
}

// bearerRecipient returns the Recipient of a current bearer
// SubjectConfirmation addressed to audience.
func bearerRecipient(subj *etree.Element, audience string, now time.Time) (string, error) {
	for _, sc := range children(subj, nsSAMLAssertion, "SubjectConfirmation") {
		if sc.SelectAttrValue("Method", "") != samlBearer {
			continue
		}
		for _, d := range children(sc, nsSAMLAssertion, "SubjectConfirmationData") {
			if d.SelectAttrValue("Recipient", "") != audience {
				continue
			}
			v := d.SelectAttrValue("NotOnOrAfter", "")
			if v == "" {
				return "", invalidSAML("SubjectConfirmationData has no NotOnOrAfter")
			}
			t, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return "", invalidSAML("SubjectConfirmationData NotOnOrAfter is not a time")
			}
			if !now.Before(t) {
				return "", fmt.Errorf("%w: the SAML assertion has expired", ErrExpired)
			}
			return audience, nil
		}
	}
	return "", invalidSAML("no bearer SubjectConfirmation with this service as Recipient")
}

// readAttributes reads the Role, RoleSessionName, SessionDuration and
// SourceIdentity attributes.
func (c *samlClaims) readAttributes(a *etree.Element) error {
	vals := map[string][]string{}
	for _, st := range children(a, nsSAMLAssertion, "AttributeStatement") {
		for _, at := range children(st, nsSAMLAssertion, "Attribute") {
			name := at.SelectAttrValue("Name", "")
			for _, v := range children(at, nsSAMLAssertion, "AttributeValue") {
				vals[name] = append(vals[name], strings.TrimSpace(v.Text()))
			}
		}
	}
	for _, v := range vals[samlRoleAttr] {
		x, y, ok := strings.Cut(v, ",")
		x, y = strings.TrimSpace(x), strings.TrimSpace(y)
		switch {
		case !ok:
		case strings.Contains(x, ":saml-provider/"):
			c.roles = append(c.roles, [2]string{y, x})
		default:
			c.roles = append(c.roles, [2]string{x, y})
		}
	}
	if len(c.roles) == 0 {
		return invalidSAML("the Role attribute is missing")
	}
	names := vals[samlSessionNameAttr]
	if len(names) != 1 || !sessionNameRE.MatchString(names[0]) {
		return invalidSAML("RoleSessionName attribute must be one value of 2-64 characters of [\\w+=,.@-]")
	}
	c.sessionName = names[0]
	if d := vals[samlDurationAttr]; len(d) > 0 {
		if len(d) != 1 {
			return invalidSAML("SessionDuration attribute has several values")
		}
		var err error
		if c.sessionDuration, err = parseSessionDuration(d[0]); err != nil {
			return err
		}
	}
	if s := vals[samlSourceIDAttr]; len(s) > 0 {
		if len(s) != 1 || !sourceIdentityRE.MatchString(s[0]) {
			return invalidSAML("SourceIdentity attribute must be one value of 2-64 characters of [\\w+=,.@-]")
		}
		c.sourceIdentity = s[0]
	}
	return nil
}

// children are el's child elements named tag in namespace ns.
func children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			out = append(out, c)
		}
	}
	return out
}

// one is el's only child element named tag in namespace ns.
func one(el *etree.Element, ns, tag string) (*etree.Element, error) {
	c := children(el, ns, tag)
	if len(c) != 1 {
		return nil, invalidSAML("want one %s element, got %d", tag, len(c))
	}
	return c[0], nil
}
