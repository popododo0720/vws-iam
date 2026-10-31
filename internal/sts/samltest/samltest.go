// Package samltest is a test SAML identity provider: it issues SAML 2.0
// responses signed with its own key, as an IdP does for AWS STS
// AssumeRoleWithSAML, and serves its provider to sts.WithSAML. It is for
// tests only.
package samltest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// Sign selects what a response signs.
type Sign int

// Signing modes.
const (
	SignAssertion Sign = iota
	SignResponse
	SignBoth
	SignNone
)

// IdP is a test identity provider.
type IdP struct {
	EntityID string
	Cert     *x509.Certificate
	signer   *dsig.SigningContext
}

// New returns an IdP with a fresh RSA key and a self-signed certificate
// valid around now.
func New(entityID string, now time.Time) (*IdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("idp key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: entityID},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("idp certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("idp certificate: %w", err)
	}
	signer, err := dsig.NewSigningContext(key, [][]byte{der})
	if err != nil {
		return nil, fmt.Errorf("idp signer: %w", err)
	}
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	return &IdP{EntityID: entityID, Cert: cert, signer: signer}, nil
}

// Provider is the SAML provider arn for this IdP.
func (p *IdP) Provider(arn string) sts.SAMLProvider {
	return sts.SAMLProvider{ARN: arn, EntityID: p.EntityID, Certificates: []*x509.Certificate{p.Cert}}
}

// Providers serves SAML providers by ARN.
type Providers map[string]sts.SAMLProvider

// SAMLProvider implements sts.SAMLProviders.
func (m Providers) SAMLProvider(_ context.Context, arn string) (sts.SAMLProvider, error) {
	p, ok := m[arn]
	if !ok {
		return sts.SAMLProvider{}, store.ErrNotFound
	}
	return p, nil
}

// Assertion describes a response. Zero times are left out.
type Assertion struct {
	Issuer       string
	Audience     string
	Recipient    string
	Destination  string
	NameID       string
	NameIDFormat string
	// Roles are Role attribute values "role-arn,provider-arn".
	Roles               []string
	SessionName         string
	SessionDuration     string
	SourceIdentity      string
	NotBefore           time.Time
	NotOnOrAfter        time.Time
	ConfirmNotOnOrAfter time.Time
	SessionNotOnOrAfter time.Time
	// Status zero means Success.
	Status string
	// MoreAudienceRestrictions are AudienceRestriction elements after the
	// one naming Audience, each with the listed Audience values.
	MoreAudienceRestrictions [][]string
	// NoSubjectConfirmation leaves the Subject without a
	// SubjectConfirmation element.
	NoSubjectConfirmation bool
	// ExtraSubjectConfirmations adds that many more bearer
	// SubjectConfirmation elements to the Subject.
	ExtraSubjectConfirmations int
	// Attributes are more Attribute elements, by Name.
	Attributes map[string][]string
}

// Response returns the base64 SAML response for a, signed as sign asks.
func (p *IdP) Response(a Assertion, sign Sign) (string, error) {
	resp, err := p.ResponseXML(a, sign)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(resp)), nil
}

// ResponseXML is Response before base64.
func (p *IdP) ResponseXML(a Assertion, sign Sign) (string, error) {
	status := a.Status
	if status == "" {
		status = "urn:oasis:names:tc:SAML:2.0:status:Success"
	}
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	resp.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	resp.CreateAttr("ID", "_resp1")
	resp.CreateAttr("Version", "2.0")
	if a.Destination != "" {
		resp.CreateAttr("Destination", a.Destination)
	}
	resp.CreateElement("saml:Issuer").SetText(a.Issuer)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", status)
	as := assertion(a)
	if sign == SignAssertion || sign == SignBoth {
		signed, err := p.signer.SignEnveloped(as)
		if err != nil {
			return "", fmt.Errorf("sign assertion: %w", err)
		}
		as = signed
	}
	resp.AddChild(as)
	if sign == SignResponse || sign == SignBoth {
		signed, err := p.signer.SignEnveloped(resp)
		if err != nil {
			return "", fmt.Errorf("sign response: %w", err)
		}
		doc.SetRoot(signed)
	}
	out, err := doc.WriteToString()
	if err != nil {
		return "", fmt.Errorf("write response: %w", err)
	}
	return out, nil
}

func assertion(a Assertion) *etree.Element {
	as := etree.NewElement("saml:Assertion")
	as.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	as.CreateAttr("ID", "_assert1")
	as.CreateAttr("Version", "2.0")
	as.CreateElement("saml:Issuer").SetText(a.Issuer)
	subj := as.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	if a.NameIDFormat != "" {
		nid.CreateAttr("Format", a.NameIDFormat)
	}
	nid.SetText(a.NameID)
	if !a.NoSubjectConfirmation {
		addSubjectConfirmation(subj, a)
		for i := 0; i < a.ExtraSubjectConfirmations; i++ {
			addSubjectConfirmation(subj, a)
		}
	}
	cond := as.CreateElement("saml:Conditions")
	setTime(cond, "NotBefore", a.NotBefore)
	setTime(cond, "NotOnOrAfter", a.NotOnOrAfter)
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(a.Audience)
	for _, r := range a.MoreAudienceRestrictions {
		ar := cond.CreateElement("saml:AudienceRestriction")
		for _, au := range r {
			ar.CreateElement("saml:Audience").SetText(au)
		}
	}
	authn := as.CreateElement("saml:AuthnStatement")
	setTime(authn, "SessionNotOnOrAfter", a.SessionNotOnOrAfter)
	st := as.CreateElement("saml:AttributeStatement")
	attr := func(name string, vals ...string) {
		at := st.CreateElement("saml:Attribute")
		at.CreateAttr("Name", name)
		for _, v := range vals {
			at.CreateElement("saml:AttributeValue").SetText(v)
		}
	}
	const base = "https://aws.amazon.com/SAML/Attributes/"
	if len(a.Roles) > 0 {
		attr(base+"Role", a.Roles...)
	}
	if a.SessionName != "" {
		attr(base+"RoleSessionName", a.SessionName)
	}
	if a.SessionDuration != "" {
		attr(base+"SessionDuration", a.SessionDuration)
	}
	if a.SourceIdentity != "" {
		attr(base+"SourceIdentity", a.SourceIdentity)
	}
	names := make([]string, 0, len(a.Attributes))
	for n := range a.Attributes {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		attr(n, a.Attributes[n]...)
	}
	return as
}

func addSubjectConfirmation(subj *etree.Element, a Assertion) {
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("Recipient", a.Recipient)
	setTime(scd, "NotOnOrAfter", a.ConfirmNotOnOrAfter)
}

func setTime(el *etree.Element, name string, t time.Time) {
	if !t.IsZero() {
		el.CreateAttr(name, t.UTC().Format(time.RFC3339))
	}
}

// Encode is base64 of an edited response XML.
func Encode(xml string) string { return base64.StdEncoding.EncodeToString([]byte(xml)) }

// Replace edits a response XML once, failing if old is absent.
func Replace(xml, old, repl string) (string, error) {
	if !strings.Contains(xml, old) {
		return "", fmt.Errorf("%q not in response", old)
	}
	return strings.Replace(xml, old, repl, 1), nil
}
