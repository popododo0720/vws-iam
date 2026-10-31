package sts

import "slices"

// samlContextAttr is the trust-policy context key a SAML attribute maps
// to and whether the key is a list of strings or one string.
type samlContextAttr struct {
	key  string
	list bool
}

// samlContextAttrs maps SAML Attribute Name values to SAML:<key> trust
// policy context keys, as the IAM User Guide lists them ("Mapping SAML
// attributes to AWS trust policy context keys": eduPerson and eduOrg,
// Active Directory, and X.500 attributes). The guide prints three X.500
// OIDs with a typo (2.4.5.42, 0.9.2342.19200300100.1.1 and .1.3); both
// the printed and the standard OIDs map, so an IdP configured either way
// reaches the same key.
var samlContextAttrs = map[string]samlContextAttr{
	// eduPerson and eduOrg.
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.1":  {"eduPersonAffiliation", true},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.2":  {"eduPersonNickname", true},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.3":  {"eduPersonOrgDN", false},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.4":  {"eduPersonOrgUnitDN", true},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.5":  {"eduPersonPrimaryAffiliation", false},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.6":  {"eduPersonPrincipalName", false},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.7":  {"eduPersonEntitlement", true},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.8":  {"eduPersonPrimaryOrgUnitDN", false},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.9":  {"eduPersonScopedAffiliation", true},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.10": {"eduPersonTargetedID", true},
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.11": {"eduPersonAssurance", true},
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.2":  {"eduOrgHomePageURI", true},
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.3":  {"eduOrgIdentityAuthNPolicyURI", true},
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.4":  {"eduOrgLegalName", true},
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.5":  {"eduOrgSuperiorURI", true},
	"urn:oid:1.3.6.1.4.1.5923.1.2.1.6":  {"eduOrgWhitePagesURI", true},
	"urn:oid:2.5.4.3":                   {"cn", true},
	// Active Directory.
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":              {"name", false},
	"http://schemas.xmlsoap.org/claims/CommonName":                            {"commonName", false},
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":         {"givenName", false},
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname":           {"surname", false},
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":      {"mail", false},
	"http://schemas.microsoft.com/ws/2008/06/identity/claims/primarygroupsid": {"uid", false},
	// X.500.
	"2.5.4.3":                    {"commonName", false},
	"2.5.4.4":                    {"surname", false},
	"2.4.5.42":                   {"givenName", false},
	"2.5.4.42":                   {"givenName", false},
	"2.5.4.45":                   {"x500UniqueIdentifier", false},
	"0.9.2342.19200300100.1.1":   {"uid", false},
	"0.9.2342.19200300.100.1.1":  {"uid", false},
	"0.9.2342.19200300100.1.3":   {"mail", false},
	"0.9.2342.19200300.100.1.3":  {"mail", false},
	"0.9.2342.19200300.100.1.45": {"organizationStatus", false},
}

// samlAttributeContext returns the SAML:<key> trust-policy context of
// the attribute values vals (by Attribute Name). A string-typed key
// with more than one distinct value, from one attribute or from several
// that map to it, is InvalidIdentityToken: AWS maps only one claim per
// key without saying which, and choosing one could let a Deny on the
// other pass.
func samlAttributeContext(vals map[string][]string) (map[string][]string, error) {
	out := map[string][]string{}
	for name, vs := range vals {
		m, ok := samlContextAttrs[name]
		if !ok || len(vs) == 0 {
			continue
		}
		k := "SAML:" + m.key
		for _, v := range vs {
			if !slices.Contains(out[k], v) {
				out[k] = append(out[k], v)
			}
		}
		if !m.list && len(out[k]) > 1 {
			return nil, invalidSAML("attribute %s must have one value", m.key)
		}
	}
	for _, vs := range out {
		slices.Sort(vs)
	}
	return out, nil
}
