package sts

import (
	"context"
	"crypto/sha1" //nolint:gosec // NameQualifier is SHA-1 by the AWS definition; it is an identifier, not a MAC.
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

// AssumeRoleWithSAML errors, named as AWS names them.
var (
	// ErrInvalidIdentityToken is a SAML response that cannot be validated:
	// not base64 or XML, unsigned, signed by a key the provider does not
	// list, for another audience or recipient, missing a required
	// attribute, or naming an unknown SAML provider.
	ErrInvalidIdentityToken = errors.New("InvalidIdentityToken")
	// ErrIDPRejectedClaim is a SAML response whose status is not Success.
	ErrIDPRejectedClaim = errors.New("IDPRejectedClaim")
)

// AssumeRoleWithSAML limits and names, from the AWS API reference and
// the IAM User Guide (Configuring SAML assertions for the authentication
// response).
const (
	SAMLAction            = "sts:AssumeRoleWithSAML"
	MaxSAMLRoleDuration   = 12 * time.Hour
	MinSAMLAssertionChars = 4
	MaxSAMLAssertionChars = 100000
	// SAMLClockSkew is how far a NotBefore may lie in the future.
	SAMLClockSkew = 5 * time.Minute

	samlRoleAttr        = "https://aws.amazon.com/SAML/Attributes/Role"
	samlSessionNameAttr = "https://aws.amazon.com/SAML/Attributes/RoleSessionName"
	samlDurationAttr    = "https://aws.amazon.com/SAML/Attributes/SessionDuration"
	samlSourceIDAttr    = "https://aws.amazon.com/SAML/Attributes/SourceIdentity"
	nameIDFormatPrefix  = "urn:oasis:names:tc:SAML:2.0:nameid-format:"
)

var (
	// samlARNRE is the AWS RoleArn/PrincipalArn pattern; validARN also
	// checks the 20-2048 character length.
	samlARNRE = regexp.MustCompile(`^[\t\n\r\x{20}-\x{7E}\x{85}\x{A0}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]+$`)
	// samlProviderNameRE is the IAM SAML provider name.
	samlProviderNameRE = regexp.MustCompile(`^[\w._-]{1,128}$`)
	sourceIdentityRE   = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)
)

// SAMLProvider is an IAM SAML provider: the IdP's entity id and the
// signing certificates from its metadata document.
type SAMLProvider struct {
	ARN string
	// EntityID is the IdP entityID; an assertion's Issuer must equal it.
	EntityID     string
	Certificates []*x509.Certificate
	// ValidUntil is the metadata expiry; zero means none.
	ValidUntil time.Time
}

// SAMLProviders looks up a SAML provider by ARN. An unknown provider is
// store.ErrNotFound.
type SAMLProviders interface {
	SAMLProvider(ctx context.Context, arn string) (SAMLProvider, error)
}

// WithSAML sets the SAML providers and the audience (the sign-in
// endpoint URL) a SAML response must be addressed to. Without it,
// AssumeRoleWithSAML refuses every call with InvalidIdentityToken.
func WithSAML(p SAMLProviders, audience string) Option {
	return func(s *Service) { s.saml, s.samlAudience = p, audience }
}

// SAMLRequest is the input of AssumeRoleWithSAML. Never log it: the
// assertion is a bearer credential.
type SAMLRequest struct {
	RoleARN      string
	PrincipalARN string
	// Assertion is the base64 SAML response from the IdP.
	Assertion string
	// Duration zero means one hour.
	Duration   time.Duration
	Policy     string
	PolicyARNs []string
}

// String hides the assertion.
func (r SAMLRequest) String() string {
	return "SAMLRequest{" + r.RoleARN + " " + r.PrincipalARN + " assertion=REDACTED}"
}

// SAMLRoleSession is what AssumeRoleWithSAML returns. Never log it.
type SAMLRoleSession struct {
	Credentials Credentials
	// AssumedRoleID is "<role id>:<session name>".
	AssumedRoleID string
	// Audience is the Recipient of the SubjectConfirmationData.
	Audience       string
	Issuer         string
	Subject        string
	SubjectType    string
	NameQualifier  string
	SourceIdentity string
	// PackedPolicySize is the percentage of MaxPackedPolicyChars the
	// session policies use.
	PackedPolicySize int
}

// String hides the credentials.
func (r SAMLRoleSession) String() string {
	return "SAMLRoleSession{" + r.Credentials.AssumedRoleARN + " " + r.Credentials.String() + "}"
}

// AssumeRoleWithSAML returns role credentials for a user authenticated by
// a SAML IdP. It needs no caller credentials: the response must be signed
// by a certificate of the SAML provider PrincipalARN, be addressed to this
// service's audience, be current, and grant the (RoleARN, PrincipalARN)
// pair in its Role attribute; the role's trust policy must allow
// sts:AssumeRoleWithSAML for the provider with the SAML:* keys of the
// assertion. Session policies narrow the session. Nothing is stored.
func (s *Service) AssumeRoleWithSAML(ctx context.Context, req SAMLRequest) (SAMLRoleSession, error) {
	packed, err := validateSAMLRequest(req)
	if err != nil {
		return SAMLRoleSession{}, err
	}
	providerName, ok := s.samlProviderName(req.PrincipalARN)
	if !ok || s.saml == nil || s.samlAudience == "" {
		return SAMLRoleSession{}, fmt.Errorf("%w: SAML provider %s does not exist", ErrInvalidIdentityToken, req.PrincipalARN)
	}
	r, err := s.samlRole(ctx, req.RoleARN)
	if err != nil {
		return SAMLRoleSession{}, err
	}
	prov, err := s.saml.SAMLProvider(ctx, req.PrincipalARN)
	if errors.Is(err, store.ErrNotFound) {
		return SAMLRoleSession{}, fmt.Errorf("%w: SAML provider %s does not exist", ErrInvalidIdentityToken, req.PrincipalARN)
	}
	if err != nil {
		return SAMLRoleSession{}, fmt.Errorf("assume role with saml: %w", err)
	}
	now := s.now().UTC()
	if prov.ARN != req.PrincipalARN || prov.EntityID == "" || len(prov.Certificates) == 0 ||
		(!prov.ValidUntil.IsZero() && !now.Before(prov.ValidUntil)) {
		return SAMLRoleSession{}, fmt.Errorf("%w: SAML provider %s has no valid metadata",
			ErrInvalidIdentityToken, req.PrincipalARN)
	}
	cl, err := verifySAMLResponse(req.Assertion, prov, s.samlAudience, now)
	if err != nil {
		return SAMLRoleSession{}, err
	}
	if !cl.grants(req.RoleARN, req.PrincipalARN) {
		return SAMLRoleSession{}, fmt.Errorf("%w: the SAML assertion does not grant %s with %s",
			ErrAccessDenied, req.RoleARN, req.PrincipalARN)
	}
	d, err := samlDuration(req.Duration, r.Object.MaxSessionDuration, cl, now)
	if err != nil {
		return SAMLRoleSession{}, err
	}
	nameQualifier := samlNameQualifier(cl.issuer, s.account, providerName)
	tctx := map[string][]string{
		"SAML:aud": {cl.recipient}, "SAML:iss": {cl.issuer}, "SAML:sub": {cl.subject},
		"SAML:sub_type": {cl.subjectType}, "SAML:namequalifier": {nameQualifier},
		"SAML:doc":              {s.account + "/" + providerName},
		"aws:FederatedProvider": {req.PrincipalARN},
	}
	if cl.sourceIdentity != "" {
		tctx["sts:SourceIdentity"] = []string{cl.sourceIdentity}
	}
	trust, err := policy.ParseTrust(r.Object.AssumeRolePolicy)
	if err != nil {
		return SAMLRoleSession{}, fmt.Errorf("trust policy of %s: %w", req.RoleARN, err)
	}
	tr := policy.Request{Federated: req.PrincipalARN, Action: SAMLAction, Resource: req.RoleARN, Context: tctx}
	if td := policy.Evaluate(tr, []policy.Named{{Name: req.RoleARN + " trust policy", Doc: trust}}, nil); !td.Allowed {
		return SAMLRoleSession{}, fmt.Errorf("%w: not authorized to perform %s on %s",
			ErrAccessDenied, SAMLAction, req.RoleARN)
	}
	for _, arn := range req.PolicyARNs {
		ok, err := s.authz.ManagedPolicyExists(ctx, arn)
		if err != nil {
			return SAMLRoleSession{}, fmt.Errorf("assume role with saml: %w", err)
		}
		if !ok {
			return SAMLRoleSession{}, fmt.Errorf("%w: policy %s does not exist or is not attachable", policy.ErrMalformed, arn)
		}
	}
	var inline []string
	if req.Policy != "" {
		inline = []string{req.Policy}
	}
	arn := iam.ARN("sts", "", s.account, "assumed-role/"+r.Object.Name+"/"+cl.sessionName)
	creds, err := s.issue(ctx, session{
		Kind: int(authz.Role), Name: r.Object.Name, ARN: arn, Policies: inline, PolicyARNs: req.PolicyARNs,
		PrincipalID: r.Object.ID, RoleID: r.Object.ID, SessionName: cl.sessionName,
	}, d)
	if err != nil {
		return SAMLRoleSession{}, fmt.Errorf("assume role with saml: %w", err)
	}
	creds.AssumedRoleARN = arn
	return SAMLRoleSession{
		Credentials: creds, AssumedRoleID: r.Object.ID + ":" + cl.sessionName, Audience: cl.recipient,
		Issuer: cl.issuer, Subject: cl.subject, SubjectType: cl.subjectType, NameQualifier: nameQualifier,
		SourceIdentity:   cl.sourceIdentity,
		PackedPolicySize: (packed*100 + MaxPackedPolicyChars - 1) / MaxPackedPolicyChars,
	}, nil
}

// validateSAMLRequest checks req as AWS does before anything is read and
// returns the packed size of its session policies.
func validateSAMLRequest(req SAMLRequest) (int, error) {
	if !validARN(req.RoleARN) {
		return 0, fmt.Errorf("%w: RoleArn must be 20-2048 valid characters", ErrInvalidRequest)
	}
	if !validARN(req.PrincipalARN) {
		return 0, fmt.Errorf("%w: PrincipalArn must be 20-2048 valid characters", ErrInvalidRequest)
	}
	if n := len(req.Assertion); n < MinSAMLAssertionChars || n > MaxSAMLAssertionChars {
		return 0, fmt.Errorf("%w: SAMLAssertion length %d outside [%d, %d]", ErrInvalidRequest,
			n, MinSAMLAssertionChars, MaxSAMLAssertionChars)
	}
	if d := req.Duration; d != 0 && (d < MinDuration || d > MaxSAMLRoleDuration) {
		return 0, fmt.Errorf("%w: DurationSeconds %d outside [%d, %d]", ErrInvalidRequest,
			int(d.Seconds()), int(MinDuration.Seconds()), int(MaxSAMLRoleDuration.Seconds()))
	}
	return validateSessionPolicies(req.Policy, req.PolicyARNs)
}

func validARN(s string) bool {
	n := utf8.RuneCountInString(s)
	return n >= 20 && n <= 2048 && utf8.ValidString(s) && samlARNRE.MatchString(s)
}

// samlProviderName returns the name of a saml-provider ARN of this
// account.
func (s *Service) samlProviderName(arn string) (string, bool) {
	name, ok := strings.CutPrefix(arn, "arn:"+iam.Partition+":iam::"+s.account+":saml-provider/")
	return name, ok && samlProviderNameRE.MatchString(name)
}

// samlRole reads the role roleARN names; an unknown role, or one whose
// path differs, is AccessDenied as in AssumeRole.
func (s *Service) samlRole(ctx context.Context, roleARN string) (store.Versioned[iam.Role], error) {
	denied := fmt.Errorf("%w: not authorized to perform %s on %s", ErrAccessDenied, SAMLAction, roleARN)
	i := strings.LastIndex(roleARN, "/")
	if !strings.HasPrefix(roleARN, "arn:"+iam.Partition+":iam::"+s.account+":role/") || i < 0 {
		return store.Versioned[iam.Role]{}, denied
	}
	r, err := store.Get[iam.Role](ctx, s.b, roleARN[i+1:])
	if errors.Is(err, store.ErrNotFound) || (err == nil && iam.RoleARN(s.account, r.Object) != roleARN) {
		return store.Versioned[iam.Role]{}, denied
	}
	if err != nil {
		return store.Versioned[iam.Role]{}, fmt.Errorf("assume role with saml: %w", err)
	}
	return r, nil
}

// samlDuration is the session length: DurationSeconds (default one
// hour), which must not exceed the role's maximum, shortened to the
// assertion's SessionDuration attribute and SessionNotOnOrAfter.
func samlDuration(req, roleMax time.Duration, cl samlClaims, now time.Time) (time.Duration, error) {
	if roleMax == 0 {
		roleMax = time.Hour
	}
	d := req
	if d == 0 {
		d = min(DefaultAssumeDuration, roleMax)
	}
	if d > roleMax {
		return 0, fmt.Errorf("%w: DurationSeconds %d exceeds the MaxSessionDuration %d of the role",
			ErrInvalidRequest, int(d.Seconds()), int(roleMax.Seconds()))
	}
	if cl.sessionDuration > 0 {
		d = min(d, cl.sessionDuration)
	}
	if !cl.sessionNotOnOrAfter.IsZero() {
		left := cl.sessionNotOnOrAfter.Sub(now).Truncate(time.Second)
		if left <= 0 {
			return 0, fmt.Errorf("%w: SessionNotOnOrAfter has passed", ErrExpired)
		}
		d = min(d, left)
	}
	return d, nil
}

// samlNameQualifier is BASE64(SHA1(issuer + account + "/" + provider)),
// as AWS defines NameQualifier.
func samlNameQualifier(issuer, account, provider string) string {
	h := sha1.Sum([]byte(issuer + account + "/" + provider)) //nolint:gosec // see import
	return base64.StdEncoding.EncodeToString(h[:])
}

// parseSessionDuration reads the SessionDuration attribute: whole
// seconds from 900 to 43200.
func parseSessionDuration(v string) (time.Duration, error) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	d := time.Duration(n) * time.Second
	if err != nil || d < MinDuration || d > MaxSAMLRoleDuration {
		return 0, fmt.Errorf("%w: SessionDuration attribute must be %d to %d seconds", ErrInvalidIdentityToken,
			int(MinDuration.Seconds()), int(MaxSAMLRoleDuration.Seconds()))
	}
	return d, nil
}
