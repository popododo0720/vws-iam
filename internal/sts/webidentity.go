package sts

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

// ErrIDPCommunication is an OIDC provider whose keys cannot be read
// (AWS IDPCommunicationError). An OIDCProviders lookup returns it
// wrapped; AssumeRoleWithWebIdentity passes it through.
var ErrIDPCommunication = errors.New("IDPCommunicationError")

// AssumeRoleWithWebIdentity limits and names, from the AWS API reference
// and the IAM User Guide (Available keys for AWS OIDC federation).
const (
	WebIdentityAction          = "sts:AssumeRoleWithWebIdentity"
	MinWebIdentityTokenChars   = 4
	MaxWebIdentityTokenChars   = 20000
	MaxWebIdentityRoleDuration = 12 * time.Hour
	// WebIdentityClockSkew is how far a token's nbf or iat may lie in the
	// future.
	WebIdentityClockSkew = 5 * time.Minute

	webSourceIdentityClaim = "https://aws.amazon.com/source_identity"
	webTagsClaim           = "https://aws.amazon.com/tags"
)

// oidcProviderNameRE is the host and path of an issuer URL after
// https://, as the oidc-provider ARN and the condition key prefix use
// it. A colon (port) is refused: it would make "<name>:sub" ambiguous.
// The host needs at least two non-empty labels: a single-label host
// (idp, sts) could collide with a service prefix and would not be a
// qualifier that ClientKey keeps away from clients.
var oidcProviderNameRE = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(/[A-Za-z0-9._~%-]+)*$`)

// OIDCProvider is an IAM OpenID Connect provider: its issuer URL, the
// client ids (audiences) it accepts, and the signing keys of its JWKS.
type OIDCProvider struct {
	ARN string
	// URL is the issuer: a token's iss must equal it.
	URL       string
	ClientIDs []string
	Keys      []OIDCKey
}

// OIDCProviders looks up an OIDC provider by ARN. An unknown provider is
// store.ErrNotFound; keys that cannot be read are ErrIDPCommunication.
type OIDCProviders interface {
	OIDCProvider(ctx context.Context, arn string) (OIDCProvider, error)
}

// WithOIDC sets the OIDC providers. Without it AssumeRoleWithWebIdentity
// refuses every call with InvalidIdentityToken.
func WithOIDC(p OIDCProviders) Option { return func(s *Service) { s.oidc = p } }

// WebIdentityRequest is the input of AssumeRoleWithWebIdentity. Never log
// it: the token is a bearer credential.
type WebIdentityRequest struct {
	RoleARN         string
	RoleSessionName string
	// Token is the OIDC ID token (compact JWS).
	Token string
	// ProviderID is set only for OAuth 2.0 access tokens of
	// www.amazon.com and graph.facebook.com, which VWS does not accept.
	ProviderID string
	// Duration zero means one hour.
	Duration   time.Duration
	Policy     string
	PolicyARNs []string
	// SourceIP is the caller's address as the gateway saw it, the
	// aws:SourceIp of the trust evaluation. Only the transport sets it,
	// never from the token or another client field. Empty means unknown:
	// a trust policy that names aws:SourceIp then refuses the call.
	SourceIP string
}

// setSourceIP puts the trusted source IP into the trust context as
// aws:SourceIp, which AWS has for every AssumeRoleWithWebIdentity call
// (IAM User Guide, AWS global condition context keys). A source IP that
// is not an IP address, or none while the trust policy of r names
// aws:SourceIp, is AccessDenied: the condition is never skipped, so an
// IP-conditioned Deny cannot fail open.
//
// TODO(#105): vws-proto#105 carries the gateway's source IP with the RPC;
// until then no production caller sets it and such a trust policy fails
// closed.
func setSourceIP(tctx map[string][]string, r iam.Role, roleARN, sourceIP string) error {
	if sourceIP != "" {
		ip, err := netip.ParseAddr(sourceIP)
		if err != nil || ip.Zone() != "" {
			return fmt.Errorf("%w: not authorized to perform %s on %s: the source IP is not an IP address",
				ErrAccessDenied, WebIdentityAction, roleARN)
		}
		tctx["aws:SourceIp"] = []string{ip.Unmap().String()}
		return nil
	}
	trust, err := policy.ParseTrust(r.AssumeRolePolicy)
	if err != nil {
		return fmt.Errorf("trust policy of %s: %w", roleARN, err)
	}
	for _, st := range trust.Statements {
		for _, c := range st.Conditions {
			if strings.EqualFold(c.Key, "aws:SourceIp") {
				return fmt.Errorf("%w: not authorized to perform %s on %s: the trust policy needs aws:SourceIp "+
					"and the request has none", ErrAccessDenied, WebIdentityAction, roleARN)
			}
		}
	}
	return nil
}

// String hides the token.
func (r WebIdentityRequest) String() string {
	return "WebIdentityRequest{" + r.RoleARN + " " + r.RoleSessionName + " token=REDACTED}"
}

// WebIdentityRoleSession is what AssumeRoleWithWebIdentity returns. Never
// log it.
type WebIdentityRoleSession struct {
	Credentials Credentials
	// AssumedRoleID is "<role id>:<session name>".
	AssumedRoleID string
	// Audience is the token's azp, else the aud that matched a client id.
	Audience string
	// Provider is the token's iss.
	Provider                    string
	SubjectFromWebIdentityToken string
	SourceIdentity              string
	// PackedPolicySize is the percentage of MaxPackedPolicyChars the
	// session policies use.
	PackedPolicySize int
}

// String hides the credentials.
func (r WebIdentityRoleSession) String() string {
	return "WebIdentityRoleSession{" + r.Credentials.AssumedRoleARN + " " + r.Credentials.String() + "}"
}

// WebIdentity is what AWS keeps of an OIDC token for later requests of
// the role session: the keys "Available in session" (<provider>:sub,
// <provider>:aud, <provider>:amr) and aws:FederatedProvider. No other
// claim carries over (IAM User Guide, Available keys for AWS OIDC
// federation).
type WebIdentity struct {
	// Provider is the provider name (issuer host and path), the prefix of
	// its condition keys.
	Provider    string   `json:"p"`
	ProviderARN string   `json:"pa"`
	Subject     string   `json:"sub"`
	Audience    []string `json:"aud"`
	AMR         []string `json:"amr,omitempty"`
}

// clone returns a deep copy of id.
func (id *WebIdentity) clone() *WebIdentity {
	if id == nil {
		return nil
	}
	c := *id
	c.Audience, c.AMR = slices.Clone(id.Audience), slices.Clone(id.AMR)
	return &c
}

// addTo sets the session keys of id in m; a nil id adds none.
func (id *WebIdentity) addTo(m map[string][]string) {
	if id == nil {
		return
	}
	m[id.Provider+":sub"] = []string{id.Subject}
	m[id.Provider+":aud"] = slices.Clone(id.Audience)
	if len(id.AMR) > 0 {
		m[id.Provider+":amr"] = slices.Clone(id.AMR)
	}
	m["aws:FederatedProvider"] = []string{id.ProviderARN}
}

// ClientKey reports whether a request context key may come from a
// client. saml:* keys, aws:FederatedProvider and OIDC provider keys
// (a qualifier with a dot or slash, like accounts.google.com:sub, which
// no service prefix has; oidcProviderNameRE accepts no other provider
// name) come only from a verified assertion or token or a sealed
// session. Server keys such as aws:userid are checked
// separately.
func ClientKey(k string) bool {
	lk := strings.ToLower(k)
	q, _, _ := strings.Cut(lk, ":")
	return !strings.HasPrefix(lk, samlKeyPrefix) && lk != "aws:federatedprovider" && !strings.ContainsAny(q, "./")
}

// webClaims are the claims of a verified ID token that
// AssumeRoleWithWebIdentity uses.
type webClaims struct {
	iss, sub, azp, email, sourceIdentity string
	aud, amr                             []string
	// hasAzp is whether the token has an azp claim, even an empty one.
	hasAzp bool
}

// AssumeRoleWithWebIdentity returns role credentials for a user
// authenticated by an OIDC provider. It needs no caller credentials: the
// ID token must be signed by a key of the IAM OIDC provider of its issuer
// in this account, name one of the provider's client ids in aud, and be
// current; the role's trust policy must allow
// sts:AssumeRoleWithWebIdentity (and sts:SetSourceIdentity with a source
// identity claim) for the Federated provider with the token's
// <provider>:* keys. Session policies narrow the session. Nothing is
// stored.
func (s *Service) AssumeRoleWithWebIdentity(
	ctx context.Context, req WebIdentityRequest,
) (WebIdentityRoleSession, error) {
	packed, err := validateWebIdentityRequest(req)
	if err != nil {
		return WebIdentityRoleSession{}, err
	}
	if req.ProviderID != "" {
		return WebIdentityRoleSession{}, fmt.Errorf("%w: OAuth 2.0 access tokens (ProviderId) are not supported",
			ErrInvalidIdentityToken)
	}
	tok, err := parseJWT(req.Token)
	if err != nil {
		return WebIdentityRoleSession{}, err
	}
	iss, err := jsonString(tok.claims, "iss")
	name, ok := strings.CutPrefix(iss, "https://")
	if err != nil || !ok || len(iss) > 255 || !oidcProviderNameRE.MatchString(name) {
		return WebIdentityRoleSession{}, fmt.Errorf("%w: the token issuer is not an https URL", ErrInvalidIdentityToken)
	}
	provARN := iam.ARN("iam", "", s.account, "oidc-provider/"+name)
	if s.oidc == nil {
		return WebIdentityRoleSession{}, fmt.Errorf("%w: no OpenIDConnect provider found in your account for %s",
			ErrInvalidIdentityToken, iss)
	}
	prov, err := s.oidc.OIDCProvider(ctx, provARN)
	if errors.Is(err, store.ErrNotFound) {
		return WebIdentityRoleSession{}, fmt.Errorf("%w: no OpenIDConnect provider found in your account for %s",
			ErrInvalidIdentityToken, iss)
	}
	if err != nil {
		return WebIdentityRoleSession{}, fmt.Errorf("assume role with web identity: %w", err)
	}
	if prov.ARN != provARN || prov.URL != iss || len(prov.Keys) == 0 {
		return WebIdentityRoleSession{}, fmt.Errorf("%w: OpenIDConnect provider %s has no keys for %s",
			ErrInvalidIdentityToken, provARN, iss)
	}
	if err := tok.verify(prov.Keys); err != nil {
		return WebIdentityRoleSession{}, err
	}
	// Claims are read only after the signature is verified.
	cl, err := readWebClaims(tok, s.now())
	if err != nil {
		return WebIdentityRoleSession{}, err
	}
	// When the token has azp, AWS STS uses it as the audience (IAM User
	// Guide, Create an OpenID Connect identity provider): azp must be a
	// client id of the provider and aud is not checked. Without azp, one
	// aud value must be a client id.
	audKey, audience := cl.aud, ""
	if cl.hasAzp {
		audKey = []string{cl.azp}
		if slices.Contains(prov.ClientIDs, cl.azp) {
			audience = cl.azp
		}
	} else {
		for _, a := range cl.aud {
			if slices.Contains(prov.ClientIDs, a) {
				audience = a
				break
			}
		}
	}
	if audience == "" {
		return WebIdentityRoleSession{}, fmt.Errorf("%w: incorrect token audience", ErrInvalidIdentityToken)
	}
	r, err := s.federatedRole(ctx, req.RoleARN, WebIdentityAction)
	if err != nil {
		return WebIdentityRoleSession{}, err
	}
	d, err := roleDuration(req.Duration, r.Object.MaxSessionDuration)
	if err != nil {
		return WebIdentityRoleSession{}, err
	}
	// <provider>:aud is azp when the token has one, else aud; oaud is
	// always aud (IAM User Guide, Available keys for AWS OIDC federation).
	id := &WebIdentity{Provider: name, ProviderARN: provARN, Subject: cl.sub, Audience: audKey, AMR: cl.amr}
	tctx := map[string][]string{name + ":oaud": slices.Clone(cl.aud), "sts:RoleSessionName": {req.RoleSessionName}}
	if cl.email != "" {
		tctx[name+":email"] = []string{cl.email}
	}
	if cl.sourceIdentity != "" {
		tctx["sts:SourceIdentity"] = []string{cl.sourceIdentity}
	}
	id.addTo(tctx)
	if err := setSourceIP(tctx, r.Object, req.RoleARN, req.SourceIP); err != nil {
		return WebIdentityRoleSession{}, err
	}
	// Like AssumeRoleWithSAML, the call carries no AWS credentials, so
	// aws:PrincipalAccount is anonymous; the server sets the time keys.
	setTimeKeys(tctx, s.now())
	setAnonymousPrincipalAccount(tctx)
	actions := []string{WebIdentityAction}
	if cl.sourceIdentity != "" {
		actions = append(actions, SetSourceIdentityAction)
	}
	if err := s.federatedTrust(r.Object, req.RoleARN, provARN, actions, tctx); err != nil {
		return WebIdentityRoleSession{}, err
	}
	if err := s.checkSessionPolicyARNs(ctx, req.PolicyARNs); err != nil {
		return WebIdentityRoleSession{}, err
	}
	var inline []string
	if req.Policy != "" {
		inline = []string{req.Policy}
	}
	arn := iam.ARN("sts", "", s.account, "assumed-role/"+r.Object.Name+"/"+req.RoleSessionName)
	// TODO(#210): AWS keeps the source identity in the session as
	// aws:SourceIdentity for later requests and chained role sessions
	// (IAM User Guide, Monitor and control actions taken with assumed
	// roles). It is checked and returned here but not sealed yet, the
	// same gap as #197 for AssumeRoleWithSAML.
	creds, err := s.issue(ctx, session{
		Kind: int(authz.Role), Name: r.Object.Name, ARN: arn, Policies: inline, PolicyARNs: req.PolicyARNs,
		PrincipalID: r.Object.ID, RoleID: r.Object.ID, SessionName: req.RoleSessionName, WebIdentity: id,
	}, d)
	if err != nil {
		return WebIdentityRoleSession{}, fmt.Errorf("assume role with web identity: %w", err)
	}
	creds.AssumedRoleARN = arn
	return WebIdentityRoleSession{
		Credentials: creds, AssumedRoleID: r.Object.ID + ":" + req.RoleSessionName, Audience: audience,
		Provider: iss, SubjectFromWebIdentityToken: cl.sub, SourceIdentity: cl.sourceIdentity,
		PackedPolicySize: (packed*100 + MaxPackedPolicyChars - 1) / MaxPackedPolicyChars,
	}, nil
}

// readWebClaims checks the time claims of a verified token at now (exp
// passed is ExpiredToken; a missing or non-integer exp or iat, or an nbf
// or iat more than WebIdentityClockSkew ahead, is InvalidIdentityToken)
// and reads the claims AssumeRoleWithWebIdentity uses. A token with
// session tags is refused until they are supported (#210).
func readWebClaims(tok jwt, now time.Time) (webClaims, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrInvalidIdentityToken}, a...)...)
	}
	exp, hasExp, err := jsonInt(tok.claims, "exp")
	if err != nil || !hasExp {
		return webClaims{}, bad("exp must be an integer")
	}
	iat, hasIat, err := jsonInt(tok.claims, "iat")
	if err != nil || !hasIat {
		return webClaims{}, bad("iat must be an integer")
	}
	nbf, hasNbf, err := jsonInt(tok.claims, "nbf")
	if err != nil {
		return webClaims{}, bad("nbf must be an integer")
	}
	late := now.Add(WebIdentityClockSkew).Unix()
	if iat > late || (hasNbf && nbf > late) {
		return webClaims{}, bad("the token is not valid yet")
	}
	if now.Unix() >= exp {
		return webClaims{}, fmt.Errorf("%w: the web identity token has expired", ErrExpired)
	}
	var cl webClaims
	if cl.iss, err = jsonString(tok.claims, "iss"); err != nil {
		return webClaims{}, bad("%v", err)
	}
	if cl.sub, err = jsonString(tok.claims, "sub"); err != nil || cl.sub == "" || len(cl.sub) > 255 {
		return webClaims{}, bad("sub must be a string of 1 to 255 characters")
	}
	if cl.aud, err = jsonStrings(tok.claims, "aud"); err != nil || len(cl.aud) == 0 {
		return webClaims{}, bad("aud must be a string or an array of strings")
	}
	if cl.amr, err = jsonStrings(tok.claims, "amr"); err != nil {
		return webClaims{}, bad("%v", err)
	}
	_, cl.hasAzp = tok.claims["azp"]
	if cl.azp, err = jsonString(tok.claims, "azp"); err != nil {
		return webClaims{}, bad("%v", err)
	}
	if cl.email, err = jsonString(tok.claims, "email"); err != nil {
		return webClaims{}, bad("%v", err)
	}
	if cl.sourceIdentity, err = jsonString(tok.claims, webSourceIdentityClaim); err != nil ||
		(cl.sourceIdentity != "" && !sourceIdentityRE.MatchString(cl.sourceIdentity)) {
		return webClaims{}, bad("the source identity claim must be 2 to 256 characters of [\\w+=,.@-]")
	}
	if _, ok := tok.claims[webTagsClaim]; ok {
		return webClaims{}, bad("session tags in the token are not supported yet")
	}
	return cl, nil
}

// ValidateWebIdentityRequest checks the parameters of an
// AssumeRoleWithWebIdentity request as AWS documents them
// (ValidationError, MalformedPolicyDocument, PackedPolicyTooLarge)
// without reading anything.
func ValidateWebIdentityRequest(req WebIdentityRequest) error {
	_, err := validateWebIdentityRequest(req)
	return err
}

// validateWebIdentityRequest checks req as AWS does before anything is
// read and returns the packed size of its session policies.
func validateWebIdentityRequest(req WebIdentityRequest) (int, error) {
	if !validARN(req.RoleARN) {
		return 0, fmt.Errorf("%w: RoleArn must be 20-2048 valid characters", ErrInvalidRequest)
	}
	if !sessionNameRE.MatchString(req.RoleSessionName) {
		return 0, fmt.Errorf("%w: RoleSessionName must be 2-64 characters of [\\w+=,.@-]", ErrInvalidRequest)
	}
	if n := len(req.Token); n < MinWebIdentityTokenChars || n > MaxWebIdentityTokenChars {
		return 0, fmt.Errorf("%w: WebIdentityToken length %d outside [%d, %d]", ErrInvalidRequest,
			n, MinWebIdentityTokenChars, MaxWebIdentityTokenChars)
	}
	if n := len(req.ProviderID); n != 0 && (n < 4 || n > 2048) {
		return 0, fmt.Errorf("%w: ProviderId must be 4-2048 characters", ErrInvalidRequest)
	}
	if d := req.Duration; d != 0 && (d < MinDuration || d > MaxWebIdentityRoleDuration) {
		return 0, fmt.Errorf("%w: DurationSeconds %d outside [%d, %d]", ErrInvalidRequest,
			int(d.Seconds()), int(MinDuration.Seconds()), int(MaxWebIdentityRoleDuration.Seconds()))
	}
	return validateSessionPolicies(req.Policy, req.PolicyARNs)
}
