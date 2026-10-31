package sts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
)

// ErrPackedPolicyTooLarge is GetFederationToken's answer when its session
// policies together exceed MaxPackedPolicyChars.
var ErrPackedPolicyTooLarge = errors.New("PackedPolicyTooLarge")

// GetFederationToken limits, from the AWS API reference.
const (
	DefaultFederationDuration = 12 * time.Hour
	MaxFederationDuration     = 36 * time.Hour
	// RootFederationMaxDuration caps a root caller's session: a longer
	// request gets one hour, as in AWS.
	RootFederationMaxDuration = time.Hour
	// MaxPackedPolicyChars bounds the plaintext of the inline session
	// policy and the managed session policy ARNs together.
	MaxPackedPolicyChars = 2048
	// MaxSessionPolicyARNs is the most managed session policies a call
	// may pass.
	MaxSessionPolicyARNs = 10
	// FederationAction is the permission GetFederationToken needs.
	FederationAction = "sts:GetFederationToken"
)

var (
	// federatedNameRE is the AWS Name pattern [\w+=,.@-]* with its
	// length constraints.
	federatedNameRE = regexp.MustCompile(`^[\w+=,.@-]{2,32}$`)
	// sessionPolicyRE is the AWS Policy pattern.
	sessionPolicyRE = regexp.MustCompile(`^[\t\n\r\x{20}-\x{FF}]+$`)
)

// FederationToken is what GetFederationToken returns. Never log it.
type FederationToken struct {
	Credentials Credentials
	// FederatedUserID is "<account>:<name>".
	FederatedUserID string
	// ARN is arn:vws:sts::<account>:federated-user/<name>.
	ARN string
	// PackedPolicySize is the percentage (0-100) of MaxPackedPolicyChars
	// that the session policies use.
	PackedPolicySize int
}

// String hides the credentials.
func (f FederationToken) String() string {
	return "FederationToken{" + f.ARN + " " + f.Credentials.String() + "}"
}

// FederationRequest is the input of GetFederationToken.
type FederationRequest struct {
	// Name is the federated user name.
	Name string
	// Duration zero means DefaultFederationDuration.
	Duration time.Duration
	// Policy is the inline session policy; empty means none.
	Policy string
	// PolicyARNs are managed session policies of this project.
	PolicyARNs []string
}

// GetFederationToken returns credentials for a federated user named
// req.Name, to an IAM user (or the root user) calling with long-term
// credentials whose policies allow sts:GetFederationToken on the
// federated user's ARN. The session's permissions are the intersection
// of the caller's policies and the session policies (inline and
// managed); without session policies it has none. Like other sessions,
// it is a sealed token, so nothing is stored and no secret is kept in
// plaintext.
func (s *Service) GetFederationToken(
	ctx context.Context, c Caller, reqCtx map[string][]string, req FederationRequest,
) (FederationToken, error) {
	if c.principalID == "" {
		return FederationToken{}, fmt.Errorf("%w: unresolved caller", ErrAccessDenied)
	}
	if (c.principal.Kind != authz.User && c.principal.Kind != authz.Root) || c.temporary {
		return FederationToken{}, fmt.Errorf("%w: GetFederationToken needs long-term user credentials", ErrAccessDenied)
	}
	d, packed, err := validateFederation(req)
	if err != nil {
		return FederationToken{}, err
	}
	if c.principal.Kind == authz.Root {
		d = min(d, RootFederationMaxDuration)
	}
	for _, arn := range req.PolicyARNs {
		ok, err := s.authz.ManagedPolicyExists(ctx, arn)
		if err != nil {
			return FederationToken{}, fmt.Errorf("get federation token: %w", err)
		}
		if !ok {
			return FederationToken{}, fmt.Errorf("%w: policy %s does not exist or is not attachable", policy.ErrMalformed, arn)
		}
	}
	arn := iam.ARN("sts", "", s.account, "federated-user/"+req.Name)
	dec, err := s.authz.Authorize(ctx, c.principal, FederationAction, arn, s.callerContext(c, reqCtx))
	if err != nil {
		return FederationToken{}, fmt.Errorf("get federation token: %w", err)
	}
	if !dec.Allowed {
		return FederationToken{}, fmt.Errorf("%w: not authorized to perform %s on %s", ErrAccessDenied, FederationAction, arn)
	}
	var inline []string
	if req.Policy != "" {
		inline = []string{req.Policy}
	}
	sess := session{
		Kind: int(c.principal.Kind), Name: c.principal.Name, ARN: arn, Policies: inline,
		PolicyARNs: req.PolicyARNs, Federated: true, PrincipalID: c.principalID, AuthTime: c.authTime,
		SessionName: req.Name,
	}
	creds, err := s.issue(ctx, sess, d)
	if err != nil {
		return FederationToken{}, fmt.Errorf("get federation token: %w", err)
	}
	return FederationToken{
		Credentials: creds, FederatedUserID: s.account + ":" + req.Name, ARN: arn,
		PackedPolicySize: (packed*100 + MaxPackedPolicyChars - 1) / MaxPackedPolicyChars,
	}, nil
}

// validateFederation checks req as AWS does before anything is read: it
// returns the session duration and the packed size of the session
// policies in characters.
func validateFederation(req FederationRequest) (time.Duration, int, error) {
	if !federatedNameRE.MatchString(req.Name) {
		return 0, 0, fmt.Errorf("%w: Name must be 2-32 characters of [\\w+=,.@-]", ErrInvalidRequest)
	}
	d := req.Duration
	if d == 0 {
		d = DefaultFederationDuration
	}
	if d < MinDuration || d > MaxFederationDuration {
		return 0, 0, fmt.Errorf("%w: DurationSeconds %d outside [%d, %d]", ErrInvalidRequest,
			int(d.Seconds()), int(MinDuration.Seconds()), int(MaxFederationDuration.Seconds()))
	}
	packed := 0
	if req.Policy != "" {
		n := utf8.RuneCountInString(req.Policy)
		if n > MaxPackedPolicyChars {
			return 0, 0, fmt.Errorf("%w: Policy is %d characters, limit %d", ErrInvalidRequest, n, MaxPackedPolicyChars)
		}
		if !sessionPolicyRE.MatchString(req.Policy) {
			return 0, 0, fmt.Errorf("%w: Policy has a character outside \\u0009, \\u000A, \\u000D, \\u0020-\\u00FF",
				ErrInvalidRequest)
		}
		if _, err := policy.ParseIdentity(req.Policy); err != nil {
			return 0, 0, fmt.Errorf("session policy: %w", err)
		}
		packed = n
	}
	if n := len(req.PolicyARNs); n > MaxSessionPolicyARNs {
		return 0, 0, fmt.Errorf("%w: %d PolicyArns, limit %d", ErrInvalidRequest, n, MaxSessionPolicyARNs)
	}
	for _, arn := range req.PolicyARNs {
		if len(arn) < 20 || len(arn) > 2048 || strings.ContainsAny(arn, " \t\r\n") {
			return 0, 0, fmt.Errorf("%w: PolicyArns arn must be 20-2048 characters", ErrInvalidRequest)
		}
		packed += len(arn)
	}
	if packed > MaxPackedPolicyChars {
		return 0, 0, fmt.Errorf("%w: session policies are %d characters, limit %d",
			ErrPackedPolicyTooLarge, packed, MaxPackedPolicyChars)
	}
	return d, packed, nil
}
