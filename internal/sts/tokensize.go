package sts

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// MaxSessionTokenSize is the AWS session token size limit in bytes (#199):
// the most MinimumSessionTokenSize may ask for, and the base of
// SessionTokenUtilization. VWS never refuses a token over it (#364): a VWS
// token is sealed JSON, not AWS's compressed token, so a request AWS
// accepts can make it longer, and refusing it would refuse that request.
const MaxSessionTokenSize = 4096

// The gRPC fields wait for vws-proto#168 (TODO(#199)): no RPC passes an
// IssueOption or returns the size fields yet.

// IssueOption is an optional parameter of the STS calls that issue a
// session: AssumeRole, GetSessionToken, GetFederationToken and
// AssumeRoleWithSAML.
type IssueOption func(*issueOptions)

type issueOptions struct {
	minTokenSize   int
	sourceIdentity string
}

// MinimumSessionTokenSize is the AWS MinimumSessionTokenSize parameter:
// the session token is grown to at least n bytes, whatever its content.
// Zero (the default) leaves it unchanged; outside 0 to
// MaxSessionTokenSize the call is ValidationError.
func MinimumSessionTokenSize(n int) IssueOption {
	return func(o *issueOptions) { o.minTokenSize = n }
}

// issueOpts applies opts of a call that has no SourceIdentity parameter
// and checks them, before any store read.
func issueOpts(opts []IssueOption) (issueOptions, error) {
	o, err := assumeRoleOpts(opts)
	if err == nil && o.sourceIdentity != "" {
		return issueOptions{}, fmt.Errorf("%w: SourceIdentity is a parameter of AssumeRole only", ErrInvalidRequest)
	}
	return o, err
}

// assumeRoleOpts applies the opts of AssumeRole and checks them, before
// any store read.
func assumeRoleOpts(opts []IssueOption) (issueOptions, error) {
	var o issueOptions
	for _, opt := range opts {
		opt(&o)
	}
	if o.minTokenSize < 0 || o.minTokenSize > MaxSessionTokenSize {
		return issueOptions{}, fmt.Errorf("%w: MinimumSessionTokenSize must be between 0 and %d",
			ErrInvalidRequest, MaxSessionTokenSize)
	}
	if o.sourceIdentity != "" && !assumeRoleSourceIdentityRE.MatchString(o.sourceIdentity) {
		return issueOptions{}, fmt.Errorf("%w: SourceIdentity must be 2-64 characters of [\\w+=,.@-]", ErrInvalidRequest)
	}
	return o, nil
}

// tokenUtilization is the AWS SessionTokenUtilization of a token of size
// bytes: the percentage of MaxSessionTokenSize, rounded up. A VWS token is
// not an AWS token, so the share describes the VWS token and can pass 100.
func tokenUtilization(size int) int {
	return (size*100 + MaxSessionTokenSize - 1) / MaxSessionTokenSize
}

// maxPadRounds bounds the reseals of padToken. A round adds the plaintext
// bytes that base64 turns into the missing token bytes, rounded down, so
// each round leaves at most 2 bytes missing, and the next adds one byte.
const maxPadRounds = 4

// padField is the JSON an empty session Pad adds to the sealed session.
const padField = `,"z":""`

// padToken seals sess with seal and, while the token is shorter than
// minSize, grows sess.Pad and seals it again. The pad is inside the sealed
// session, so it is authenticated like the rest and opening ignores it.
func padToken(sess *session, minSize int, seal func(*session) (string, error)) (string, error) {
	token, err := seal(sess)
	for round := 0; err == nil && len(token) < minSize; round++ {
		if round == maxPadRounds {
			return "", fmt.Errorf("session token: %d bytes after %d rounds, want %d", len(token), round, minSize)
		}
		grow := base64.RawURLEncoding.DecodedLen(minSize - len(token))
		if sess.Pad == "" {
			grow -= len(padField) // the first byte also brings the field
		}
		sess.Pad += strings.Repeat("0", max(1, grow))
		token, err = seal(sess)
	}
	return token, err
}
