package sts

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/store"
)

// ErrNoSuchAccessKey is GetAccessKeyInfo's answer for a key id that no
// project holds: never created, deleted, or still pending. AWS documents
// that a deleted key "might return an error that the key doesn't exist";
// its common error for an access key id that "does not exist in our
// records" is InvalidClientTokenId.
var ErrNoSuchAccessKey = errors.New("InvalidClientTokenId")

// GetAccessKeyInfo limits.
const (
	// MinAccessKeyIDLen and MaxAccessKeyIDLen are the AWS AccessKeyId
	// length constraints.
	MinAccessKeyIDLen = 16
	MaxAccessKeyIDLen = 128
	// KeyInfoAction is the permission GetAccessKeyInfo needs.
	KeyInfoAction = "sts:GetAccessKeyInfo"
)

// accessKeyIDRE is the AWS AccessKeyId pattern [\w]* with its length
// constraints.
var accessKeyIDRE = regexp.MustCompile(`^\w{16,128}$`)

// WithKeyIndex sets the unscoped backend that holds the key id -> project
// index of every project, which GetAccessKeyInfo reads. Without it,
// GetAccessKeyInfo fails closed.
func WithKeyIndex(index store.Backend) Option { return func(s *Service) { s.index = index } }

// GetAccessKeyInfo returns the project (AWS account) that owns
// accessKeyID, to a caller whose policies allow sts:GetAccessKeyInfo. The
// key may belong to any project, and its state (active or inactive) is
// not reported, as in AWS. The permission is checked before the key is
// looked up, so a caller without it learns nothing about the key. It only
// reads, so a repeat returns the same account.
//
// Temporary (ASIA) key ids are not stored, so they are ErrNoSuchAccessKey
// for now (popododo0720/vws-iam#188).
func (s *Service) GetAccessKeyInfo(
	ctx context.Context, c Caller, reqCtx map[string][]string, accessKeyID string,
) (string, error) {
	if c.principalID == "" {
		return "", fmt.Errorf("%w: unresolved caller", ErrAccessDenied)
	}
	if n := len(accessKeyID); n < MinAccessKeyIDLen || n > MaxAccessKeyIDLen {
		return "", fmt.Errorf("%w: AccessKeyId length %d outside [%d, %d]",
			ErrInvalidRequest, n, MinAccessKeyIDLen, MaxAccessKeyIDLen)
	}
	if !accessKeyIDRE.MatchString(accessKeyID) {
		return "", fmt.Errorf("%w: AccessKeyId must match [\\w]*", ErrInvalidRequest)
	}
	d, err := s.authz.Authorize(ctx, c.principal, KeyInfoAction, "*", s.callerContext(c, reqCtx))
	if err != nil {
		return "", err
	}
	if !d.Allowed {
		return "", fmt.Errorf("%w: not authorized to perform %s", ErrAccessDenied, KeyInfoAction)
	}
	if s.index == nil {
		return "", errors.New("get access key info: no key index")
	}
	pid, err := accesskey.AccountOf(ctx, s.index, accessKeyID)
	if errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("%w: the access key id does not exist", ErrNoSuchAccessKey)
	}
	if err != nil {
		return "", fmt.Errorf("get access key info: %w", err)
	}
	return pid, nil
}
