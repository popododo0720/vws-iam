package grpcapi

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/password"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/sigv4"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// ErrorDomain is google.rpc.ErrorInfo.domain (vws.common.v1.ErrorReason).
const ErrorDomain = "vws.dev"

// AWSCodeKey is the ErrorInfo metadata key carrying the AWS error code
// (NoSuchEntity, MalformedPolicyDocument, ...) for console-api's Query API.
const AWSCodeKey = "aws_code"

// apiError is a wire error: gRPC code, ErrorReason, and AWS code.
type apiError struct {
	code   codes.Code
	reason string
	aws    string
	msg    string
}

func (e *apiError) Error() string { return e.msg }

// GRPCStatus lets status.FromError read an apiError.
func (e *apiError) GRPCStatus() *status.Status {
	st := status.New(e.code, e.msg)
	d, err := st.WithDetails(&errdetails.ErrorInfo{Reason: e.reason, Domain: ErrorDomain, Metadata: map[string]string{AWSCodeKey: e.aws}})
	if err != nil {
		return st
	}
	return d
}

func fail(code codes.Code, reason, aws, msg string) error {
	return &apiError{code: code, reason: reason, aws: aws, msg: msg}
}

func invalidSpec(msg string) error {
	return fail(codes.InvalidArgument, "INVALID_SPEC", "ValidationError", msg)
}

// invalidInput is AWS InvalidInput: a well-formed request with an invalid
// value, such as a tag outside the AWS tag alphabet.
func invalidInput(msg string) error {
	return fail(codes.InvalidArgument, "INVALID_SPEC", "InvalidInput", msg)
}

func invalidID(msg string) error {
	return fail(codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError", msg)
}

func notFound(msg string) error {
	return fail(codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity", msg)
}

func deleteConflict(msg string) error {
	return fail(codes.FailedPrecondition, "DEPENDENCY_MISSING", "DeleteConflict", msg)
}

func quota(msg string) error {
	return fail(codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded", msg)
}

func invalidCredentials(aws, msg string) error {
	return fail(codes.Unauthenticated, "INVALID_CREDENTIALS", aws, msg)
}

func accessDenied(msg string) error {
	return fail(codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied", msg)
}

// mapping is the domain error table. Order matters only for wrapped errors
// that match several sentinels; the first match wins.
var mapping = []struct {
	err    error
	code   codes.Code
	reason string
	aws    string
}{
	{policy.ErrMalformed, codes.InvalidArgument, "INVALID_SPEC", "MalformedPolicyDocument"},
	{iam.ErrInvalid, codes.InvalidArgument, "INVALID_SPEC", "ValidationError"},
	{sts.ErrInvalidRequest, codes.InvalidArgument, "INVALID_SPEC", "ValidationError"},
	{sts.ErrInvalidAuthorizationMessage, codes.InvalidArgument, "INVALID_SPEC", "InvalidAuthorizationMessageException"},
	{sts.ErrNoSuchAccessKey, codes.NotFound, "RESOURCE_NOT_FOUND", "InvalidClientTokenId"},
	{store.ErrNotFound, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity"},
	{authz.ErrNoSuchEntity, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity"},
	{accesskey.ErrNoSuchUser, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity"},
	{mfa.ErrNotAssociated, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity"},
	{store.ErrExists, codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists"},
	{mfa.ErrEntityInUse, codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists"},
	{store.ErrConflict, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification"},
	{store.ErrRenaming, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification"},
	{accesskey.ErrLimitExceeded, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded"},
	{accesskey.ErrInactive, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId"},
	{sts.ErrInvalidToken, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidToken"},
	{sts.ErrExpired, codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken"},
	{mfa.ErrInvalidCode, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidAuthenticationCode"},
	{mfa.ErrLocked, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied"},
	{password.ErrMismatch, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId"},
	{sigv4.ErrSkew, codes.Unauthenticated, "INVALID_CREDENTIALS", "RequestTimeTooSkewed"},
	{sigv4.ErrSignature, codes.Unauthenticated, "INVALID_CREDENTIALS", "SignatureDoesNotMatch"},
	{sigv4.ErrHash, codes.Unauthenticated, "INVALID_CREDENTIALS", "SignatureDoesNotMatch"},
	{sigv4.ErrScope, codes.Unauthenticated, "INVALID_CREDENTIALS", "IncompleteSignature"},
	{sigv4.ErrMalformed, codes.Unauthenticated, "INVALID_CREDENTIALS", "IncompleteSignature"},
	{errThrottled, codes.ResourceExhausted, "QUOTA_EXCEEDED", "Throttling"},
	{sts.ErrThrottling, codes.ResourceExhausted, "QUOTA_EXCEEDED", "Throttling"},
	{sts.ErrAccessDenied, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied"},
	{store.ErrUnavailable, codes.Unavailable, "", "ServiceUnavailable"},
}

// toStatus maps any error to the wire. Unknown errors become INTERNAL with
// no detail; the cause is logged without request data.
func toStatus(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.GRPCStatus().Err()
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return status.FromContextError(err).Err()
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	for _, m := range mapping {
		if errors.Is(err, m.err) {
			msg := err.Error()
			if m.code == codes.Unauthenticated || m.code == codes.Unavailable {
				msg = m.aws // never echo key ids, tokens, or backend detail
			}
			return (&apiError{code: m.code, reason: m.reason, aws: m.aws, msg: msg}).GRPCStatus().Err()
		}
	}
	slog.Default().LogAttrs(ctx, slog.LevelError, "internal error", slog.String("error", err.Error()))
	return (&apiError{code: codes.Internal, aws: "InternalFailure", msg: "internal error"}).GRPCStatus().Err()
}
