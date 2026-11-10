package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

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

// unmodifiable is AWS UnmodifiableEntity: the entity is protected, such
// as a service-linked role, which only DeleteServiceLinkedRole deletes.
func unmodifiable(msg string) error {
	return fail(codes.FailedPrecondition, "INVALID_SPEC", "UnmodifiableEntity", msg)
}

// serviceFailure is AWS ServiceFailure: the request failed for a reason
// on the service side, such as a misconfigured linked service.
func serviceFailure(msg string) error {
	return fail(codes.Internal, "", "ServiceFailure", msg)
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

// lockedMsg is the wire message of a locked MFA device. The mfa sentinel
// text (MFADeviceLocked) is not an AWS error code and never reaches the
// wire (#12).
const lockedMsg = "MFA device is locked after too many failed attempts; try again later."

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
	{iam.ErrProtectedRole, codes.FailedPrecondition, "INVALID_SPEC", "UnmodifiableEntity"},
	{sts.ErrInvalidRequest, codes.InvalidArgument, "INVALID_SPEC", "ValidationError"},
	{sts.ErrInvalidAuthorizationMessage, codes.InvalidArgument, "INVALID_SPEC", "InvalidAuthorizationMessageException"},
	{sts.ErrNoSuchAccessKey, codes.NotFound, "RESOURCE_NOT_FOUND", "InvalidClientTokenId"},
	{sts.ErrPackedPolicyTooLarge, codes.InvalidArgument, "INVALID_SPEC", "PackedPolicyTooLarge"},
	{sts.ErrInvalidIdentityToken, codes.InvalidArgument, "INVALID_CREDENTIALS", "InvalidIdentityToken"},
	{sts.ErrIDPRejectedClaim, codes.PermissionDenied, "ACCESS_DENIED", "IDPRejectedClaim"},
	{store.ErrNotFound, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity"},
	{authz.ErrNoSuchEntity, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity"},
	{accesskey.ErrNoSuchUser, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity"},
	{mfa.ErrNotAssociated, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity"},
	{store.ErrExists, codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists"},
	{mfa.ErrEntityInUse, codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists"},
	{store.ErrConflict, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification"},
	{store.ErrRenaming, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification"},
	{mfa.ErrLimitExceeded, codes.ResourceExhausted, "QUOTA_EXCEEDED", "LimitExceeded"},
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

// contextualError keeps diagnostic context separate from the client message.
type contextualError struct {
	operation string
	cause     error
}

func (e *contextualError) Error() string { return fmt.Sprintf("%s: %v", e.operation, e.cause) }
func (e *contextualError) Unwrap() error { return e.cause }

func withErrorContext(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &contextualError{operation: operation, cause: err}
}

// clientMessage is err.Error() with the text of every contextualError in
// err's tree removed, wherever a caller wrapped it (sts.ErrThrottling
// around a limiter error, #305): the client sees the message err had
// without diagnostic context. Outer layers come first, so each layer's
// text is still whole when it is replaced by its cause's.
func clientMessage(err error) string {
	msg := err.Error()
	var walk func(error)
	walk = func(e error) {
		if c, ok := e.(*contextualError); ok { //nolint:errorlint // Visits each node of the tree once.
			msg = strings.Replace(msg, c.Error(), c.cause.Error(), 1)
		}
		switch u := e.(type) { //nolint:errorlint // Walks the wrap tree itself.
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		case interface{ Unwrap() []error }:
			for _, x := range u.Unwrap() {
				walk(x)
			}
		}
	}
	walk(err)
	return msg
}

// toStatus maps any error to the wire. Unknown errors become INTERNAL with
// no detail; the cause is logged without request data.
func toStatus(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	diagnostic := err
	for {
		contextual, ok := err.(*contextualError) //nolint:errorlint // Only strip outer diagnostic wrappers.
		if !ok {
			break
		}
		err = contextual.cause
	}
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.GRPCStatus().Err()
	}
	// Lost compare-and-swap races until the deadline is contention, not a
	// timeout: ConcurrentModification tells the client to retry (#51).
	timedOut := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
	if timedOut && !errors.Is(err, store.ErrConflict) {
		return status.Error(status.FromContextError(err).Code(), clientMessage(err))
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		// A wrapped status takes err.Error() as its message (grpc-go), so
		// a contextual layer under the wrapper is removed here too.
		if msg := clientMessage(err); msg != err.Error() {
			p := st.Proto()
			p.Message = msg
			return status.ErrorProto(p)
		}
		return err
	}
	for _, m := range mapping {
		if errors.Is(err, m.err) {
			msg := clientMessage(err)
			switch {
			case errors.Is(m.err, mfa.ErrLocked):
				msg = lockedMsg
			case m.code == codes.Unauthenticated || m.code == codes.Unavailable:
				msg = m.aws // never echo key ids, tokens, or backend detail
			}
			return (&apiError{code: m.code, reason: m.reason, aws: m.aws, msg: msg}).GRPCStatus().Err()
		}
	}
	slog.Default().LogAttrs(ctx, slog.LevelError, "internal error", slog.String("error", diagnostic.Error()))
	return (&apiError{code: codes.Internal, aws: "InternalFailure", msg: "internal error"}).GRPCStatus().Err()
}
