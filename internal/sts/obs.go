package sts

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
)

const scope = "github.com/popododo0720/vws-iam/internal/sts"

// Instruments come from the global providers, which delegate to the ones
// obs.Setup installs later. Labels are op and result only: the principal,
// role, session name, key id, token, MFA serial and code, SAML assertion
// and policy text are client data or secrets.
var (
	tracer = otel.Tracer(scope)
	ops    = func() metric.Int64Counter {
		c, err := otel.Meter(scope).Int64Counter("vws.iam.sts.operations",
			metric.WithDescription("STS operations by op and result"))
		if err != nil {
			return noop.Int64Counter{} // a bad instrument must not stop serving
		}
		return c
	}()
	duration = func() metric.Float64Histogram {
		h, err := otel.Meter(scope).Float64Histogram("vws.iam.sts.duration",
			metric.WithDescription("STS operation latency, store reads included, by op and result"),
			metric.WithUnit("s"))
		if err != nil {
			return noop.Float64Histogram{}
		}
		return h
	}()
)

// start opens the span sts.<op>. The returned func ends it, labelled with
// the outcome of *err, counts the operation and records its latency.
func start(ctx context.Context, op string) (context.Context, func(*error)) {
	ctx, span := tracer.Start(ctx, "sts."+op, trace.WithAttributes(attribute.String("op", op)))
	begin := time.Now()
	return ctx, func(err *error) {
		r := outcome(*err)
		kv := []attribute.KeyValue{attribute.String("op", op), attribute.String("result", r)}
		span.SetAttributes(attribute.String("result", r))
		if *err != nil {
			span.SetStatus(codes.Error, r) // the message may name a user, role or key
		}
		span.End()
		ops.Add(ctx, 1, metric.WithAttributes(kv...))
		duration.Record(ctx, time.Since(begin).Seconds(), metric.WithAttributes(kv...))
	}
}

// outcomes is the low-cardinality result label of an error; the first
// match wins. The STS sentinels come first: an AccessDenied that wraps the
// text of an MFA failure is access_denied, whatever it quotes.
var outcomes = []struct {
	err   error
	label string
}{
	{ErrThrottling, "throttling"},
	{ErrExpired, "expired"},
	{ErrInvalidToken, "invalid_token"},
	{ErrNoSuchAccessKey, "invalid_token"},
	{ErrInvalidRequest, "validation"},
	{ErrAccessDenied, "access_denied"},
	{ErrInvalidIdentityToken, "invalid_identity_token"},
	{ErrIDPRejectedClaim, "idp_rejected_claim"},
	{ErrInvalidAuthorizationMessage, "invalid_authorization_message"},
	{ErrPackedPolicyTooLarge, "packed_policy_too_large"},
	{authz.ErrNoSuchEntity, "no_such_entity"},
	{policy.ErrMalformed, "malformed_policy"},
	{secret.ErrUnknownKEK, "unknown_kek"},
	{secret.ErrOpen, "open_failed"},
	{store.ErrNotFound, "not_found"},
	{store.ErrConflict, "conflict"},
	{store.ErrUnavailable, "unavailable"},
	{context.Canceled, "canceled"},
	{context.DeadlineExceeded, "deadline_exceeded"},
}

func outcome(err error) string {
	if err == nil {
		return "ok"
	}
	for _, o := range outcomes {
		if errors.Is(err, o.err) {
			return o.label
		}
	}
	return "error"
}
