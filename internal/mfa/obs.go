package mfa

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
)

const scope = "github.com/popododo0720/vws-iam/internal/mfa"

// Instruments come from the global providers, which delegate to the ones
// obs.Setup installs later. Labels are op, result and event only: no user
// name, device name, serial, seed or code.
var (
	tracer   = otel.Tracer(scope)
	ops      = counter("vws.iam.mfa.operations", "MFA device operations by op and result")
	lockouts = counter("vws.iam.mfa.lockouts", "MFA device lockouts started or renewed, by op and event")
)

func counter(name, desc string) metric.Int64Counter {
	c, err := otel.Meter(scope).Int64Counter(name, metric.WithDescription(desc))
	if err != nil {
		return noop.Int64Counter{} // a bad instrument must not stop serving
	}
	return c
}

// start opens the span of op. The returned func ends it, labelled with the
// outcome of *err, and counts the operation.
func start(ctx context.Context, op string) (context.Context, func(*error)) {
	ctx, span := tracer.Start(ctx, "mfa."+op, trace.WithAttributes(attribute.String("op", op)))
	return ctx, func(err *error) {
		r := outcome(*err)
		span.SetAttributes(attribute.String("result", r))
		if *err != nil {
			span.SetStatus(codes.Error, r) // the message may name a user or device; the result does not
		}
		span.End()
		ops.Add(ctx, 1, metric.WithAttributes(attribute.String("op", op), attribute.String("result", r)))
	}
}

// Lockout events.
const (
	lockStarted = "started"
	lockRenewed = "renewed"
)

func countLockout(ctx context.Context, op, event string) {
	lockouts.Add(ctx, 1, metric.WithAttributes(attribute.String("op", op), attribute.String("event", event)))
	trace.SpanFromContext(ctx).SetAttributes(attribute.String("lockout", event))
}

// outcomes is the low-cardinality result label of an error; the first
// match wins.
var outcomes = []struct {
	err   error
	label string
}{
	{ErrInvalidCode, "invalid_code"},
	{ErrLocked, "locked"},
	{ErrNotAssociated, "not_associated"},
	{ErrEntityInUse, "in_use"},
	{iam.ErrInvalid, "invalid"},
	{secret.ErrUnknownKEK, "unknown_kek"},
	{secret.ErrOpen, "open_failed"},
	{store.ErrNotFound, "not_found"},
	{store.ErrExists, "exists"},
	{store.ErrConflict, "conflict"},
	{store.ErrRenaming, "renaming"},
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
