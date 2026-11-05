package accesskey

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"

	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
)

const scope = "github.com/popododo0720/vws-iam/internal/accesskey"

// Instruments come from the global providers, which delegate to the ones
// obs.Setup installs later. Labels are op and result only: no key id,
// user name or secret.
var (
	tracer  = otel.Tracer(scope)
	ops     = counter("vws.iam.access_key.operations", "Access key operations by op and result")
	rewraps = counter("vws.iam.access_key.rewraps", "Secrets resealed under the active KEK, by result")
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
	ctx, span := tracer.Start(ctx, "accesskey."+op, trace.WithAttributes(attribute.String("op", op)))
	return ctx, func(err *error) {
		r := outcome(*err)
		span.SetAttributes(attribute.String("result", r))
		if *err != nil {
			span.SetStatus(codes.Error, r) // the message may name a user; the result does not
		}
		span.End()
		ops.Add(ctx, 1, metric.WithAttributes(attribute.String("op", op), attribute.String("result", r)))
	}
}

func countRewrap(ctx context.Context, r string) {
	rewraps.Add(ctx, 1, metric.WithAttributes(attribute.String("result", r)))
	trace.SpanFromContext(ctx).SetAttributes(attribute.String("rewrap", r))
}

// outcomes is the low-cardinality result label of an error; the first
// match wins.
var outcomes = []struct {
	err   error
	label string
}{
	{ErrInactive, "inactive"},
	{ErrLimitExceeded, "limit_exceeded"},
	{ErrNoSuchUser, "no_such_user"},
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
