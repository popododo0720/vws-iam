package authz

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

const scope = "github.com/popododo0720/vws-iam/internal/authz"

// Instruments come from the global providers, which delegate to the ones
// obs.Setup installs later. Labels are decision and result only: the
// principal, action, resource and request context are client data.
var (
	tracer      = otel.Tracer(scope)
	evaluations = func() metric.Int64Counter {
		c, err := otel.Meter(scope).Int64Counter("vws.iam.authz.evaluations",
			metric.WithDescription("Authorize evaluations by decision and result"))
		if err != nil {
			return noop.Int64Counter{} // a bad instrument must not stop serving
		}
		return c
	}()
	duration = func() metric.Float64Histogram {
		h, err := otel.Meter(scope).Float64Histogram("vws.iam.authz.duration",
			metric.WithDescription("Authorize latency, store reads included, by decision and result"),
			metric.WithUnit("s"))
		if err != nil {
			return noop.Float64Histogram{}
		}
		return h
	}()
)

// observe opens the authz.authorize span. The returned func ends it with
// the decision and the outcome of err, counts the evaluation and records
// its latency.
func observe(ctx context.Context) (context.Context, func(policy.Decision, error)) {
	ctx, span := tracer.Start(ctx, "authz.authorize")
	begin := time.Now()
	return ctx, func(d policy.Decision, err error) {
		r := outcome(err)
		kv := []attribute.KeyValue{attribute.String("decision", decision(d, err)), attribute.String("result", r)}
		span.SetAttributes(kv...)
		if err != nil {
			span.SetStatus(codes.Error, r) // the message may name a user or policy
		}
		span.End()
		evaluations.Add(ctx, 1, metric.WithAttributes(kv...))
		duration.Record(ctx, time.Since(begin).Seconds(), metric.WithAttributes(kv...))
	}
}

func decision(d policy.Decision, err error) string {
	switch {
	case err != nil:
		return "none"
	case d.Allowed:
		return "allow"
	case d.Explicit:
		return "explicit_deny"
	}
	return "implicit_deny"
}

// outcomes is the low-cardinality result label of an error; the first
// match wins.
var outcomes = []struct {
	err   error
	label string
}{
	{ErrNoSuchEntity, "no_such_entity"},
	{policy.ErrMalformed, "malformed_policy"},
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
