package kubestore

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

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

const instrumentation = "github.com/popododo0720/vws-iam/internal/store/kubestore"

// telemetry traces and times every store.Backend call. Keys never become
// attributes: they hold user names and would explode cardinality.
type telemetry struct {
	tracer   trace.Tracer
	duration metric.Float64Histogram
}

func newTelemetry(tp trace.TracerProvider, mp metric.MeterProvider) telemetry {
	h, err := mp.Meter(instrumentation).Float64Histogram("vws.iam.store.duration",
		metric.WithDescription("Kube store call latency by operation, kind and result"),
		metric.WithUnit("s"))
	if err != nil {
		h = noop.Float64Histogram{} // a bad instrument must not stop serving
	}
	return telemetry{tracer: tp.Tracer(instrumentation), duration: h}
}

func globalTelemetry() telemetry {
	return newTelemetry(otel.GetTracerProvider(), otel.GetMeterProvider())
}

// start opens the span of one Backend call; end records its result.
func (t telemetry) start(ctx context.Context, op string, kind iam.Kind) (context.Context, func(error)) {
	attrs := []attribute.KeyValue{
		attribute.String("vws.iam.store.op", op),
		attribute.String("vws.iam.store.kind", string(kind)),
	}
	ctx, span := t.tracer.Start(ctx, "kubestore."+op,
		trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
	begin := time.Now()
	return ctx, func(err error) {
		res := outcome(err)
		attrs = append(attrs, attribute.String("vws.iam.store.result", res))
		span.SetAttributes(attrs[len(attrs)-1])
		if res == "unavailable" || res == "error" {
			span.RecordError(err)
			span.SetStatus(codes.Error, res)
		}
		span.End()
		t.duration.Record(ctx, time.Since(begin).Seconds(), metric.WithAttributes(attrs...))
	}
}

// outcome is the low-cardinality result label. Not found, exists and
// conflict are answers, not failures.
func outcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.Is(err, store.ErrExists):
		return "exists"
	case errors.Is(err, store.ErrConflict):
		return "conflict"
	case errors.Is(err, store.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	}
	return "error"
}
