package grpcapi_test

import (
	"context"
	"net"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
)

// traceProbe records the span context its handler runs under.
type traceProbe struct {
	iamv1.UnimplementedAccessKeyServiceServer

	mu  sync.Mutex
	got trace.SpanContext
}

func (p *traceProbe) ListAccessKeys(
	ctx context.Context, _ *iamv1.ListAccessKeysRequest,
) (*iamv1.ListAccessKeysResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.got = trace.SpanContextFromContext(ctx)
	return &iamv1.ListAccessKeysResponse{}, nil
}

func (p *traceProbe) last() trace.SpanContext {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.got
}

// TestTraceContextPropagatesOverGRPC: with the W3C propagator obs.Setup
// installs, a call served through the production ServerOptions continues
// the caller's trace (#27): the handler runs in a server span whose parent
// is the span named by the incoming traceparent, so the sts, authz, mfa and
// accesskey spans it opens join the caller's trace. A call without one, or
// with a malformed one, starts a new trace and is still served.
func TestTraceContextPropagatesOverGRPC(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	p := &traceProbe{}
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer(grpcapi.ServerOptions()...)
	iamv1.RegisterAccessKeyServiceServer(srv, p)
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cc.Close(); err != nil {
			t.Error(err)
		}
	})
	client := iamv1.NewAccessKeyServiceClient(cc)
	call := func(traceparent string) trace.SpanContext {
		t.Helper()
		ctx := t.Context()
		if traceparent != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "traceparent", traceparent)
		}
		if _, err := client.ListAccessKeys(ctx, &iamv1.ListAccessKeysRequest{}); err != nil {
			t.Fatalf("traceparent %q: %v", traceparent, err)
		}
		return p.last()
	}

	const traceID, parentID = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
	got := call("00-" + traceID + "-" + parentID + "-01")
	if got.TraceID().String() != traceID {
		t.Fatalf("handler trace %s, want the caller's %s", got.TraceID(), traceID)
	}
	if got.SpanID().String() == parentID {
		t.Fatal("handler runs in the caller's span, not a server span")
	}
	var server sdktrace.ReadOnlySpan
	for _, s := range spans.Ended() {
		if s.SpanContext().SpanID() == got.SpanID() {
			server = s
		}
	}
	if server == nil || server.SpanKind() != trace.SpanKindServer ||
		server.Parent().SpanID().String() != parentID || !server.Parent().IsRemote() {
		t.Fatalf("server span %v, want a server span whose remote parent is %s", server, parentID)
	}

	for _, tp := range []string{"", "00-zz-" + parentID + "-01", "00-" + traceID + "-0000000000000000-01"} {
		got := call(tp)
		if !got.IsValid() || got.TraceID().String() == traceID {
			t.Errorf("traceparent %q: handler span %v, want a new valid trace", tp, got)
		}
	}
}
