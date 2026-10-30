package grpcapi

import (
	"context"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-lib/obs/grpcobs"
)

func obsOptions() []grpc.ServerOption { return grpcobs.ServerOptions(ServiceName) }

// metrics are the IAM-specific OTel instruments; RPC counts and latency
// come from grpcobs.
type metrics struct {
	authn   metric.Int64Counter
	authz   metric.Int64Counter
	login   metric.Int64Counter
	issued  metric.Int64Counter
	decoded metric.Int64Counter
}

func newMetrics() *metrics {
	m := otel.Meter("github.com/popododo0720/vws-iam/internal/grpcapi")
	c := func(name, desc string) metric.Int64Counter {
		ctr, err := m.Int64Counter(name, metric.WithDescription(desc))
		if err != nil {
			return noop.Int64Counter{} // a bad instrument must not stop serving
		}
		return ctr
	}
	return &metrics{
		authn:   c("vws.iam.authenticate", "Authenticate results by key kind and result"),
		authz:   c("vws.iam.authorize", "Authorize decisions"),
		login:   c("vws.iam.login", "Login results"),
		issued:  c("vws.iam.sts.issued", "Temporary credentials issued"),
		decoded: c("vws.iam.sts.decode_authorization_message", "DecodeAuthorizationMessage results"),
	}
}

func (m *metrics) add(ctx context.Context, c metric.Int64Counter, kv ...attribute.KeyValue) {
	if c != nil {
		c.Add(ctx, 1, metric.WithAttributes(kv...))
	}
	trace.SpanFromContext(ctx).SetAttributes(kv...)
}

// result is the low-cardinality outcome label of an error.
func result(err error) string {
	if err == nil {
		return "ok"
	}
	return strings.ToLower(status.Code(err).String())
}

var mutating = []string{"Create", "Update", "Delete", "Set", "Change", "Enable", "Deactivate", "Login", "Logout", "Assume", "GetSessionToken"}

func isMutating(method string) bool {
	for _, p := range mutating {
		if strings.HasPrefix(method, p) {
			return true
		}
	}
	return false
}

// auditUnary logs every mutating or credential RPC: method and outcome
// only. Request and response bodies (passwords, secrets, codes, tokens)
// are never logged.
func auditUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	method := info.FullMethod[strings.LastIndex(info.FullMethod, "/")+1:]
	resp, err := next(ctx, req)
	if isMutating(method) || method == "Authenticate" || method == "DecodeAuthorizationMessage" {
		level := slog.LevelInfo
		if err != nil {
			level = slog.LevelWarn
		}
		slog.Default().LogAttrs(ctx, level, "audit", slog.String("method", method), slog.String("result", result(err)))
	}
	return resp, err
}
