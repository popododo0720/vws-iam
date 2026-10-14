// Package grpcapi is the gRPC edge of vws-iam. Until vws-proto#24 publishes
// vws/iam/v1 it serves only grpc.health.v1, with the vws-lib interceptors.
package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/popododo0720/vws-lib/obs/grpcobs"
)

// ServiceName is the observability service name.
const ServiceName = "vws-iam"

// ServerOptions are the only server interceptors: vws-lib grpcobs.
func ServerOptions() []grpc.ServerOption { return grpcobs.ServerOptions(ServiceName) }

// Health reports SERVING while ready succeeds.
type Health struct {
	srv   *health.Server
	ready func(context.Context) error
}

// RegisterHealth registers grpc.health.v1 on s, NOT_SERVING until checked.
func RegisterHealth(s *grpc.Server, ready func(context.Context) error) *Health {
	h := &Health{srv: health.NewServer(), ready: ready}
	h.srv.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	healthpb.RegisterHealthServer(s, h.srv)
	return h
}

// Check sets the status from one readiness probe.
func (h *Health) Check(ctx context.Context) {
	st := healthpb.HealthCheckResponse_SERVING
	if h.ready(ctx) != nil {
		st = healthpb.HealthCheckResponse_NOT_SERVING
	}
	h.srv.SetServingStatus("", st)
}

// Run checks now and every interval until ctx is done.
func (h *Health) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		h.Check(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Shutdown reports NOT_SERVING for good.
func (h *Health) Shutdown() { h.srv.Shutdown() }
