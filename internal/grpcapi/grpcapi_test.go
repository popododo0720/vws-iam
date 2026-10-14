package grpcapi_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
)

func TestHealthFollowsReadiness(t *testing.T) {
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := errors.New("store down")
	srv := grpc.NewServer(grpcapi.ServerOptions()...)
	h := grpcapi.RegisterHealth(srv, func(context.Context) error { return ready })
	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	defer func() {
		srv.Stop()
		if err := <-served; err != nil {
			t.Error(err)
		}
	}()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	c := healthpb.NewHealthClient(conn)
	ctx := context.Background()
	check := func() healthpb.HealthCheckResponse_ServingStatus {
		r, err := c.Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetStatus()
	}
	h.Check(ctx)
	if s := check(); s != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("not ready: %v", s)
	}
	ready = nil
	h.Check(ctx)
	if s := check(); s != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("ready: %v", s)
	}
}
