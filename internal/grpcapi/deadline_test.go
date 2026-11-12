package grpcapi_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
)

// probe answers every call with UNAVAILABLE after recording, per method,
// how often it was called and the deadline the handler saw.
type probe struct {
	longrunningpb.UnimplementedOperationsServer
	iamv1.UnimplementedAccessKeyServiceServer
	iamv1.UnimplementedMfaDeviceServiceServer
	iamv1.UnimplementedKeyPairServiceServer

	mu       sync.Mutex
	calls    map[string]int
	deadline time.Duration
	hasLimit bool
}

func (p *probe) hit(ctx context.Context, method string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[method]++
	d, ok := ctx.Deadline()
	p.deadline, p.hasLimit = time.Until(d), ok
	return status.Error(codes.Unavailable, "probe")
}

func (p *probe) GetOperation(
	ctx context.Context, _ *longrunningpb.GetOperationRequest,
) (*longrunningpb.Operation, error) {
	return nil, p.hit(ctx, "GetOperation")
}

func (p *probe) ListAccessKeys(
	ctx context.Context, _ *iamv1.ListAccessKeysRequest,
) (*iamv1.ListAccessKeysResponse, error) {
	return nil, p.hit(ctx, "ListAccessKeys")
}

func (p *probe) CreateAccessKey(
	ctx context.Context, _ *iamv1.CreateAccessKeyRequest,
) (*iamv1.CreateAccessKeyResponse, error) {
	return nil, p.hit(ctx, "CreateAccessKey")
}

func (p *probe) CreateVirtualMfaDevice(
	ctx context.Context, _ *iamv1.CreateVirtualMfaDeviceRequest,
) (*iamv1.CreateVirtualMfaDeviceResponse, error) {
	return nil, p.hit(ctx, "CreateVirtualMfaDevice")
}

func (p *probe) CreateKeyPair(
	ctx context.Context, _ *iamv1.CreateKeyPairRequest,
) (*iamv1.CreateKeyPairResponse, error) {
	return nil, p.hit(ctx, "CreateKeyPair")
}

func (p *probe) count(method string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[method]
}

// serveProbe serves p with the production ServerOptions and dials it with
// the service config cfg.
func serveProbe(t *testing.T, p *probe, cfg string) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer(grpcapi.ServerOptions()...)
	longrunningpb.RegisterOperationsServer(srv, p)
	iamv1.RegisterAccessKeyServiceServer(srv, p)
	iamv1.RegisterMfaDeviceServiceServer(srv, p)
	iamv1.RegisterKeyPairServiceServer(srv, p)
	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Error(err)
		}
	}()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cc.Close(); err != nil {
			t.Error(err)
		}
	})
	return cc
}

// TestServerDeadline: through the production ServerOptions a handler
// always runs under a deadline: DefaultTimeout (10s) when the client sent
// none, the client's own when shorter, and never more than MaxTimeout
// (30s), however long the client asks for (#19).
func TestServerDeadline(t *testing.T) {
	if grpcapi.DefaultTimeout != 10*time.Second || grpcapi.MaxTimeout != 30*time.Second {
		t.Fatalf("DefaultTimeout=%v MaxTimeout=%v, want 10s and 30s", grpcapi.DefaultTimeout, grpcapi.MaxTimeout)
	}
	p := &probe{calls: map[string]int{}}
	// No client service config: each case is one call whose deadline is
	// exactly what the client set.
	cc := serveProbe(t, p, `{}`)
	for _, c := range []struct {
		name   string
		client time.Duration // 0: no client deadline
		want   time.Duration
	}{
		{"none", 0, grpcapi.DefaultTimeout},
		{"shorter", 3 * time.Second, 3 * time.Second},
		{"between", 20 * time.Second, 20 * time.Second},
		{"longer", time.Hour, grpcapi.MaxTimeout},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			if c.client > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, c.client)
				defer cancel()
			}
			_, err := iamv1.NewAccessKeyServiceClient(cc).CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{})
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("err = %v, want the probe's UNAVAILABLE", err)
			}
			p.mu.Lock()
			got, ok := p.deadline, p.hasLimit
			p.mu.Unlock()
			if !ok || got > c.want || got < c.want-2*time.Second {
				t.Fatalf("handler deadline = %v (set %v), want about %v", got, ok, c.want)
			}
		})
	}
}

// TestClientServiceConfigRetryPolicy: a client dialed with the published
// ClientServiceConfig makes exactly 4 attempts of an idempotent call that
// keeps answering UNAVAILABLE, and exactly one of a secret creation
// (CreateAccessKey, CreateVirtualMfaDevice, CreateKeyPair), whose lost response cannot be
// replayed without the secret (#19).
func TestClientServiceConfigRetryPolicy(t *testing.T) {
	p := &probe{calls: map[string]int{}}
	cc := serveProbe(t, p, grpcapi.ClientServiceConfig)
	ops := longrunningpb.NewOperationsClient(cc)
	keys := iamv1.NewAccessKeyServiceClient(cc)
	mfa := iamv1.NewMfaDeviceServiceClient(cc)
	pairs := iamv1.NewKeyPairServiceClient(cc)
	for _, c := range []struct {
		method string
		call   func(context.Context) error
		want   int
	}{
		{"GetOperation", func(ctx context.Context) error {
			_, err := ops.GetOperation(ctx, &longrunningpb.GetOperationRequest{Name: "x"})
			return err
		}, 4},
		{"ListAccessKeys", func(ctx context.Context) error {
			_, err := keys.ListAccessKeys(ctx, &iamv1.ListAccessKeysRequest{})
			return err
		}, 4},
		{"CreateAccessKey", func(ctx context.Context) error {
			_, err := keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{})
			return err
		}, 1},
		{"CreateVirtualMfaDevice", func(ctx context.Context) error {
			_, err := mfa.CreateVirtualMfaDevice(ctx, &iamv1.CreateVirtualMfaDeviceRequest{})
			return err
		}, 1},
		{"CreateKeyPair", func(ctx context.Context) error {
			_, err := pairs.CreateKeyPair(ctx, &iamv1.CreateKeyPairRequest{})
			return err
		}, 1},
	} {
		t.Run(c.method, func(t *testing.T) {
			if err := c.call(t.Context()); status.Code(err) != codes.Unavailable {
				t.Fatalf("err = %v, want UNAVAILABLE after the retries", err)
			}
			if got := p.count(c.method); got != c.want {
				t.Fatalf("%s attempts = %d, want %d", c.method, got, c.want)
			}
		})
	}
}
