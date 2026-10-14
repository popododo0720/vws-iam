// Package grpcapi is the gRPC edge of vws-iam: vws.iam.v1 (users, groups,
// roles, policies, access keys, MFA devices, auth, STS) and
// google.longrunning.Operations. Wire types stay in this package.
package grpcapi

import (
	"context"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// ServiceName is the observability service name.
const ServiceName = "vws-iam"

// Defaults.
const (
	DefaultTimeout    = 10 * time.Second
	MaxTimeout        = 30 * time.Second
	ConsoleSessionTTL = 12 * time.Hour
	maxRecvBytes      = 1 << 20
)

// Server serves every vws.iam.v1 service from one backend.
type Server struct {
	iamv1.UnsafeUserServiceServer
	iamv1.UnsafeGroupServiceServer
	iamv1.UnsafeRoleServiceServer
	iamv1.UnsafePolicyServiceServer
	iamv1.UnsafeAccessKeyServiceServer
	iamv1.UnsafeMfaDeviceServiceServer
	iamv1.UnsafeAuthServiceServer
	iamv1.UnsafeTokenServiceServer
	longrunningpb.UnimplementedOperationsServer

	b    store.Backend
	keys *secret.Keyring
	now  func() time.Time
	m    *metrics
	// marked throttles MarkUsed writes: access key id -> last write time.
	marked sync.Map
	// stsSeen is a per-replica fast front of the shared replay store
	// (replay.go): replay hash -> time after which it can be forgotten.
	// It only ever rejects, so it is safe to be stale or empty.
	stsSeen sync.Map
}

// Option configures a Server.
type Option func(*Server)

// WithClock replaces time.Now (tests).
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// New returns a Server. b is the unscoped backend; keys seals secrets.
func New(b store.Backend, keys *secret.Keyring, opts ...Option) *Server {
	s := &Server{b: b, keys: keys, now: time.Now, m: newMetrics()}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Register serves every service on g.
func Register(g *grpc.Server, s *Server) {
	iamv1.RegisterUserServiceServer(g, s)
	iamv1.RegisterGroupServiceServer(g, s)
	iamv1.RegisterRoleServiceServer(g, s)
	iamv1.RegisterPolicyServiceServer(g, s)
	iamv1.RegisterAccessKeyServiceServer(g, s)
	iamv1.RegisterMfaDeviceServiceServer(g, s)
	iamv1.RegisterAuthServiceServer(g, s)
	iamv1.RegisterTokenServiceServer(g, s)
	longrunningpb.RegisterOperationsServer(g, s)
}

// project is one project's view of every domain service.
type project struct {
	id    string
	b     store.Backend
	authz *authz.Authorizer
	keys  *accesskey.Service
	mfa   *mfa.Service
	sts   *sts.Service
}

func (s *Server) project(id string) project {
	b := store.Scoped(s.b, id)
	az := authz.New(b, id, s.now)
	m := mfa.New(b, s.keys, id, s.now)
	return project{
		id:    id,
		b:     b,
		authz: az,
		keys:  accesskey.New(b, s.b, id, s.keys, s.now),
		mfa:   m,
		sts:   sts.New(b, s.keys, az, id, s.now, sts.WithMFA(mfaVerifier{m})),
	}
}

// ServerOptions are the vws-lib grpcobs interceptors (OTel traces, metrics,
// logs, panic recovery) plus the deadline and audit interceptors, and
// message size and keepalive limits.
func ServerOptions(extra ...grpc.ServerOption) []grpc.ServerOption {
	opts := obsOptions()
	opts = append(opts,
		grpc.ChainUnaryInterceptor(deadlineUnary, auditUnary),
		grpc.MaxRecvMsgSize(maxRecvBytes),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 5 * time.Minute, Time: time.Minute, Timeout: 20 * time.Second}),
	)
	return append(opts, extra...)
}

// deadlineUnary gives every call a deadline: DefaultTimeout when the
// client sent none, and never more than MaxTimeout.
func deadlineUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
	limit := DefaultTimeout
	if d, ok := ctx.Deadline(); ok {
		limit = min(time.Until(d), MaxTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	return next(ctx, req)
}

// ClientServiceConfig is the gRPC service config callers (console-api)
// should dial with: per-call timeouts, and retries of UNAVAILABLE for every
// method. Mutations carry request_id, so a retry is idempotent; the secret
// RPCs (CreateAccessKey, CreateVirtualMfaDevice) are excluded.
const ClientServiceConfig = `{
  "methodConfig": [
    {
      "name": [
        {"service": "vws.iam.v1.AuthService"},
        {"service": "vws.iam.v1.TokenService"},
        {"service": "vws.iam.v1.UserService"},
        {"service": "vws.iam.v1.GroupService"},
        {"service": "vws.iam.v1.RoleService"},
        {"service": "vws.iam.v1.PolicyService"},
        {"service": "vws.iam.v1.MfaDeviceService", "method": "GetMfaDevice"},
        {"service": "vws.iam.v1.MfaDeviceService", "method": "ListMfaDevices"},
        {"service": "vws.iam.v1.AccessKeyService", "method": "GetAccessKey"},
        {"service": "vws.iam.v1.AccessKeyService", "method": "ListAccessKeys"},
        {"service": "google.longrunning.Operations"}
      ],
      "timeout": "5s",
      "retryPolicy": {
        "maxAttempts": 4,
        "initialBackoff": "0.05s",
        "maxBackoff": "1s",
        "backoffMultiplier": 2,
        "retryableStatusCodes": ["UNAVAILABLE"]
      }
    },
    {
      "name": [
        {"service": "vws.iam.v1.AccessKeyService", "method": "CreateAccessKey"},
        {"service": "vws.iam.v1.MfaDeviceService", "method": "CreateVirtualMfaDevice"}
      ],
      "timeout": "10s"
    }
  ]
}`

// mfaVerifier lets STS verify SerialNumber + TokenCode against this
// project's devices, with the replay guard and lockout of internal/mfa.
type mfaVerifier struct{ m *mfa.Service }

func (v mfaVerifier) VerifyMFA(ctx context.Context, user, serial, code string) error {
	prefix := v.m.Serial("")
	if !strings.HasPrefix(serial, prefix) {
		return mfa.ErrNotAssociated
	}
	return v.m.Verify(ctx, user, strings.TrimPrefix(serial, prefix), code)
}
