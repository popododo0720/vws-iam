// Package grpcapi is the gRPC edge of vws-iam: vws.iam.v1 (users, groups,
// roles, policies, access keys, MFA devices, auth, STS) and
// google.longrunning.Operations. Wire types stay in this package.
package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
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
	// gcPage is the GC list page size (gcPageSize; tests lower it).
	gcPage int
	// saml and samlSP serve AssumeRoleWithSAML (WithSAML).
	saml   sts.SAMLProviders
	samlSP sts.SAMLServiceProvider
}

// Option configures a Server.
type Option func(*Server)

// WithClock replaces time.Now (tests).
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// WithSAML sets the SAML providers and the service provider audience and
// sign-in URL of AssumeRoleWithSAML. Without it (there is no SAML
// provider store yet, #196) every AssumeRoleWithSAML call is
// InvalidIdentityToken.
func WithSAML(p sts.SAMLProviders, sp sts.SAMLServiceProvider) Option {
	return func(s *Server) { s.saml, s.samlSP = p, sp }
}

// New returns a Server. b is the unscoped backend; keys seals secrets.
func New(b store.Backend, keys *secret.Keyring, opts ...Option) *Server {
	s := &Server{b: b, keys: keys, now: time.Now, m: newMetrics(), gcPage: gcPageSize}
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

// stsOptions are the sts.Service options of project id.
func (s *Server) stsOptions(m *mfa.Service, id string) []sts.Option {
	opts := []sts.Option{sts.WithMFA(mfaVerifier{m: m, s: s, project: id}), sts.WithKeyIndex(s.b)}
	if s.saml != nil {
		opts = append(opts, sts.WithSAML(s.saml, s.samlSP))
	}
	return opts
}

// project is one project's view of every domain service.
type project struct {
	id    string
	now   func() time.Time
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
		now:   s.now,
		b:     b,
		authz: az,
		keys:  accesskey.New(b, s.b, id, s.keys, s.now),
		mfa:   m,
		sts:   sts.New(b, s.keys, az, id, s.now, s.stsOptions(m, id)...),
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
// project's devices, with the replay guard and lockout of internal/mfa,
// and counts the attempt for the user and for the access key and source
// IP the STS call carried (limit.go).
type mfaVerifier struct {
	m       *mfa.Service
	s       *Server
	project string
}

func (v mfaVerifier) VerifyMFA(ctx context.Context, user, serial, code string) error {
	cs := callers{userSubject(v.project, user)}
	if extra, ok := ctx.Value(attemptsKey{}).(callers); ok {
		cs = append(cs, extra...)
	}
	err := v.s.limitedVerify(ctx, cs, func() error {
		return v.m.VerifySerial(ctx, user, serial, code)
	})
	if !errors.Is(err, errThrottled) {
		return err
	}
	// A throttle by the user's own limit renews a running device lock
	// (#44): it then lasts LockoutDuration from this attempt, never past
	// mfa.MaxLockout from the failure that locked it, and a throttle never
	// starts a lock: it checks no code (#48). A throttle by the source IP
	// or access key alone leaves the device untouched: those are shared
	// with or held by other callers. The answer stays Throttling.
	if throttledBy(err, iam.AttemptUser) {
		if _, lerr := v.m.RenewLockSerial(context.WithoutCancel(ctx), user, serial); lerr != nil {
			slog.Default().LogAttrs(ctx, slog.LevelWarn, "mfa lock renewal on throttle failed", slog.String("error", lerr.Error()))
		}
	}
	return fmt.Errorf("%w: %w", sts.ErrThrottling, err)
}
