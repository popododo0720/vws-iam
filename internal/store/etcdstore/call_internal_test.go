package etcdstore

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// TestTranslate names every way an etcd call can fail: a backend that
// cannot be reached is ErrUnavailable and keeps its cause, a permanent
// answer and the caller's own cancellation are not.
func TestTranslate(t *testing.T) {
	refusedStatus := status.Error(codes.Unavailable,
		`connection error: desc = "transport: Error while dialing: dial tcp 127.0.0.1:2379: connect: connection refused"`)
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name        string
		ctx         context.Context //nolint:containedctx // table input
		err         error
		unavailable bool
	}{
		{"connection refused", context.Background(), refused, true},
		{"connection refused in a status", context.Background(), refusedStatus, true},
		{"unavailable status", context.Background(), status.Error(codes.Unavailable, "etcdserver: request timed out"), true},
		{"no leader", context.Background(), rpctypes.ErrGRPCNoLeader, true},
		{"call timeout", context.Background(), context.DeadlineExceeded, true},
		{"deadline status", context.Background(), status.Error(codes.DeadlineExceeded, "context deadline exceeded"), true},
		{"permission denied", context.Background(), rpctypes.ErrGRPCPermissionDenied, false},
		{"request too large", context.Background(), rpctypes.ErrGRPCRequestTooLarge, false},
		{"caller canceled", canceled, status.Error(codes.Canceled, "context canceled"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := translate(tc.ctx, "get", iam.KindUser, tc.err)
			if got := errors.Is(err, store.ErrUnavailable); got != tc.unavailable {
				t.Fatalf("translate(%v) = %v, ErrUnavailable %t, want %t", tc.err, err, got, tc.unavailable)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("translate(%v) = %v, lost its cause", tc.err, err)
			}
			if want := "etcd get " + string(iam.KindUser); !strings.Contains(err.Error(), want) {
				t.Fatalf("translate(%v) = %v, does not name %q", tc.err, err, want)
			}
		})
	}
}
