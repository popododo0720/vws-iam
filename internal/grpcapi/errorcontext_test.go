package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func TestErrorContextKeepsWireMessages(t *testing.T) {
	causes := []error{
		context.Canceled, context.DeadlineExceeded, errors.New("backend detail"),
		invalidSpec("bad field"), accessDenied("denied"), status.Error(codes.Unavailable, "retry later"),
	}
	for _, m := range mapping {
		causes = append(causes, m.err)
	}
	for _, cause := range causes {
		t.Run(cause.Error(), func(t *testing.T) {
			wrapped := withErrorContext("reserve attempt counter",
				withErrorContext("read attempt counter", cause))
			if !errors.Is(wrapped, cause) ||
				!strings.Contains(wrapped.Error(), "reserve attempt counter: read attempt counter:") {
				t.Fatalf("context or cause lost: %v", wrapped)
			}
			before := status.Convert(toStatus(t.Context(), cause)).Proto()
			after := status.Convert(toStatus(t.Context(), wrapped)).Proto()
			if !proto.Equal(before, after) {
				t.Fatalf("wire changed: before %v, after %v", before, after)
			}
		})
	}
	if withErrorContext("nothing failed", nil) != nil {
		t.Fatal("nil error became a failure")
	}
}

type contextFaultStore struct {
	store.Backend
	op    string
	cause error
}

func (b contextFaultStore) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	if b.op == "get" {
		return store.Entry{}, b.cause
	}
	return b.Backend.Get(ctx, kind, key)
}

func (b contextFaultStore) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	if b.op == "create" {
		return "", b.cause
	}
	return b.Backend.Create(ctx, kind, key, spec)
}

func (b contextFaultStore) Delete(ctx context.Context, kind iam.Kind, key, version string) error {
	if b.op == "delete" {
		return b.cause
	}
	return b.Backend.Delete(ctx, kind, key, version)
}

func (b contextFaultStore) List(ctx context.Context, kind iam.Kind) ([]store.Entry, error) {
	if b.op == "list" {
		return nil, b.cause
	}
	return b.Backend.List(ctx, kind)
}

func TestLimiterErrorsNameTheStep(t *testing.T) {
	cause := errors.New("backend detail")
	cs := callers{userSubject("acme", "alice")}
	for _, tc := range []struct {
		name, op, want string
		run            func(*Server) error
	}{
		{"check", "get", "read attempt counter", func(s *Server) error { return s.checkAttempts(t.Context(), cs) }},
		{"reserve", "create", "create attempt counter", func(s *Server) error {
			_, err := s.reserveAttempts(t.Context(), cs)
			return err
		}},
		{"mutate", "get", "mutate attempt counter", func(s *Server) error {
			_, err := s.bump(t.Context(), counter{scope: iam.AttemptUser, key: "counter"}, -1)
			return err
		}},
		{"release", "get", "release attempt counter", func(s *Server) error {
			return s.releaseAttempts(t.Context(), []counter{{scope: iam.AttemptUser, key: "counter"}})
		}},
		{"verify", "", "verify credentials", func(s *Server) error {
			return s.limitedVerify(t.Context(), cs, func() error { return cause })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(contextFaultStore{Backend: memstore.New(), op: tc.op, cause: cause}, testRing(t, "a", "a"))
			err := tc.run(s)
			if !errors.Is(err, cause) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q and original cause", err, tc.want)
			}
		})
	}
}

func TestGarbageCollectionErrorsNameTheStep(t *testing.T) {
	cause := errors.New("backend detail")
	for _, op := range []string{"list", "delete"} {
		t.Run(op, func(t *testing.T) {
			b := memstore.New()
			entry := iam.ReplayEntry{Hash: strings.Repeat("a", 64), Expires: time.Unix(1, 0)}
			if _, err := store.Create(t.Context(), b, entry); err != nil {
				t.Fatal(err)
			}
			s := New(contextFaultStore{Backend: b, op: op, cause: cause}, testRing(t, "a", "a"))
			n, err := s.GCReplayEntries(t.Context())
			if n != 0 || !errors.Is(err, cause) || !strings.Contains(err.Error(), op+" garbage collection") {
				t.Fatalf("got %d, %v", n, err)
			}
		})
	}
}
