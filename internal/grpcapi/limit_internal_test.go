package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestIPSubject covers the source IP normalization: v4-mapped v6 is the
// v4 address, IPv6 counts per /64, malformed input is still counted, and
// an empty field adds no subject.
func TestIPSubject(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:bbbb::9", "2001:db8:1:2::/64"},
		{"not-an-ip\n", "invalid/not-an-ip\n"},
	} {
		j, ok := ipSubject(c.in)
		if !ok || j.scope != iam.AttemptIP || j.id != c.want {
			t.Errorf("ipSubject(%q) = %+v %v, want %q", c.in, j, ok, c.want)
		}
	}
	if _, ok := ipSubject(""); ok {
		t.Error("empty source_ip added a subject")
	}
}

// downStore fails every attempt-counter call, as an unreachable API server.
type downStore struct{ store.Backend }

func (d downStore) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	if k == iam.KindAttempt {
		return store.Entry{}, store.ErrUnavailable
	}
	return d.Backend.Get(ctx, k, key)
}

func (d downStore) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	if k == iam.KindAttempt {
		return "", store.ErrUnavailable
	}
	return d.Backend.Create(ctx, k, key, spec)
}

// TestLimitFailsClosed refuses the attempt, without running the
// credential check, when the counters cannot be read or written.
func TestLimitFailsClosed(t *testing.T) {
	now := time.Now().UTC()
	s := New(downStore{memstore.New()}, nil, WithClock(func() time.Time { return now }))
	ran := false
	err := s.limitedVerify(t.Context(), callers{userSubject("acme", "alice")}, func() error { ran = true; return nil })
	if !errors.Is(err, store.ErrUnavailable) || ran {
		t.Fatalf("err %v, check ran %v; want ErrUnavailable and no check", err, ran)
	}
}
