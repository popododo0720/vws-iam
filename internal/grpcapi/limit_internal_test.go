package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// testRing is a keyring of the KEKs ids, each with a fixed key, so rings
// built apart share a KEK by id.
func testRing(t *testing.T, active string, ids ...string) *secret.Keyring {
	t.Helper()
	keys := map[string][]byte{}
	for _, id := range ids {
		keys[id] = bytes.Repeat([]byte(id[:1]), 32)
	}
	k, err := secret.NewKeyring(active, keys)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

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
	s := New(downStore{memstore.New()}, testRing(t, "a", "a"), WithClock(func() time.Time { return now }))
	ran := false
	err := s.limitedVerify(t.Context(), callers{userSubject("acme", "alice")}, func() error { ran = true; return nil })
	if !errors.Is(err, store.ErrUnavailable) || ran {
		t.Fatalf("err %v, check ran %v; want ErrUnavailable and no check", err, ran)
	}
}

var errWrong = errors.New("wrong password")

// TestAttemptCountersAreKeyed covers #41: a counter key is a digest under
// each KEK, never the plain SHA-256 a store reader could brute-force; a
// lock holds after a restart and across a KEK rotation either way; a
// success releases the counter under every KEK.
func TestAttemptCountersAreKeyed(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	clock := WithClock(func() time.Time { return now })
	b := memstore.New()
	cs := callers{userSubject("acme", "alice")}
	s := New(b, testRing(t, "a", "a"), clock)
	for range UserAttemptLimit {
		if err := s.limitedVerify(ctx, cs, func() error { return errWrong }); !errors.Is(err, errWrong) {
			t.Fatalf("attempt under the limit: %v", err)
		}
	}
	vs, err := store.List[iam.AttemptCounter](ctx, b)
	if err != nil || len(vs) != 1 {
		t.Fatalf("counters %d %v, want 1", len(vs), err)
	}
	if k := vs[0].Object.Hash; k == legacySubjectHash(cs[0]) || k != s.counters(cs)[0].key {
		t.Fatalf("counter key %q is not the keyed digest", k)
	}
	for name, r := range map[string]*Server{
		"restart":           New(b, testRing(t, "a", "a"), clock),
		"ring {a,b}":        New(b, testRing(t, "a", "a", "b"), clock),
		"ring {a,b} b live": New(b, testRing(t, "b", "a", "b"), clock),
	} {
		ran := false
		err := r.limitedVerify(ctx, cs, func() error { ran = true; return nil })
		if !throttledBy(err, iam.AttemptUser) || ran {
			t.Errorf("%s: err %v, check ran %v; want Throttling before the check", name, err, ran)
		}
	}

	bob := callers{userSubject("acme", "bob")}
	ab := New(b, testRing(t, "b", "a", "b"), clock)
	if err := ab.limitedVerify(ctx, bob, func() error { return errWrong }); !errors.Is(err, errWrong) {
		t.Fatal(err)
	}
	if err := ab.limitedVerify(ctx, bob, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, c := range ab.counters(bob) {
		v, err := store.Get[iam.AttemptCounter](ctx, b, c.key)
		if err != nil || v.Object.Failures != 1 {
			t.Fatalf("bob under one KEK: %+v %v, want 1 failure after a failure and a success", v.Object, err)
		}
	}
}

// TestLegacyAttemptCounterLocks keeps a lock written by a release before
// #41 under the plain SHA-256 key, without writing that counter.
func TestLegacyAttemptCounterLocks(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC()
	b := memstore.New()
	cs := callers{userSubject("acme", "alice")}
	legacy := iam.AttemptCounter{
		Hash: legacySubjectHash(cs[0]), Scope: iam.AttemptUser, Failures: UserAttemptLimit, WindowStart: now,
	}
	if _, err := store.Create(ctx, b, legacy); err != nil {
		t.Fatal(err)
	}
	s := New(b, testRing(t, "a", "a"), WithClock(func() time.Time { return now }))
	ran := false
	err := s.limitedVerify(ctx, cs, func() error { ran = true; return nil })
	if !throttledBy(err, iam.AttemptUser) || ran {
		t.Fatalf("err %v, check ran %v; want Throttling before the check", err, ran)
	}
	vs, err := store.List[iam.AttemptCounter](ctx, b)
	if err != nil || len(vs) != 1 || vs[0].Object.Hash != legacy.Hash || vs[0].Object.Failures != legacy.Failures {
		t.Fatalf("counters %+v %v, want only the legacy one, unchanged", vs, err)
	}
}
