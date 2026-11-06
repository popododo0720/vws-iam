package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// conflicting serves one group and answers the first conflicts Updates
// with ErrConflict (all of them when conflicts < 0), then updateErr.
type conflicting struct {
	Backend   // nil: only Get and Update are called
	t         *testing.T
	conflicts int
	updateErr error
	onUpdate  func()
	updates   int
}

func (c *conflicting) Get(_ context.Context, _ iam.Kind, key string) (Entry, error) {
	spec, err := json.Marshal(iam.Group{Name: key, ID: "1"})
	if err != nil {
		c.t.Fatal(err)
	}
	return Entry{Key: key, Spec: spec, Version: "1"}, nil
}

func (c *conflicting) Update(context.Context, iam.Kind, string, []byte, string) (string, error) {
	c.updates++
	if c.onUpdate != nil {
		c.onUpdate()
	}
	if c.conflicts < 0 || c.updates <= c.conflicts {
		return "", ErrConflict
	}
	return "2", c.updateErr
}

// recordSleeps replaces sleep for the test with one that records each
// delay and returns at once.
func recordSleeps(t *testing.T) *[]time.Duration {
	t.Helper()
	var waits []time.Duration
	orig := sleep
	sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	}
	t.Cleanup(func() { sleep = orig })
	return &waits
}

// TestMutateBacksOffBetweenConflicts: Mutate waits between version
// conflict retries, a jittered delay in [d/2, d] with d doubling from 5 ms
// to at most 200 ms, makes 1+8 attempts in all, and never waits after a
// success or another error (#27).
func TestMutateBacksOffBetweenConflicts(t *testing.T) {
	ctx := context.Background()
	inc := func(g *iam.Group) error { g.Generation++; return nil }

	waits := recordSleeps(t)
	b := &conflicting{t: t, conflicts: -1}
	if _, err := Mutate(ctx, b, "g", inc); !errors.Is(err, ErrConflict) {
		t.Fatalf("always conflicting: %v", err)
	}
	if b.updates != 1+mutateRetries || len(*waits) != mutateRetries {
		t.Fatalf("%d updates, %d waits; want %d and %d", b.updates, len(*waits), 1+mutateRetries, mutateRetries)
	}
	caps := []time.Duration{5, 10, 20, 40, 80, 160, 200, 200}
	for i, w := range *waits {
		d := caps[i] * time.Millisecond
		if w < d/2 || w > d {
			t.Errorf("wait %d = %v, want in [%v, %v]", i, w, d/2, d)
		}
	}

	*waits = nil
	b = &conflicting{t: t, conflicts: 2}
	g, err := Mutate(ctx, b, "g", inc)
	if err != nil || g.Generation != 1 || b.updates != 3 || len(*waits) != 2 {
		t.Fatalf("two conflicts then success: %v gen=%d updates=%d waits=%d", err, g.Generation, b.updates, len(*waits))
	}

	*waits = nil
	b = &conflicting{t: t, updateErr: ErrUnavailable}
	if _, err := Mutate(ctx, b, "g", inc); !errors.Is(err, ErrUnavailable) || b.updates != 1 || len(*waits) != 0 {
		t.Fatalf("other error: %v updates=%d waits=%d", err, b.updates, len(*waits))
	}
}

// TestMutateBackoffIsJittered: racing writers do not all wait the same
// delay, and every delay stays inside its bound, also far past the cap.
func TestMutateBackoffIsJittered(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 200 {
		seen[conflictDelay(0)] = true
		if d := conflictDelay(1000); d < mutateMaxBackoff/2 || d > mutateMaxBackoff {
			t.Fatalf("delay of retry 1000 = %v", d)
		}
	}
	if len(seen) < 10 {
		t.Fatalf("%d distinct delays out of 200, want jitter", len(seen))
	}
}

// TestMutateStopsWaitingWhenContextEnds: a context canceled during the
// backoff ends Mutate at once with both the conflict and the cancellation,
// and no further write.
func TestMutateStopsWaitingWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &conflicting{t: t, conflicts: -1, onUpdate: cancel}
	begin := time.Now()
	_, err := Mutate(ctx, b, "g", func(*iam.Group) error { return nil })
	if !errors.Is(err, ErrConflict) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the conflict and context.Canceled", err)
	}
	if b.updates != 1 || time.Since(begin) > time.Second {
		t.Fatalf("%d updates in %v after cancel", b.updates, time.Since(begin))
	}
}

// TestMutateReportsTheConflictWhenARetryRunsOutOfTime: a context that
// ends while a retry reads ends Mutate with the conflict and the context's
// error, so the caller sees contention, not a slow backend (#51). A first
// read cut short is only the context's error.
func TestMutateReportsTheConflictWhenARetryRunsOutOfTime(t *testing.T) {
	recordSleeps(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &ctxReads{conflicting: conflicting{t: t, conflicts: -1, onUpdate: cancel}}
	_, err := Mutate(ctx, b, "g", func(*iam.Group) error { return nil })
	if !errors.Is(err, ErrConflict) || !errors.Is(err, context.Canceled) || b.updates != 1 {
		t.Fatalf("err = %v after %d updates, want the conflict and context.Canceled after 1", err, b.updates)
	}

	b = &ctxReads{conflicting: conflicting{t: t, conflicts: -1}}
	_, err = Mutate(ctx, b, "g", func(*iam.Group) error { return nil })
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrConflict) || b.updates != 0 {
		t.Fatalf("first read on a done context: %v after %d updates", err, b.updates)
	}
}

// ctxReads fails a Get once ctx is done, as a real backend does.
type ctxReads struct{ conflicting }

func (c *ctxReads) Get(ctx context.Context, k iam.Kind, key string) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	return c.conflicting.Get(ctx, k, key)
}
