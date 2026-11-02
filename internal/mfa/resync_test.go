package mfa_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
)

// enrollSerial is enroll that also returns the device's serial number.
func enrollSerial(t *testing.T, svc *mfa.Service, clk *clock, user, name string) ([]byte, string) {
	t.Helper()
	seed := enroll(t, svc, clk, user, name)
	return seed, "arn:vws:iam::" + acct + ":mfa/" + name
}

func device(t *testing.T, b store.Backend, name string) iam.MfaDevice {
	t.Helper()
	d, err := store.Get[iam.MfaDevice](context.Background(), b, name)
	if err != nil {
		t.Fatal(err)
	}
	return d.Object
}

// TestResync: a device whose clock runs 8 minutes ahead fails Verify
// until Resync finds two consecutive codes and stores the drift; then
// its codes verify, also after later steps, and a code is never accepted
// twice (the pair's steps are consumed).
func TestResync(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	seed, serial := enrollSerial(t, svc, clk, "alice", "alice-phone")
	clk.t = clk.t.Add(time.Minute)
	const ahead = 16 // steps, 8 minutes
	if err := svc.Verify(ctx, "alice", "alice-phone", code(seed, clk.t, ahead)); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("drifted code before resync: %v, want InvalidAuthenticationCode", err)
	}
	if err := svc.Resync(ctx, "ALICE", serial, code(seed, clk.t, ahead-1), code(seed, clk.t, ahead)); err != nil {
		t.Fatal(err)
	}
	d := device(t, b, "alice-phone")
	if d.Drift != ahead || d.FailedAttempts != 0 {
		t.Fatalf("drift %d failed %d, want %d 0", d.Drift, d.FailedAttempts, ahead)
	}
	if err := svc.Verify(ctx, "alice", "alice-phone", code(seed, clk.t, ahead)); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("resync code replayed: %v, want InvalidAuthenticationCode", err)
	}
	err := svc.Resync(ctx, "alice", serial, code(seed, clk.t, ahead-1), code(seed, clk.t, ahead))
	if !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("resync repeated: %v, want InvalidAuthenticationCode", err)
	}
	clk.t = clk.t.Add(5 * time.Minute)
	if err := svc.Verify(ctx, "alice", "alice-phone", code(seed, clk.t, ahead)); err != nil {
		t.Fatalf("device code after resync: %v", err)
	}
	if err := svc.Verify(ctx, "alice", "alice-phone", code(seed, clk.t, 0)); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("service-clock code after resync: %v, want InvalidAuthenticationCode", err)
	}
	// Resync back to the service clock once it has passed the last step.
	clk.t = clk.t.Add(10 * time.Minute)
	if err := svc.Resync(ctx, "alice", serial, code(seed, clk.t, -1), code(seed, clk.t, 0)); err != nil {
		t.Fatal(err)
	}
	if d := device(t, b, "alice-phone"); d.Drift != 0 {
		t.Fatalf("drift %d, want 0", d.Drift)
	}
}

// TestResyncWindow: the pair must lie within ±ResyncSkew steps of now
// and be newer than the last accepted step; a wrong pair counts as a
// failed attempt and changes no drift.
func TestResyncWindow(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	seed, serial := enrollSerial(t, svc, clk, "alice", "alice-phone")
	clk.t = clk.t.Add(time.Minute)
	for _, tc := range []struct {
		name   string
		c1, c2 int64
		ok     bool
	}{
		{"first below window", -mfa.ResyncSkew - 1, -mfa.ResyncSkew, false},
		{"second above window", mfa.ResyncSkew, mfa.ResyncSkew + 1, false},
		{"not consecutive", 3, 5, false},
		{"at or before last step", -2, -1, false},
		{"upper edge", mfa.ResyncSkew - 1, mfa.ResyncSkew, true},
	} {
		before := device(t, b, "alice-phone")
		err := svc.Resync(ctx, "alice", serial, code(seed, clk.t, tc.c1), code(seed, clk.t, tc.c2))
		after := device(t, b, "alice-phone")
		if tc.ok {
			if err != nil || after.Drift != tc.c2 {
				t.Fatalf("%s: %v drift %d, want nil %d", tc.name, err, after.Drift, tc.c2)
			}
			continue
		}
		if !errors.Is(err, mfa.ErrInvalidCode) {
			t.Fatalf("%s: %v, want InvalidAuthenticationCode", tc.name, err)
		}
		if after.Drift != before.Drift || after.LastStep != before.LastStep ||
			after.FailedAttempts != before.FailedAttempts+1 {
			t.Fatalf("%s: device %+v -> %+v", tc.name, before, after)
		}
	}
	// Lower edge on a fresh device whose last step is far behind.
	clk.t = clk.t.Add(time.Hour)
	lo := -int64(mfa.ResyncSkew)
	if err := svc.Resync(ctx, "alice", serial, code(seed, clk.t, lo), code(seed, clk.t, lo+1)); err != nil {
		t.Fatal(err)
	}
	if d := device(t, b, "alice-phone"); d.Drift != -mfa.ResyncSkew+1 {
		t.Fatalf("drift %d, want %d", d.Drift, -mfa.ResyncSkew+1)
	}
}

// TestResyncNotAssociated: another user, a serial without the device's
// path, a disabled device and an unknown or malformed serial are
// NoSuchEntity and change nothing.
func TestResyncNotAssociated(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	seed, serial := enrollSerial(t, svc, clk, "alice", "alice-phone")
	if _, err := svc.CreateVirtual(ctx, "spare", "/team/"); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Minute)
	c1, c2 := code(seed, clk.t, 0), code(seed, clk.t, 1)
	for _, tc := range []struct{ name, user, serial string }{
		{"other user", "bob", serial},
		{"other account", "alice", "arn:vws:iam::111111111111:mfa/alice-phone"},
		{"path mismatch", "alice", "arn:vws:iam::" + acct + ":mfa/x/alice-phone"},
		{"not enabled", "alice", "arn:vws:iam::" + acct + ":mfa/team/spare"},
		{"malformed", "alice", "alice-phone"},
	} {
		if err := svc.Resync(ctx, tc.user, tc.serial, c1, c2); !errors.Is(err, mfa.ErrNotAssociated) {
			t.Errorf("%s: %v, want NoSuchEntity", tc.name, err)
		}
	}
	if err := svc.Resync(ctx, "alice", "arn:vws:iam::"+acct+":mfa/nope", c1, c2); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown device: %v, want not found", err)
	}
	if d := device(t, b, "alice-phone"); d.Drift != 0 || d.FailedAttempts != 0 {
		t.Fatalf("device changed: %+v", d)
	}
	if err := svc.Resync(ctx, "alice", serial, c1, c2); err != nil {
		t.Fatal(err)
	}
}

// TestResyncLockout: MaxFailedAttempts wrong pairs lock the device, and
// then even the right pair is refused until the lock ends.
func TestResyncLockout(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	seed, serial := enrollSerial(t, svc, clk, "alice", "alice-phone")
	clk.t = clk.t.Add(time.Minute)
	var err error
	for range mfa.MaxFailedAttempts {
		err = svc.Resync(ctx, "alice", serial, "000000", "000000")
	}
	if !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("after %d wrong pairs: %v, want locked", mfa.MaxFailedAttempts, err)
	}
	err = svc.Resync(ctx, "alice", serial, code(seed, clk.t, 0), code(seed, clk.t, 1))
	if !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("right pair while locked: %v, want locked", err)
	}
	clk.t = clk.t.Add(mfa.LockoutDuration)
	if err := svc.Resync(ctx, "alice", serial, code(seed, clk.t, 0), code(seed, clk.t, 1)); err != nil {
		t.Fatalf("after the lock: %v", err)
	}
}

// TestResyncConcurrent: racing requests with one pair succeed once.
func TestResyncConcurrent(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	seed, serial := enrollSerial(t, svc, clk, "alice", "alice-phone")
	clk.t = clk.t.Add(time.Minute)
	c1, c2 := code(seed, clk.t, 6), code(seed, clk.t, 7)
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { errs[i] = svc.Resync(ctx, "alice", serial, c1, c2) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, mfa.ErrInvalidCode) && !errors.Is(err, mfa.ErrLocked):
			t.Fatalf("unexpected %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d successes, want 1", ok)
	}
	if d := device(t, b, "alice-phone"); d.Drift != 7 {
		t.Fatalf("drift %d, want 7", d.Drift)
	}
}

// TestEnableResetsDrift: a device enabled again starts at the service
// clock, whatever drift it had for its previous user.
func TestEnableResetsDrift(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	seed, serial := enrollSerial(t, svc, clk, "alice", "alice-phone")
	clk.t = clk.t.Add(time.Minute)
	if err := svc.Resync(ctx, "alice", serial, code(seed, clk.t, 9), code(seed, clk.t, 10)); err != nil {
		t.Fatal(err)
	}
	if err := svc.Deactivate(ctx, "alice", "alice-phone"); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(10 * time.Minute)
	if err := svc.Enable(ctx, "bob", "alice-phone", code(seed, clk.t, -1), code(seed, clk.t, 0)); err != nil {
		t.Fatal(err)
	}
	if d := device(t, b, "alice-phone"); d.Drift != 0 {
		t.Fatalf("drift %d after enable, want 0", d.Drift)
	}
}
