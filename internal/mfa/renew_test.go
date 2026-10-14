package mfa_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/totp"
)

func lockState(t *testing.T, b store.Backend, name string) iam.MfaDevice {
	t.Helper()
	d, err := store.Get[iam.MfaDevice](context.Background(), b, name)
	if err != nil {
		t.Fatal(err)
	}
	return d.Object
}

// TestRenewLock: a renewal only extends a running lockout of the user's
// own device, never starts one, and never runs past MaxLockout from the
// failure that locked it (#48).
func TestRenewLock(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	seed := enroll(t, svc, clk, "alice", "d1")
	clk.t = clk.t.Add(totp.Period)

	// Not locked: no write, no lock (a throttle is no evidence).
	if wrote, err := svc.RenewLock(ctx, "alice", "d1"); err != nil || wrote {
		t.Fatalf("renew unlocked: %v %v", wrote, err)
	}
	if d := lockState(t, b, "d1"); !d.LockedUntil.IsZero() || d.FailedAttempts != 0 {
		t.Fatalf("renewal started a lock: %+v", d)
	}

	failCodes(t, svc)
	start := clk.t.UTC()
	if d := lockState(t, b, "d1"); !d.LockedSince.Equal(start) || !d.LockedUntil.Equal(start.Add(mfa.LockoutDuration)) {
		t.Fatalf("lock %+v, want since %v", d, start)
	}
	// Someone else's name does not renew alice's device.
	clk.t = clk.t.Add(10 * time.Minute)
	if wrote, err := svc.RenewLock(ctx, "bob", "d1"); err != nil || wrote {
		t.Fatalf("bob renewed alice's device: %v %v", wrote, err)
	}
	// Renewals extend to now+15m, but never past start+MaxLockout.
	for clk.t.Before(start.Add(mfa.MaxLockout + 2*mfa.LockoutDuration)) {
		_, err := svc.RenewLock(ctx, "alice", "d1")
		if err != nil {
			t.Fatal(err)
		}
		d := lockState(t, b, "d1")
		if d.LockedUntil.After(start.Add(mfa.MaxLockout)) {
			t.Fatalf("lock %v past cap %v", d.LockedUntil, start.Add(mfa.MaxLockout))
		}
		if clk.t.Before(start.Add(mfa.MaxLockout-mfa.LockoutDuration)) && !d.LockedUntil.Equal(clk.t.UTC().Add(mfa.LockoutDuration)) {
			t.Fatalf("not renewed at %v: %v", clk.t, d.LockedUntil)
		}
		clk.t = clk.t.Add(10 * time.Minute)
	}
	// Past the cap the device works again, and renewal does not relock it.
	if wrote, err := svc.RenewLock(ctx, "alice", "d1"); err != nil || wrote {
		t.Fatal("renewal after the cap relocked")
	}
	if err := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, 0)); err != nil {
		t.Fatalf("after cap: %v", err)
	}
	if d := lockState(t, b, "d1"); !d.LockedSince.IsZero() || !d.LockedUntil.IsZero() {
		t.Fatalf("expired lock not cleared: %+v", d)
	}
	// A new lock needs new wrong codes, and gets a new start.
	failCodes(t, svc)
	if err := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, 0)); !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("relock by wrong codes: %v", err)
	}
	if d := lockState(t, b, "d1"); !d.LockedSince.Equal(clk.t.UTC()) {
		t.Fatalf("new lock since %v, want %v", d.LockedSince, clk.t)
	}
}

// TestRenewLockLegacy: a lock stored before LockedSince existed is capped
// from LockedUntil-LockoutDuration.
func TestRenewLockLegacy(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	enroll(t, svc, clk, "alice", "d1")
	start := clk.t.UTC()
	if _, err := store.Mutate(ctx, b, "d1", func(d *iam.MfaDevice) error {
		d.LockedUntil, d.LockedSince = start.Add(mfa.LockoutDuration), time.Time{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	clk.t = start.Add(mfa.MaxLockout - time.Minute)
	if _, err := svc.RenewLock(ctx, "alice", "d1"); err != nil {
		t.Fatal(err)
	}
	clk.t = start.Add(10 * time.Minute)
	for range 10 {
		if _, err := svc.RenewLock(ctx, "alice", "d1"); err != nil {
			t.Fatal(err)
		}
		clk.t = clk.t.Add(10 * time.Minute)
	}
	if d := lockState(t, b, "d1"); !d.LockedUntil.Equal(start.Add(mfa.MaxLockout)) || !d.LockedSince.Equal(start) {
		t.Fatalf("legacy lock %+v", d)
	}
}

// failCodes sends MaxFailedAttempts wrong codes; the last one locks.
func failCodes(t *testing.T, svc *mfa.Service) {
	t.Helper()
	for i := 1; i <= mfa.MaxFailedAttempts; i++ {
		want := mfa.ErrInvalidCode
		if i == mfa.MaxFailedAttempts {
			want = mfa.ErrLocked
		}
		if err := svc.Verify(context.Background(), "alice", "d1", "000000"); !errors.Is(err, want) {
			t.Fatalf("wrong code %d: %v, want %v", i, err, want)
		}
	}
}
