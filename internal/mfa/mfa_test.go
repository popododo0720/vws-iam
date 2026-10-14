package mfa_test

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/totp"
)

const acct = "000000000000"

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup(t *testing.T) (*mfa.Service, store.Backend, *clock) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring("kek-1", map[string][]byte{"kek-1": k})
	if err != nil {
		t.Fatal(err)
	}
	b := memstore.New()
	for _, n := range []string{"alice", "bob"} {
		if _, err := store.Create(context.Background(), b, iam.User{Name: n, ID: n}); err != nil {
			t.Fatal(err)
		}
	}
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	return mfa.New(b, keys, acct, clk.now), b, clk
}

func seedOf(t *testing.T, e mfa.Enrollment) []byte {
	s, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(e.Base32Seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func code(seed []byte, at time.Time, off int64) string {
	return totp.Code(seed, totp.Step(at)+off, totp.Digits)
}

func enroll(t *testing.T, svc *mfa.Service, clk *clock, user, name string) []byte {
	ctx := context.Background()
	e, err := svc.CreateVirtual(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	seed := seedOf(t, e)
	if err := svc.Enable(ctx, user, name, code(seed, clk.t, -1), code(seed, clk.t, 0)); err != nil {
		t.Fatal(err)
	}
	return seed
}

func TestEnrollmentSeedIsSealedAndShownOnce(t *testing.T) {
	svc, b, _ := setup(t)
	ctx := context.Background()
	e, err := svc.CreateVirtual(ctx, "alice-phone")
	if err != nil {
		t.Fatal(err)
	}
	if e.SerialNumber != "arn:vws:iam::"+acct+":mfa/alice-phone" || !strings.HasPrefix(e.URI, "otpauth://totp/") {
		t.Fatalf("%s %s", e.SerialNumber, e.URI)
	}
	if strings.Contains(fmt.Sprint(e), e.Base32Seed) {
		t.Fatal("String prints the seed")
	}
	raw, err := b.Get(ctx, iam.KindMfaDevice, "alice-phone")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw.Spec), e.Base32Seed) || strings.Contains(string(raw.Spec), string(seedOf(t, e))) {
		t.Fatal("stored device contains the seed")
	}
	ds, err := svc.List(ctx, "")
	if err != nil || len(ds) != 1 || len(ds[0].Seed.Ciphertext) != 0 {
		t.Fatalf("list leaks sealed seed: %v %+v", err, ds)
	}
	if _, err := svc.CreateVirtual(ctx, "ALICE-PHONE"); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate device: %v", err)
	}
}

func TestEnableNeedsTwoConsecutiveCodes(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	// Each bad pair gets its own device so the lockout does not interfere.
	for i, c := range []func(seed []byte) [2]string{
		func(s []byte) [2]string { return [2]string{code(s, clk.t, 0), code(s, clk.t, 0)} },   // same code twice
		func(s []byte) [2]string { return [2]string{code(s, clk.t, 0), code(s, clk.t, -1)} },  // reversed
		func(s []byte) [2]string { return [2]string{code(s, clk.t, -1), code(s, clk.t, 1)} },  // not consecutive
		func(s []byte) [2]string { return [2]string{code(s, clk.t, -5), code(s, clk.t, -4)} }, // too old
		func(s []byte) [2]string { return [2]string{code(s, clk.t, -2), code(s, clk.t, -1)} }, // outside ±1 step
		func(s []byte) [2]string { return [2]string{code(s, clk.t, 1), code(s, clk.t, 2)} },   // second code 2 steps ahead
		func([]byte) [2]string { return [2]string{"000000", "111111"} },
	} {
		name := fmt.Sprintf("bad-%d", i)
		e, err := svc.CreateVirtual(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		p := c(seedOf(t, e))
		if err := svc.Enable(ctx, "alice", name, p[0], p[1]); !errors.Is(err, mfa.ErrInvalidCode) {
			t.Fatalf("case %d %v: %v", i, p, err)
		}
	}
	e, err := svc.CreateVirtual(ctx, "d1")
	if err != nil {
		t.Fatal(err)
	}
	seed := seedOf(t, e)
	// The ±1 window still accepts the current pair (0, +1).
	e2, err := svc.CreateVirtual(ctx, "d2")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Enable(ctx, "bob", "d2", code(seedOf(t, e2), clk.t, 0), code(seedOf(t, e2), clk.t, 1)); err != nil {
		t.Fatalf("(0,+1): %v", err)
	}
	if err := svc.Enable(ctx, "nobody", "d1", code(seed, clk.t, -1), code(seed, clk.t, 0)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
	if err := svc.Enable(ctx, "alice", "d1", code(seed, clk.t, -1), code(seed, clk.t, 0)); err != nil {
		t.Fatal(err)
	}
	if err := svc.Enable(ctx, "bob", "d1", code(seed, clk.t, 0), code(seed, clk.t, 1)); !errors.Is(err, mfa.ErrEntityInUse) {
		t.Fatalf("device stolen by bob: %v", err)
	}
	if req, err := svc.Required(ctx, "alice"); err != nil || !req {
		t.Fatalf("required: %v %v", req, err)
	}
}

func TestReusedCodeIsRejected(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	seed := enroll(t, svc, clk, "alice", "d1")
	// The enabling code was consumed.
	if err := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, 0)); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("enable code replayed: %v", err)
	}
	clk.t = clk.t.Add(totp.Period)
	c := code(seed, clk.t, 0)
	if err := svc.Verify(ctx, "alice", "d1", c); err != nil {
		t.Fatal(err)
	}
	if err := svc.Verify(ctx, "alice", "d1", c); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("replay: %v", err)
	}
	// An older but still in-window code is also refused after a newer one.
	if err := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, -1)); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("older code: %v", err)
	}
	// Clock skew: next step accepted, two steps out refused.
	if err := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, 2)); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("+2 steps: %v", err)
	}
	if err := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, 1)); err != nil {
		t.Fatalf("+1 step: %v", err)
	}
	if err := svc.Verify(ctx, "bob", "d1", code(seed, clk.t.Add(time.Minute), 0)); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("bob used alice's device: %v", err)
	}
}

func TestConcurrentReplayWinsOnce(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	seed := enroll(t, svc, clk, "alice", "d1")
	clk.t = clk.t.Add(2 * totp.Period)
	c := code(seed, clk.t, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 8 {
		wg.Go(func() {
			if svc.Verify(ctx, "alice", "d1", c) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("code accepted %d times", ok)
	}
}

func TestDeactivateAndDelete(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	enroll(t, svc, clk, "alice", "d1")
	if err := svc.Delete(ctx, "d1"); !errors.Is(err, mfa.ErrEntityInUse) {
		t.Fatalf("deleted an enabled device: %v", err)
	}
	if err := svc.Deactivate(ctx, "bob", "d1"); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("bob deactivated: %v", err)
	}
	if err := svc.Deactivate(ctx, "alice", "d1"); err != nil {
		t.Fatal(err)
	}
	if req, err := svc.Required(ctx, "alice"); err != nil || req {
		t.Fatalf("still required: %v %v", req, err)
	}
	if err := svc.Delete(ctx, "d1"); err != nil {
		t.Fatal(err)
	}
}

func TestMFARequiredPolicyDeniesWithoutMFA(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	if _, err := store.Mutate(ctx, b, "alice", func(u *iam.User) error {
		u.InlinePolicies = map[string]string{"mfa": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Sid":"RequireMFA","Effect":"Deny","Action":"ec2:TerminateInstances","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	seed := enroll(t, svc, clk, "alice", "d1")
	az := authz.New(b, acct, clk.now)
	alice := authz.Principal{Kind: authz.User, Name: "alice"}
	ctxFor := func(present bool) map[string][]string {
		return map[string][]string{"aws:MultiFactorAuthPresent": {fmt.Sprint(present)}}
	}
	if d, err := az.Authorize(ctx, alice, "ec2:TerminateInstances", "*", nil); err != nil || d.Allowed {
		t.Fatalf("no MFA context: %+v %v", d, err)
	}
	clk.t = clk.t.Add(totp.Period)
	present := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, 0)) == nil
	if !present {
		t.Fatal("valid code rejected")
	}
	if d, err := az.Authorize(ctx, alice, "ec2:TerminateInstances", "*", ctxFor(present)); err != nil || !d.Allowed {
		t.Fatalf("with MFA: %+v %v", d, err)
	}
	present = svc.Verify(ctx, "alice", "d1", "000000") == nil
	if d, err := az.Authorize(ctx, alice, "ec2:TerminateInstances", "*", ctxFor(present)); err != nil || d.Allowed {
		t.Fatalf("bad code still allowed: %+v %v", d, err)
	}
}

func TestFailedAttemptsLockTheDevice(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	seed := enroll(t, svc, clk, "alice", "d1")
	clk.t = clk.t.Add(totp.Period)
	for i := 1; i < mfa.MaxFailedAttempts; i++ {
		if err := svc.Verify(ctx, "alice", "d1", "000000"); !errors.Is(err, mfa.ErrInvalidCode) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// A success resets the counter.
	if err := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, 0)); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < mfa.MaxFailedAttempts; i++ {
		if err := svc.Verify(ctx, "alice", "d1", "000000"); !errors.Is(err, mfa.ErrInvalidCode) {
			t.Fatalf("attempt %d after reset: %v", i, err)
		}
	}
	if err := svc.Verify(ctx, "alice", "d1", "000000"); !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("limit reached: %v", err)
	}
	// Locked: even the right code is refused, and the lock survives a
	// restart because it is stored on the device.
	clk.t = clk.t.Add(totp.Period)
	restarted := mfa.New(b, nil, acct, clk.now)
	if err := restarted.Verify(ctx, "alice", "d1", code(seed, clk.t, 0)); !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("correct code while locked: %v", err)
	}
	d, err := store.Get[iam.MfaDevice](ctx, b, "d1")
	if err != nil || d.Object.LockedUntil.IsZero() {
		t.Fatalf("lock not stored: %v %+v", err, d.Object.LockedUntil)
	}
	// After the lockout the device works again with a fresh counter.
	clk.t = clk.t.Add(mfa.LockoutDuration)
	if err := svc.Verify(ctx, "alice", "d1", code(seed, clk.t, 0)); err != nil {
		t.Fatalf("after lockout: %v", err)
	}
	if err := svc.Verify(ctx, "alice", "d1", "000000"); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("counter not reset: %v", err)
	}
}

func TestEnableFailuresCountTowardLockout(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	e, err := svc.CreateVirtual(ctx, "d1")
	if err != nil {
		t.Fatal(err)
	}
	for range mfa.MaxFailedAttempts - 1 {
		if err := svc.Enable(ctx, "alice", "d1", "000000", "111111"); !errors.Is(err, mfa.ErrInvalidCode) {
			t.Fatal(err)
		}
	}
	if err := svc.Enable(ctx, "alice", "d1", "000000", "111111"); !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("limit: %v", err)
	}
	seed := seedOf(t, e)
	if err := svc.Enable(ctx, "alice", "d1", code(seed, clk.t, -1), code(seed, clk.t, 0)); !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("enable while locked: %v", err)
	}
}
