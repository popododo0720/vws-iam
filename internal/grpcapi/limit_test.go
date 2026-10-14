package grpcapi_test

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const goodPW = "correct horse battery"

// TestAttemptLimitsMemstore runs the #12 per-caller limit suite on one
// shared in-memory backend.
func TestAttemptLimitsMemstore(t *testing.T) {
	testAttemptLimits(t, func(*testing.T) store.Backend { return memstore.New() })
}

// TestAttemptLimitsOnAPIServer runs it on kubestore against a real
// kube-apiserver with deploy/crds (IamAttemptCounter). It skips without
// KUBEBUILDER_ASSETS.
func TestAttemptLimitsOnAPIServer(t *testing.T) {
	testAttemptLimits(t, apiServerBackends(t))
}

func wantThrottled(t *testing.T, err error) {
	t.Helper()
	wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "Throttling")
}

func wantBadLogin(t *testing.T, err error) {
	t.Helper()
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
}

// slowRPC is the deadline of a call that runs argon2id (64 MiB, t=3):
// under -race next to envtest and other packages that alone can take
// seconds, so it gets the server's MaxTimeout. Without a client deadline
// the server's DefaultTimeout (10s) applies, which a loaded box can miss
// (#43).
func slowRPC(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, grpcapi.MaxTimeout)
}

func login(ctx context.Context, e *env, user, pw, ip string) error {
	ctx, cancel := slowRPC(ctx)
	defer cancel()
	_, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: user, Password: pw, SourceIp: ip})
	return err
}

func withPassword(t *testing.T, e *env, users ...string) {
	t.Helper()
	for _, n := range users {
		u := e.createUser(t, t.Context(), n)
		ctx, cancel := slowRPC(t.Context())
		_, err := e.users.SetLoginProfile(ctx, &iamv1.SetLoginProfileRequest{Name: u.GetName(), Password: goodPW})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func testAttemptLimits(t *testing.T, backend func(*testing.T) store.Backend) {
	t.Run("PerUserAcrossReplicas", func(t *testing.T) {
		b := backend(t)
		now := time.Now().UTC()
		a, rb := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
		withPassword(t, a, "alice", "bob")
		ctx := t.Context()
		for i := range grpcapi.UserAttemptLimit {
			e := a
			if i%2 == 1 {
				e = rb
			}
			wantBadLogin(t, login(ctx, e, "alice", "wrong password!", ""))
		}
		// Locked on both replicas, even with the right password.
		wantThrottled(t, login(ctx, rb, "alice", goodPW, ""))
		wantThrottled(t, login(ctx, a, "ALICE", goodPW, ""))
		if err := login(ctx, rb, "bob", goodPW, ""); err != nil {
			t.Fatalf("another user is not limited: %v", err)
		}
		// A restarted replica still refuses.
		wantThrottled(t, login(ctx, newEnvOn(t, b, &now), "alice", goodPW, ""))
		// Lockout ends.
		now = now.Add(grpcapi.AttemptLockout + time.Second)
		if err := login(ctx, a, "alice", goodPW, ""); err != nil {
			t.Fatalf("after lockout: %v", err)
		}
		// Nothing identifying is stored: no user, project or IP text.
		es, err := b.List(ctx, iam.KindAttempt)
		if err != nil || len(es) == 0 {
			t.Fatalf("counters %d %v", len(es), err)
		}
		for _, e := range es {
			if s := string(e.Spec); strings.Contains(strings.ToLower(s), "alice") || strings.Contains(s, proj) {
				t.Fatalf("counter holds plaintext: %s", s)
			}
		}
	})

	t.Run("PerSourceIP", func(t *testing.T) {
		now := time.Now().UTC()
		e := newEnvOn(t, backend(t), &now)
		withPassword(t, e, "bob")
		ctx := t.Context()
		const ip = "203.0.113.7"
		// Spread over many unknown names: each user counter stays at 1.
		for i := range grpcapi.IPAttemptLimit {
			wantBadLogin(t, login(ctx, e, "guess"+strconv.Itoa(i), "wrong password!", ip))
		}
		wantThrottled(t, login(ctx, e, "bob", goodPW, ip))
		wantThrottled(t, login(ctx, e, "bob", goodPW, "::ffff:"+ip)) // same address, v4-mapped
		if err := login(ctx, e, "bob", goodPW, "198.51.100.9"); err != nil {
			t.Fatalf("another IP is not limited: %v", err)
		}
	})

	t.Run("PerAccessKeySTSMFA", func(t *testing.T) {
		now := time.Now().UTC()
		e := newEnvOn(t, backend(t), &now)
		ctx := t.Context()
		u := e.createUser(t, ctx, "alice")
		key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
		if err != nil {
			t.Fatal(err)
		}
		kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
		pair := strings.SplitN(enableMFA(t, e, ctx, "alice"), "|", 2)
		seed, serial := pair[0], pair[1]
		gstMFA := func(code string) error {
			_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
				Authentication: gstSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")), SerialNumber: serial, TokenCode: code})
			return err
		}
		for range grpcapi.KeyAttemptLimit {
			wantErr(t, gstMFA("000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		}
		// The key is locked before the code is checked: Throttling.
		now = now.Add(30 * time.Second)
		wantThrottled(t, gstMFA(code(t, e, seed)))
		// Without an MFA code the key still works (the limit is on MFA).
		if err := gst(ctx, e, e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")); err != nil {
			t.Fatalf("plain GetSessionToken: %v", err)
		}
	})

	t.Run("STSThrottleRenewsMFALockAcrossReplicas", func(t *testing.T) {
		// #44: past the per-user limit STS answers Throttling, not
		// AccessDenied, and the throttled attempt renews the device lock,
		// so it runs LockoutDuration from the last attempt.
		b := backend(t)
		now := time.Now().UTC().Truncate(time.Second)
		a, rb := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
		ctx := t.Context()
		u := a.createUser(t, ctx, "alice")
		key, err := a.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
		if err != nil {
			t.Fatal(err)
		}
		kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
		pair := strings.SplitN(enableMFA(t, a, ctx, "alice"), "|", 2)
		seed, serial := pair[0], pair[1]
		// One signer for both replicas: each request has its own nonce.
		gstMFA := func(e *env, code string) error {
			_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
				Authentication: gstSig(a.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")), SerialNumber: serial, TokenCode: code})
			return err
		}
		t0 := now // after enabling, which moves the clock
		// Read on the replica that did not take the attempt.
		lockedUntil := func(e *env) time.Time {
			t.Helper()
			d, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: parentName + "/mfaDevices/alice-phone"})
			if err != nil {
				t.Fatal(err)
			}
			return d.GetStatus().GetLockedUntil().AsTime()
		}
		for i := range grpcapi.UserAttemptLimit {
			e := a
			if i%2 == 1 {
				e = rb
			}
			wantErr(t, gstMFA(e, "000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		}
		if got, want := lockedUntil(a), t0.Add(mfa.LockoutDuration); !got.Equal(want) {
			t.Fatalf("device lock after 5 failures = %v, want %v", got, want)
		}
		// Ten minutes later, on the other replica, even the right code is
		// throttled, and the device lock now runs from this attempt.
		now = t0.Add(10 * time.Minute)
		last := now
		wantThrottled(t, gstMFA(rb, code(t, rb, seed)))
		wantThrottled(t, gstMFA(a, code(t, a, seed)))
		if got, want := lockedUntil(rb), last.Add(mfa.LockoutDuration); !got.Equal(want) {
			t.Fatalf("device lock after throttle = %v, want %v", got, want)
		}
		// The counter window is over, but the device is still locked.
		now = t0.Add(grpcapi.AttemptWindow + time.Minute)
		wantErr(t, gstMFA(a, code(t, a, seed)), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		// 15 minutes after the last attempt the right code works again.
		now = last.Add(mfa.LockoutDuration + time.Minute)
		if err := gstMFA(rb, code(t, rb, seed)); err != nil {
			t.Fatalf("after device lock: %v", err)
		}
	})

	t.Run("STSThrottleLocksOnlyForUserLimitAcrossReplicas", func(t *testing.T) {
		// #44 fix (vws-test r97 3b): a throttle by the source IP or the
		// access key alone must not touch the device lock or failed_attempts;
		// only a user over its own limit renews the lock.
		b := backend(t)
		now := time.Now().UTC().Truncate(time.Second)
		a, rb := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
		ctx := t.Context()
		const busyIP, otherIP = "198.51.100.60", "198.51.100.61"
		seed := func(scope, id string, failures int) {
			t.Helper()
			c := iam.AttemptCounter{Hash: grpcapi.AttemptCounterHash(scope, id), Scope: scope, Failures: failures, WindowStart: now}
			if _, err := store.Create(ctx, b, c); err != nil {
				t.Fatal(err)
			}
		}
		type caller struct {
			kid, secret, seed, serial, dev string
		}
		newCaller := func(name string) caller {
			u := a.createUser(t, ctx, name)
			key, err := a.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
			if err != nil {
				t.Fatal(err)
			}
			kn := key.GetAccessKey().GetName()
			pair := strings.SplitN(enableMFA(t, a, ctx, name), "|", 2)
			return caller{kn[strings.LastIndex(kn, "/")+1:], key.GetSecretAccessKey(), pair[0], pair[1], parentName + "/mfaDevices/" + name + "-phone"}
		}
		gstMFA := func(e *env, c caller, ip, code string) error {
			r := a.stsSign(c.kid, c.secret, "", "GetSessionToken")
			r.SourceIp = ip
			_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{Authentication: gstSig(r), SerialNumber: c.serial, TokenCode: code})
			return err
		}
		status := func(e *env, c caller) (time.Time, int32) {
			t.Helper()
			d, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: c.dev})
			if err != nil {
				t.Fatal(err)
			}
			st := d.GetStatus()
			if st.GetLockedUntil() == nil {
				return time.Time{}, st.GetFailedAttempts()
			}
			return st.GetLockedUntil().AsTime(), st.GetFailedAttempts()
		}
		wantStatus := func(e *env, c caller, lock time.Time, failed int32) {
			t.Helper()
			gotLock, gotFailed := status(e, c)
			if !gotLock.Equal(lock) || gotFailed != failed {
				t.Fatalf("%s: locked_until %v failed_attempts %d, want %v %d", c.dev, gotLock, gotFailed, lock, failed)
			}
		}

		// (a)+(b) IP limit only: one own failure, then the IP is full.
		ipc := newCaller("ipuser")
		wantErr(t, gstMFA(a, ipc, otherIP, "000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		seed(iam.AttemptIP, busyIP, grpcapi.IPAttemptLimit)
		wantThrottled(t, gstMFA(rb, ipc, busyIP, code(t, rb, ipc.seed)))
		wantThrottled(t, gstMFA(a, ipc, busyIP, "000000"))
		wantStatus(a, ipc, time.Time{}, 1)
		if err := gstMFA(rb, ipc, otherIP, code(t, rb, ipc.seed)); err != nil {
			t.Fatalf("right code from another IP after an IP-only throttle: %v", err)
		}

		// (a)+(b) Key limit only, user at 0 failures. A key cannot fail
		// apart from its user through the API, so its counter is seeded.
		kc := newCaller("keyuser")
		seed(iam.AttemptKey, kc.kid, grpcapi.KeyAttemptLimit)
		wantThrottled(t, gstMFA(a, kc, otherIP, code(t, a, kc.seed)))
		wantThrottled(t, gstMFA(rb, kc, otherIP, "000000"))
		wantStatus(rb, kc, time.Time{}, 0)
		if err := gst(ctx, a, a.stsSign(kc.kid, kc.secret, "", "GetSessionToken")); err != nil {
			t.Fatalf("plain GetSessionToken with the key: %v", err)
		}

		// (c) An existing device lock: an IP-only throttle leaves it, a
		// user over its limit renews it from that attempt.
		lc := newCaller("lockuser")
		t0 := now
		for range mfa.MaxFailedAttempts {
			wantErr(t, gstMFA(a, lc, otherIP, "000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		}
		first := t0.Add(mfa.LockoutDuration)
		wantStatus(rb, lc, first, 0)
		now = t0.Add(5 * time.Minute)
		wantThrottled(t, gstMFA(rb, lc, busyIP, code(t, rb, lc.seed)))
		wantStatus(a, lc, first, 0)
		// Fill the user counter to its limit with a second key, so
		// neither key nor any IP is over its own limit.
		lc2 := lc
		key2, err := a.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: parentName + "/users/lockuser"})
		if err != nil {
			t.Fatal(err)
		}
		kn := key2.GetAccessKey().GetName()
		lc2.kid, lc2.secret = kn[strings.LastIndex(kn, "/")+1:], key2.GetSecretAccessKey()
		for range grpcapi.UserAttemptLimit - mfa.MaxFailedAttempts {
			wantErr(t, gstMFA(rb, lc2, "198.51.100.63", "000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		}
		wantStatus(a, lc, first, 0)
		now = t0.Add(10 * time.Minute)
		wantThrottled(t, gstMFA(a, lc, "198.51.100.62", code(t, a, lc.seed)))
		wantStatus(rb, lc, now.Add(mfa.LockoutDuration), 0)
	})

	t.Run("WindowReset", func(t *testing.T) {
		now := time.Now().UTC()
		e := newEnvOn(t, backend(t), &now)
		withPassword(t, e, "alice")
		ctx := t.Context()
		for range grpcapi.UserAttemptLimit - 1 {
			wantBadLogin(t, login(ctx, e, "alice", "wrong password!", ""))
		}
		now = now.Add(grpcapi.AttemptWindow)
		for range grpcapi.UserAttemptLimit - 1 {
			wantBadLogin(t, login(ctx, e, "alice", "wrong password!", ""))
		}
		if err := login(ctx, e, "alice", goodPW, ""); err != nil {
			t.Fatalf("a new window starts from zero: %v", err)
		}
		// GC removes only finished windows.
		if n, err := e.api.GCAttemptCounters(ctx); err != nil || n != 0 {
			t.Fatalf("GC in window = %d, %v", n, err)
		}
		now = now.Add(grpcapi.AttemptWindow)
		if n, err := e.api.GCAttemptCounters(ctx); err != nil || n != 1 {
			t.Fatalf("GC after window = %d, %v", n, err)
		}
	})

	t.Run("ConcurrentGuessesStopAtLimit", func(t *testing.T) {
		b := backend(t)
		now := time.Now().UTC()
		a, rb := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
		withPassword(t, a, "carol")
		ctx := t.Context()
		const n = 3 * grpcapi.UserAttemptLimit
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			e := a
			if i%2 == 1 {
				e = rb
			}
			wg.Go(func() { errs[i] = login(ctx, e, "carol", "wrong password!", "") })
		}
		wg.Wait()
		checked := 0
		for _, err := range errs {
			if c := codesOf(err); c == codes.Unauthenticated {
				checked++
			} else {
				wantThrottled(t, err)
			}
		}
		if checked != grpcapi.UserAttemptLimit {
			t.Fatalf("%d of %d concurrent guesses reached the password check, want %d", checked, n, grpcapi.UserAttemptLimit)
		}
		wantThrottled(t, login(ctx, rb, "carol", goodPW, ""))
	})
}

func codesOf(err error) codes.Code { return status.Code(err) }
