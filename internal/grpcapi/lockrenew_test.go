package grpcapi_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestLoginLockRenewalMemstore runs the #48 console Login lock renewal
// suite on one shared in-memory backend.
func TestLoginLockRenewalMemstore(t *testing.T) {
	testLoginLockRenewal(t, func(*testing.T) store.Backend { return memstore.New() })
}

// TestLoginLockRenewalOnAPIServer runs it on kubestore against a real
// kube-apiserver. It skips without KUBEBUILDER_ASSETS.
func TestLoginLockRenewalOnAPIServer(t *testing.T) {
	testLoginLockRenewal(t, apiServerBackends(t))
}

func loginTOTP(ctx context.Context, e *env, user, pw, totpCode, ip string) error {
	ctx, cancel := context.WithTimeout(ctx, grpcapi.MaxTimeout)
	defer cancel()
	_, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: user, Password: pw, TotpCode: totpCode, SourceIp: ip})
	return err
}

// deviceLock reads alice-phone's status through the API.
func deviceLock(t *testing.T, e *env) (int32, time.Time) {
	t.Helper()
	d, err := e.mfa.GetMfaDevice(t.Context(), &iamv1.GetMfaDeviceRequest{Name: parentName + "/mfaDevices/alice-phone"})
	if err != nil {
		t.Fatal(err)
	}
	var until time.Time
	if lu := d.GetStatus().GetLockedUntil(); lu != nil {
		until = lu.AsTime()
	}
	return d.GetStatus().GetFailedAttempts(), until
}

func testLoginLockRenewal(t *testing.T, backend func(*testing.T) store.Backend) {
	// lockAlice locks alice-phone with wrong codes behind the right
	// password (each also counts toward alice's user limit).
	lockAlice := func(t *testing.T, e *env) time.Time {
		t.Helper()
		for range mfa.MaxFailedAttempts {
			wantErr(t, loginTOTP(t.Context(), e, "alice", goodPW, "000000", "203.0.113.9"), codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidAuthenticationCode")
		}
		_, until := deviceLock(t, e)
		if until.IsZero() {
			t.Fatal("device not locked")
		}
		return e.now.UTC()
	}
	// tripUser fills alice's user limit with wrong passwords (no MFA code
	// is checked, as an attacker knowing only the name would).
	tripUser := func(t *testing.T, e *env, already int) {
		t.Helper()
		for range grpcapi.UserAttemptLimit - already {
			wantBadLogin(t, login(t.Context(), e, "alice", "wrong password!", "198.51.100.7"))
		}
	}

	t.Run("UserThrottleRenewsRunningLockAcrossReplicas", func(t *testing.T) {
		b := backend(t)
		now := time.Now().UTC()
		a, rb := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
		withCheapPassword(t, a, b, "alice")
		seed, _, _ := strings.Cut(enableMFA(t, a, t.Context(), "alice"), "|")
		start := lockAlice(t, a)
		tripUser(t, rb, mfa.MaxFailedAttempts)
		now = now.Add(10 * time.Minute)
		// A user-limit throttle on the other replica renews the lock from now.
		wantThrottled(t, loginTOTP(t.Context(), rb, "alice", goodPW, code(t, rb, seed), "192.0.2.1"))
		if n, until := deviceLock(t, a); n != 0 || !until.Equal(now.Add(mfa.LockoutDuration)) {
			t.Fatalf("after user throttle: %d %v, want %v", n, until, now.Add(mfa.LockoutDuration))
		}
		// The renewal is capped: keep alice's user limit tripped (wrong
		// passwords only) for two hours; the lock never passes the cap.
		for now.Before(start.Add(mfa.MaxLockout + grpcapi.AttemptLockout)) {
			now = now.Add(5 * time.Minute)
			for i := 0; i <= grpcapi.UserAttemptLimit; i++ {
				err := login(t.Context(), a, "alice", "wrong password!", "198.51.100."+strconv.Itoa(i))
				if status.Code(err) == codes.ResourceExhausted {
					break
				}
			}
			if _, until := deviceLock(t, rb); until.After(start.Add(mfa.MaxLockout)) {
				t.Fatalf("lock %v past cap %v", until, start.Add(mfa.MaxLockout))
			}
		}
		if _, until := deviceLock(t, a); !until.IsZero() {
			t.Fatalf("still locked after the cap: %v", until)
		}
		// Once alice's own counter lockout ends, the right code works.
		now = now.Add(grpcapi.AttemptLockout + grpcapi.AttemptWindow)
		if err := loginTOTP(t.Context(), a, "alice", goodPW, code(t, a, seed), "192.0.2.1"); err != nil {
			t.Fatalf("after cap: %v", err)
		}
	})

	t.Run("UserThrottleDoesNotStartALock", func(t *testing.T) {
		b := backend(t)
		now := time.Now().UTC()
		a, rb := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
		withCheapPassword(t, a, b, "alice")
		seed, _, _ := strings.Cut(enableMFA(t, a, t.Context(), "alice"), "|")
		tripUser(t, a, 0)
		wantThrottled(t, loginTOTP(t.Context(), rb, "alice", goodPW, code(t, rb, seed), ""))
		if n, until := deviceLock(t, rb); n != 0 || !until.IsZero() {
			t.Fatalf("throttle locked the device: %d %v", n, until)
		}
		now = now.Add(grpcapi.AttemptLockout + time.Second)
		if err := loginTOTP(t.Context(), a, "alice", goodPW, code(t, a, seed), ""); err != nil {
			t.Fatalf("after user lockout: %v", err)
		}
	})

	t.Run("IPOnlyThrottleLeavesLockAcrossReplicas", func(t *testing.T) {
		b := backend(t)
		now := time.Now().UTC()
		a, rb := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
		withCheapPassword(t, a, b, "alice")
		seed, _, _ := strings.Cut(enableMFA(t, a, t.Context(), "alice"), "|")
		const shared = "203.0.113.50"
		// Other users (cheap hashes, each below its own limit) exhaust the
		// shared IP; alice has no failures. Nonexistent names would burn a
		// production-cost argon2id each (#43).
		const others = 10
		var names []string
		for i := range others {
			names = append(names, "guess"+strconv.Itoa(i))
		}
		withCheapPassword(t, a, b, names...)
		for i := range grpcapi.IPAttemptLimit {
			e := a
			if i%2 == 1 {
				e = rb
			}
			wantBadLogin(t, login(t.Context(), e, names[i%others], "wrong password!", shared))
		}
		wantThrottled(t, loginTOTP(t.Context(), rb, "alice", goodPW, code(t, rb, seed), shared))
		if n, until := deviceLock(t, a); n != 0 || !until.IsZero() {
			t.Fatalf("IP-only throttle locked the device: %d %v", n, until)
		}
		// The right code from another IP works on either replica.
		if err := loginTOTP(t.Context(), a, "alice", goodPW, code(t, a, seed), "192.0.2.1"); err != nil {
			t.Fatalf("other IP: %v", err)
		}
		// A running lock is not renewed by an IP-only throttle either.
		now = now.Add(time.Minute)
		lockAlice(t, rb)
		_, before := deviceLock(t, a)
		now = now.Add(10 * time.Minute)
		wantThrottled(t, loginTOTP(t.Context(), a, "alice", goodPW, code(t, a, seed), shared))
		if _, until := deviceLock(t, a); !until.Equal(before) {
			t.Fatalf("IP-only throttle renewed: %v, was %v", until, before)
		}
	})
}

// TestSTSLockRenewalMemstore and TestSTSLockRenewalOnAPIServer: a STS
// attempt throttled by the user's own limit renews only a running device
// lock, never past mfa.MaxLockout from the failure that locked it, and
// never starts one (#48).
func TestSTSLockRenewalMemstore(t *testing.T) {
	testSTSLockRenewal(t, func(*testing.T) store.Backend { return memstore.New() })
}

func TestSTSLockRenewalOnAPIServer(t *testing.T) {
	testSTSLockRenewal(t, apiServerBackends(t))
}

func testSTSLockRenewal(t *testing.T, backend func(*testing.T) store.Backend) {
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
	seed, serial, _ := strings.Cut(enableMFA(t, a, ctx, "alice"), "|")
	gstMFA := func(e *env, code string) error {
		_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
			Authentication: gstSig(a.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")),
			SerialNumber:   serial,
			TokenCode:      code,
		})
		return err
	}
	// tripUser puts alice's user counter at its limit in a fresh window,
	// as wrong passwords from anyone who knows the name would.
	userHash := grpcapi.AttemptCounterHash(iam.AttemptUser, proj+"/alice")
	tripUser := func() {
		t.Helper()
		c := iam.AttemptCounter{Hash: userHash, Scope: iam.AttemptUser, Failures: grpcapi.UserAttemptLimit, WindowStart: now}
		if _, err := store.Create(ctx, b, c); err == nil {
			return
		}
		if _, err := store.Mutate(ctx, b, userHash, func(x *iam.AttemptCounter) error {
			*x = c
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Never starts: the user is over its limit, the device is not locked.
	tripUser()
	wantThrottled(t, gstMFA(rb, code(t, rb, seed)))
	if n, until := deviceLock(t, a); n != 0 || !until.IsZero() {
		t.Fatalf("STS throttle started a lock: %d %v", n, until)
	}

	// Lock by wrong codes once the counter is clear, then keep the user
	// limit tripped for two hours: renewals stop at start+MaxLockout.
	now = now.Add(grpcapi.AttemptLockout + grpcapi.AttemptWindow)
	start := now
	for range mfa.MaxFailedAttempts {
		wantErr(t, gstMFA(a, "000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	}
	for i := 0; now.Before(start.Add(mfa.MaxLockout + grpcapi.AttemptLockout)); i++ {
		now = now.Add(10 * time.Minute)
		tripUser()
		e := a
		if i%2 == 1 {
			e = rb
		}
		wantThrottled(t, gstMFA(e, code(t, e, seed)))
		_, until := deviceLock(t, a)
		want := now.Add(mfa.LockoutDuration)
		if cap := start.Add(mfa.MaxLockout); want.After(cap) {
			want = cap
		}
		if now.Before(start.Add(mfa.MaxLockout)) && !until.Equal(want) {
			t.Fatalf("at +%v: locked_until %v, want %v", now.Sub(start), until, want)
		}
		if until.After(start.Add(mfa.MaxLockout)) {
			t.Fatalf("lock %v past cap %v", until, start.Add(mfa.MaxLockout))
		}
	}
	if _, until := deviceLock(t, rb); !until.IsZero() {
		t.Fatalf("still locked after the cap: %v", until)
	}
	// Counter clear: the right code works.
	now = now.Add(grpcapi.AttemptLockout + grpcapi.AttemptWindow)
	if err := gstMFA(rb, code(t, rb, seed)); err != nil {
		t.Fatalf("after cap: %v", err)
	}
}
