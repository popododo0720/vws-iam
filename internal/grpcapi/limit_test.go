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

func login(ctx context.Context, e *env, user, pw, ip string) error {
	_, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: user, Password: pw, SourceIp: ip})
	return err
}

func withPassword(t *testing.T, e *env, users ...string) {
	t.Helper()
	ctx := t.Context()
	for _, n := range users {
		u := e.createUser(t, ctx, n)
		if _, err := e.users.SetLoginProfile(ctx, &iamv1.SetLoginProfileRequest{Name: u.GetName(), Password: goodPW}); err != nil {
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
