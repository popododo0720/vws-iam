package grpcapi_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/totp"
)

// resyncDevice enables a virtual device for a new user and returns the
// user, the device's seed and serial number.
func resyncDevice(t *testing.T, e *env, user string) ([]byte, string) {
	t.Helper()
	e.createUser(t, t.Context(), user)
	seedB32, serial, _ := strings.Cut(enableMFA(t, e, t.Context(), user), "|")
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seedB32)
	if err != nil {
		t.Fatal(err)
	}
	return seed, serial
}

func resyncReq(user, serial string, seed []byte, at time.Time, off int64) grpcapi.ResyncMFADeviceRequest {
	s := totp.Step(at) + off
	return grpcapi.ResyncMFADeviceRequest{
		UserName: user, SerialNumber: serial,
		AuthenticationCode1: totp.Code(seed, s, totp.Digits), AuthenticationCode2: totp.Code(seed, s+1, totp.Digits),
	}
}

// TestResyncMfaDevice: a drifted device is resynchronized in the shared
// store, so every replica sees its drift, and the same pair is refused
// on any replica afterwards (InvalidAuthenticationCode). On both store
// backends.
func TestResyncMfaDevice(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			seed, serial := resyncDevice(t, e, "alice")
			req := resyncReq("alice", serial, seed, now, 11)
			if err := e.api.ResyncMFADevice(ctx, proj, req); err != nil {
				t.Fatal(err)
			}
			d, err := store.Get[iam.MfaDevice](ctx, store.Scoped(b, proj), "alice-phone")
			if err != nil || d.Object.Drift != 12 {
				t.Fatalf("device %+v %v, want drift 12", d.Object, err)
			}
			err = newEnvOn(t, b, &now).api.ResyncMFADevice(ctx, proj, req)
			wantAWS(t, err, codes.Unauthenticated, "InvalidAuthenticationCode")
			err = e.api.ResyncMFADevice(ctx, proj, resyncReq("alice", serial, seed, now, 40))
			wantAWS(t, err, codes.Unauthenticated, "InvalidAuthenticationCode")
		})
	}
}

// TestResyncMfaDeviceNoSuchEntity: an unknown user, a user name longer
// than any user, and a serial that is not a device enabled for the user
// are NoSuchEntity and change no device.
func TestResyncMfaDeviceNoSuchEntity(t *testing.T) {
	now := time.Now().UTC()
	b := memstore.New()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seed, serial := resyncDevice(t, e, "alice")
	e.createUser(t, ctx, "bob")
	for _, tc := range []struct{ name, user, serial string }{
		{"unknown user", "carol", serial},
		{"name over 64", strings.Repeat("a", 65), serial},
		{"other user", "bob", serial},
		{"unknown device", "alice", "arn:vws:iam::" + proj + ":mfa/nope"},
		{"not an mfa arn", "alice", "arn:vws:iam::" + proj + ":user/alice"},
		{"hardware serial", "alice", "GAHT12345678"},
	} {
		err := e.api.ResyncMFADevice(ctx, proj, resyncReq(tc.user, tc.serial, seed, now, 0))
		wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	}
	d, err := store.Get[iam.MfaDevice](ctx, store.Scoped(b, proj), "alice-phone")
	if err != nil || d.Object.Drift != 0 || d.Object.FailedAttempts != 0 {
		t.Fatalf("device changed: %+v %v", d.Object, err)
	}
}

// TestResyncMfaDeviceValidation: the AWS length and pattern constraints
// are ValidationError before any store access, at their boundaries, and
// no message carries a code.
func TestResyncMfaDeviceValidation(t *testing.T) {
	now := time.Now().UTC()
	e := newEnvOn(t, memstore.New(), &now)
	ctx := t.Context()
	ok := grpcapi.ResyncMFADeviceRequest{
		UserName: "alice", SerialNumber: "arn:vws:iam::" + proj + ":mfa/alice-phone",
		AuthenticationCode1: "123456", AuthenticationCode2: "654321",
	}
	for _, tc := range []struct {
		name string
		edit func(*grpcapi.ResyncMFADeviceRequest)
	}{
		{"empty user", func(r *grpcapi.ResyncMFADeviceRequest) { r.UserName = "" }},
		{"user over 128", func(r *grpcapi.ResyncMFADeviceRequest) { r.UserName = strings.Repeat("a", 129) }},
		{"user pattern", func(r *grpcapi.ResyncMFADeviceRequest) { r.UserName = "al ice" }},
		{"serial under 9", func(r *grpcapi.ResyncMFADeviceRequest) { r.SerialNumber = "12345678" }},
		{"serial over 256", func(r *grpcapi.ResyncMFADeviceRequest) { r.SerialNumber = strings.Repeat("a", 257) }},
		{"serial pattern", func(r *grpcapi.ResyncMFADeviceRequest) { r.SerialNumber = "arn:vws:iam::x:mfa/a b" }},
		{"code1 short", func(r *grpcapi.ResyncMFADeviceRequest) { r.AuthenticationCode1 = "12345" }},
		{"code1 long", func(r *grpcapi.ResyncMFADeviceRequest) { r.AuthenticationCode1 = "1234567" }},
		{"code1 letters", func(r *grpcapi.ResyncMFADeviceRequest) { r.AuthenticationCode1 = "12a456" }},
		{"code2 empty", func(r *grpcapi.ResyncMFADeviceRequest) { r.AuthenticationCode2 = "" }},
		{"code2 unicode digits", func(r *grpcapi.ResyncMFADeviceRequest) {
			r.AuthenticationCode2 = "\u0661\u0662\u0663\u0664\u0665\u0666"
		}},
	} {
		r := ok
		tc.edit(&r)
		err := e.api.ResyncMFADevice(ctx, proj, r)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
		leaks := func(c string) bool { return c != "" && strings.Contains(err.Error(), c) }
		if leaks(r.AuthenticationCode1) || leaks(r.AuthenticationCode2) {
			t.Errorf("%s: message %q carries a code", tc.name, err)
		}
	}
	err := e.api.ResyncMFADevice(ctx, "Not A Project", ok)
	wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	// Boundaries that pass validation reach the store (NoSuchEntity).
	for _, us := range [][2]string{
		{strings.Repeat("a", 128), ok.SerialNumber},
		{"a", "123456789"},
		{"alice", strings.Repeat("a", 256)},
	} {
		r := ok
		r.UserName, r.SerialNumber = us[0], us[1]
		wantAWS(t, e.api.ResyncMFADevice(ctx, proj, r), codes.NotFound, "NoSuchEntity")
	}
	s := grpcapi.ResyncMFADeviceRequest{AuthenticationCode1: "246810", AuthenticationCode2: "135791"}.String()
	if strings.Contains(s, "246810") || strings.Contains(s, "135791") {
		t.Fatalf("String() = %q carries a code", s)
	}
}

// TestResyncMfaDeviceLockout: wrong pairs lock the device (AccessDenied
// while locked, as for every MFA use), and then the right pair is
// refused too.
func TestResyncMfaDeviceLockout(t *testing.T) {
	now := time.Now().UTC()
	e := newEnvOn(t, memstore.New(), &now)
	ctx := t.Context()
	seed, serial := resyncDevice(t, e, "alice")
	bad := grpcapi.ResyncMFADeviceRequest{
		UserName: "alice", SerialNumber: serial, AuthenticationCode1: "000000", AuthenticationCode2: "000000",
	}
	for range 4 {
		wantAWS(t, e.api.ResyncMFADevice(ctx, proj, bad), codes.Unauthenticated, "InvalidAuthenticationCode")
	}
	wantAWS(t, e.api.ResyncMFADevice(ctx, proj, bad), codes.PermissionDenied, "AccessDenied")
	err := e.api.ResyncMFADevice(ctx, proj, resyncReq("alice", serial, seed, now, 2))
	wantAWS(t, err, codes.PermissionDenied, "AccessDenied")
}
