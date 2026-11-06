package grpcapi_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/totp"
)

// wantLockedOnWire checks a locked-device answer as console-api sees it:
// PERMISSION_DENIED with AWS code AccessDenied, and a message that names
// neither the mfa sentinel (MFADeviceLocked, not an AWS code) nor the
// device.
func wantLockedOnWire(t *testing.T, err error, device string) {
	t.Helper()
	wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	msg := status.Convert(err).Message()
	if strings.Contains(msg, "MFADeviceLocked") || strings.Contains(msg, device) {
		t.Fatalf("wire message %q leaks the mfa error", msg)
	}
}

// TestMFALockedNeverReachesTheWire (#12): every served path that meets a
// locked device (STS GetSessionToken, EnableMfaDevice, ResyncMfaDevice)
// answers AccessDenied without the MFADeviceLocked text, before and after
// a restart on the same store, on both backends. STS answers a wrong code
// and a locked device with the same AWS message.
func TestMFALockedNeverReachesTheWire(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()

			u := e.createUser(t, ctx, "alice")
			seed, serial, _ := strings.Cut(enableMFA(t, e, ctx, "alice"), "|")
			key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
			if err != nil {
				t.Fatal(err)
			}
			gst := func(e *env, code string) error {
				_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
					SerialNumber: serial, TokenCode: code,
					Authentication: gstSig(e.stsSign(keyID(key), key.GetSecretAccessKey(), "", "GetSessionToken")),
				})
				return err
			}
			var wrongMsg string
			for i := range 5 {
				err := gst(e, "000000")
				wantLockedOnWire(t, err, "alice-phone")
				if i == 0 {
					wrongMsg = status.Convert(err).Message()
				}
			}
			wantLockedOnWire(t, gst(e, code(t, e, seed)), "alice-phone")
			if got := status.Convert(gst(e, code(t, e, seed))).Message(); got != wrongMsg {
				t.Fatalf("locked message %q, wrong-code message %q: a caller can tell a lock", got, wrongMsg)
			}

			restarted := newEnvOn(t, b, &now)
			wantLockedOnWire(t, gst(restarted, code(t, restarted, seed)), "alice-phone")

			// Resync of the locked device.
			raw, err := base32Seed(seed)
			if err != nil {
				t.Fatal(err)
			}
			wantLockedOnWire(t, restarted.api.ResyncMFADevice(ctx, proj, resyncReq("alice", serial, raw, now, 2)), "alice-phone")

			// Enable of a new device locked by wrong pairs.
			e.createUser(t, ctx, "bob")
			d, err := e.mfa.CreateVirtualMfaDevice(ctx, &iamv1.CreateVirtualMfaDeviceRequest{
				Parent: parentName, MfaDeviceId: "bob-phone", MfaDevice: &iamv1.MfaDevice{},
			})
			if err != nil {
				t.Fatal(err)
			}
			enable := func(e *env, c1, c2 string) error {
				_, err := e.mfa.EnableMfaDevice(ctx, &iamv1.EnableMfaDeviceRequest{
					Name: d.GetMfaDevice().GetName(), User: parentName + "/users/bob",
					AuthenticationCode_1: c1, AuthenticationCode_2: c2,
				})
				return err
			}
			for range 4 {
				wantErr(t, enable(e, "000000", "000000"), codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidAuthenticationCode")
			}
			wantLockedOnWire(t, enable(e, "000000", "000000"), "bob-phone")
			bobSeed, err := base32Seed(d.GetBase32StringSeed())
			if err != nil {
				t.Fatal(err)
			}
			step := totp.Step(now)
			wantLockedOnWire(t, enable(restarted,
				totp.Code(bobSeed, step-1, totp.Digits), totp.Code(bobSeed, step, totp.Digits)), "bob-phone")
		})
	}
}

func base32Seed(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}
