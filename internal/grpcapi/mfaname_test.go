package grpcapi_test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/totp"
)

// TestMFADeviceNameLength: CreateVirtualMfaDevice accepts a device id of
// up to iam.MaxMFADeviceNameLen (175) characters, longer than the 64 of
// other IAM names as AWS VirtualMFADeviceName has no maximum; the device
// enables, its serial passes GetSessionToken, and it survives a restart.
// 176 characters, or a path that makes the serial longer than 256, is
// InvalidArgument (ValidationError) and stores nothing (#179).
func TestMFADeviceNameLength(t *testing.T) {
	now := time.Now().UTC()
	b := memstore.New()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	id := strings.Repeat("m", iam.MaxMFADeviceNameLen)
	create := func(id, path string) (*iamv1.CreateVirtualMfaDeviceResponse, error) {
		return e.mfa.CreateVirtualMfaDevice(ctx, &iamv1.CreateVirtualMfaDeviceRequest{
			Parent: parentName, MfaDeviceId: id, MfaDevice: &iamv1.MfaDevice{Spec: &iamv1.MfaDeviceSpec{Path: path}},
		})
	}

	_, err := create(id+"m", "")
	wantErr(t, err, codes.InvalidArgument, "INVALID_RESOURCE_ID", "ValidationError")
	_, err = create(id, "/"+strings.Repeat("x", 256)+"/")
	wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	_, err = e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: parentName + "/mfaDevices/" + id})
	wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "NoSuchEntity")

	d, err := create(id, "")
	if err != nil {
		t.Fatalf("CreateVirtualMfaDevice of %d: %v", len(id), err)
	}
	if want := parentName + "/mfaDevices/" + id; d.GetMfaDevice().GetName() != want {
		t.Fatalf("device name %q", d.GetMfaDevice().GetName())
	}
	_, err = create(strings.ToUpper(id), "")
	wantErr(t, err, codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")

	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(d.GetBase32StringSeed())
	if err != nil {
		t.Fatal(err)
	}
	step := totp.Step(now)
	if _, err := e.mfa.EnableMfaDevice(ctx, &iamv1.EnableMfaDeviceRequest{
		Name: d.GetMfaDevice().GetName(), User: u.GetName(),
		AuthenticationCode_1: totp.Code(seed, step-1, totp.Digits), AuthenticationCode_2: totp.Code(seed, step, totp.Digits),
	}); err != nil {
		t.Fatalf("EnableMfaDevice of %d: %v", len(id), err)
	}
	got, err := e.mfa.GetMfaDevice(ctx, &iamv1.GetMfaDeviceRequest{Name: d.GetMfaDevice().GetName()})
	serial := got.GetStatus().GetSerialNumber()
	if err != nil || serial != "arn:vws:iam::"+proj+":mfa/"+id || got.GetStatus().GetUser() != u.GetName() {
		t.Fatalf("device %v %v", got, err)
	}
	key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]

	restarted := newEnvOn(t, b, &now)
	now = now.Add(30 * time.Second)
	st, err := restarted.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
		Authentication: gstSig(restarted.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")),
		SerialNumber:   serial, TokenCode: code(t, restarted, d.GetBase32StringSeed()),
	})
	if err != nil {
		t.Fatalf("GetSessionToken with the %d-character device after a restart: %v", len(id), err)
	}
	c := st.GetCredentials()
	signed := restarted.sign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken())
	a, err := restarted.auth.Authenticate(ctx, signed)
	if err != nil || !a.GetPrincipal().GetMfaAuthenticated() {
		t.Fatalf("authenticate MFA session %v %v", a, err)
	}
}
