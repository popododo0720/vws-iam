package grpcapi_test

import (
	"encoding/base32"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/totp"
)

func mfaEnableRequest(t *testing.T, e *env, u *iamv1.User) *iamv1.EnableMfaDeviceRequest {
	t.Helper()
	d, err := e.mfa.CreateVirtualMfaDevice(t.Context(), &iamv1.CreateVirtualMfaDeviceRequest{
		Parent: parentName, MfaDeviceId: "phone", MfaDevice: &iamv1.MfaDevice{},
	})
	if err != nil {
		t.Fatal(err)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(d.GetBase32StringSeed())
	if err != nil {
		t.Fatal(err)
	}
	step := totp.Step(*e.now)
	return &iamv1.EnableMfaDeviceRequest{
		Name: d.GetMfaDevice().GetName(), User: u.GetName(),
		UserEtag: u.GetEtag(), ExpectedUserArn: u.GetStatus().GetArn(),
		AuthenticationCode_1: totp.Code(seed, step-1, totp.Digits),
		AuthenticationCode_2: totp.Code(seed, step, totp.Digits),
	}
}

func mfaStoredDevice(t *testing.T, b store.Backend) store.Versioned[iam.MfaDevice] {
	t.Helper()
	d, err := store.Get[iam.MfaDevice](t.Context(), store.Scoped(b, proj), "phone")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func replaceMFAUser(t *testing.T, b store.Backend) {
	t.Helper()
	sb := store.Scoped(b, proj)
	u, err := store.Get[iam.User](t.Context(), sb, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete[iam.User](t.Context(), sb, "alice", u.Version); err != nil {
		t.Fatal(err)
	}
	u.Object.UID = iam.NewUID()
	u.Object.MFARegistrationLease = iam.MFARegistrationLease{}
	if _, err := store.Create(t.Context(), sb, u.Object); err != nil {
		t.Fatal(err)
	}
}

func TestEnableMFAPreconditions(t *testing.T) {
	for _, bc := range renameBackends {
		for _, scenario := range []string{"moved", "replaced", "bad-arn", "bad-etag", "arn-only", "etag-only", "both"} {
			t.Run(bc.name+"/"+scenario, func(t *testing.T) {
				b := bc.open()
				now := time.Now().UTC()
				e := newEnvOn(t, b, &now)
				u := e.createUser(t, t.Context(), "alice")
				if scenario == "replaced" {
					// The fake API resets resourceVersion on recreate; real
					// Kubernetes versions never repeat. Read a distinct version.
					e.updateUserPath(t, u.GetName(), "/team/")
					var err error
					u, err = e.users.GetUser(t.Context(), &iamv1.GetUserRequest{Name: u.GetName()})
					if err != nil {
						t.Fatal(err)
					}
				}
				req := mfaEnableRequest(t, e, u)
				code, reason := codes.OK, ""
				switch scenario {
				case "moved":
					e.updateUserPath(t, u.GetName(), "/moved/")
					code, reason = codes.FailedPrecondition, "GENERATION_CONFLICT"
				case "replaced":
					replaceMFAUser(t, b)
					code, reason = codes.Aborted, "ETAG_MISMATCH"
				case "bad-arn":
					req.ExpectedUserArn = "bad-arn"
					code, reason = codes.InvalidArgument, "INVALID_RESOURCE_ID"
				case "bad-etag":
					req.UserEtag = "bad etag"
					code, reason = codes.InvalidArgument, "INVALID_SPEC"
				case "arn-only":
					req.UserEtag = ""
				case "etag-only":
					req.ExpectedUserArn = ""
				}
				before := mfaStoredDevice(t, b)
				sb := store.Scoped(b, proj)
				userBefore, err := store.Get[iam.User](t.Context(), sb, "alice")
				if err != nil {
					t.Fatal(err)
				}
				// A new server consumes the caller's persisted preconditions.
				e = newEnvOn(t, b, &now)
				out, err := e.mfa.EnableMfaDevice(t.Context(), req)
				if code == codes.OK {
					if err != nil || !mfaStoredDevice(t, b).Object.Enabled {
						t.Fatalf("enable: %v, %v", out, err)
					}
					committed := mfaStoredDevice(t, b)
					e = newEnvOn(t, b, &now)
					_, err = e.mfa.EnableMfaDevice(t.Context(), req)
					if req.UserEtag != "" {
						wantErr(t, err, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
					} else {
						wantErr(t, err, codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists")
					}
					if !reflect.DeepEqual(committed, mfaStoredDevice(t, b)) {
						t.Fatal("successful enable replay changed device")
					}
					return
				}
				aws := "ConcurrentModification"
				if code == codes.InvalidArgument {
					aws = "ValidationError"
				}
				wantErr(t, err, code, reason, aws)
				if out != nil || !reflect.DeepEqual(before, mfaStoredDevice(t, b)) {
					t.Fatal("failed precondition changed device")
				}
				userAfter, err := store.Get[iam.User](t.Context(), sb, "alice")
				if err != nil || !reflect.DeepEqual(userBefore, userAfter) {
					t.Fatalf("failed precondition changed user: %v", err)
				}
			})
		}
	}
}

func TestEnableMFAPreconditionsBeforeCommit(t *testing.T) {
	for _, bc := range renameBackends {
		for _, change := range []string{"move", "replace"} {
			t.Run(bc.name+"/"+change, func(t *testing.T) {
				h := &hooked{Backend: bc.open()}
				now := time.Now().UTC()
				e := newEnvOn(t, h, &now)
				u := e.createUser(t, t.Context(), "alice")
				req := mfaEnableRequest(t, e, u)
				before := mfaStoredDevice(t, h)
				fired := false
				h.at("update", iam.KindMfaDevice, "phone", func() error {
					fired = true
					other := newEnvOn(t, h.Backend, &now)
					if change == "move" {
						other.updateUserPath(t, u.GetName(), "/moved/")
					} else {
						replaceMFAUser(t, h.Backend)
					}
					return nil
				})
				_, err := e.mfa.EnableMfaDevice(t.Context(), req)
				wantErr(t, err, codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification")
				if !fired || !reflect.DeepEqual(before, mfaStoredDevice(t, h)) {
					t.Fatal("conditional enable did not preserve the unassigned device")
				}
			})
		}
	}
}

func TestEnableMFAPreconditionsRestartAndReplay(t *testing.T) {
	for _, bc := range renameBackends {
		for _, lost := range []bool{false, true} {
			name := bc.name + "/before-write"
			if lost {
				name = bc.name + "/lost-response"
			}
			t.Run(name, func(t *testing.T) {
				c := &crashing{Backend: bc.open()}
				now := time.Now().UTC()
				e := newEnvOn(t, c, &now)
				u := e.createUser(t, t.Context(), "alice")
				req := mfaEnableRequest(t, e, u)
				before := mfaStoredDevice(t, c)
				// Lease, slot claim, then the atomic device write.
				c.arm(3, lost)
				if _, err := e.mfa.EnableMfaDevice(t.Context(), req); err == nil {
					t.Fatal("interrupted enable succeeded")
				}
				if !c.revive() {
					t.Fatal("enable never reached the device commit")
				}
				committed := mfaStoredDevice(t, c)
				if committed.Object.Enabled != lost || (!lost && !reflect.DeepEqual(before, committed)) {
					t.Fatal("interruption did not preserve atomic device state")
				}
				now = now.Add(11 * time.Second) // persisted lease expires across restart
				e = newEnvOn(t, c, &now)
				_, err := e.mfa.EnableMfaDevice(t.Context(), req)
				wantErr(t, err, codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification")
				if !reflect.DeepEqual(committed, mfaStoredDevice(t, c)) {
					t.Fatal("replay changed committed device state")
				}
			})
		}
	}
}
