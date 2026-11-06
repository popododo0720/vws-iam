package grpcapi

import (
	"context"
	"errors"
	"regexp"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
)

// ResyncMFADeviceRequest is the input of IAM ResyncMFADevice. The codes
// are secrets: never log them.
type ResyncMFADeviceRequest struct {
	UserName            string
	SerialNumber        string
	AuthenticationCode1 string
	AuthenticationCode2 string
}

// String hides the codes.
func (r ResyncMFADeviceRequest) String() string {
	return "ResyncMFADeviceRequest{" + r.UserName + " " + r.SerialNumber + " codes=REDACTED}"
}

var (
	// resyncUserRE and resyncSerialRE are the AWS patterns of UserName
	// and SerialNumber; authCodeRE is that of an AuthenticationCode with
	// its fixed length of 6.
	resyncUserRE   = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)
	resyncSerialRE = regexp.MustCompile(`^[\w+=/:,.@-]{9,256}$`)
	authCodeRE     = regexp.MustCompile(`^[0-9]{6}$`)
)

// checkResyncRequest checks the AWS length and pattern constraints of
// req (ValidationError). The messages never contain a code.
func checkResyncRequest(req ResyncMFADeviceRequest) error {
	switch {
	case !resyncUserRE.MatchString(req.UserName):
		return invalidSpec("userName must be 1 to 128 characters of [\\w+=,.@-]")
	case !resyncSerialRE.MatchString(req.SerialNumber):
		return invalidSpec("serialNumber must be 9 to 256 characters of [\\w+=/:,.@-]")
	case !authCodeRE.MatchString(req.AuthenticationCode1):
		return invalidSpec("authenticationCode1 must be a sequence of six digits")
	case !authCodeRE.MatchString(req.AuthenticationCode2):
		return invalidSpec("authenticationCode2 must be a sequence of six digits")
	}
	return nil
}

// resyncMfaDevice is IAM ResyncMFADevice: it resynchronizes the virtual
// MFA device SerialNumber of user UserName in project pid from two
// consecutive codes (mfa.Service.Resync) and stores the device's clock
// drift. An unknown user, or a serial that is not a device enabled for
// that user, is NoSuchEntity; a pair that is wrong, outside the window
// or already used is InvalidAuthenticationCode and counts towards the
// device lockout (AccessDenied while locked); a write that keeps losing
// to concurrent writes is ConcurrentModification. Authorization
// (iam:ResyncMFADevice) is console-api's, as for EnableMFADevice.
//
// TODO(#102): serve this as MfaDeviceService.ResyncMfaDevice, which
// vws-proto v0.9.0 carries and unserved.go answers UNIMPLEMENTED.
func (s *Server) resyncMfaDevice(ctx context.Context, pid string, req ResyncMFADeviceRequest) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	if err := checkResyncRequest(req); err != nil {
		return err
	}
	noUser := notFound("The user with name " + req.UserName + " cannot be found.")
	if !iam.ValidName(req.UserName) { // longer than any stored user name
		return noUser
	}
	p := s.project(pid)
	u, err := store.Get[iam.User](ctx, p.b, req.UserName)
	if errors.Is(err, store.ErrNotFound) {
		return noUser
	}
	if err != nil {
		return toStatus(ctx, err)
	}
	err = p.mfa.Resync(ctx, u.Object.Name, req.SerialNumber, req.AuthenticationCode1, req.AuthenticationCode2)
	if errors.Is(err, mfa.ErrNotAssociated) || errors.Is(err, store.ErrNotFound) {
		return notFound("MFA device " + req.SerialNumber + " is not enabled for user " + u.Object.Name + ".")
	}
	return toStatus(ctx, err)
}
