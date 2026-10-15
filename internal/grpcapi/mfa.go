package grpcapi

import (
	"context"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
)

func (p project) mfaProto(d iam.MfaDevice, version string) *iamv1.MfaDevice {
	user := ""
	if d.Enabled {
		user = name(p.id, "users", d.UserName)
	}
	return &iamv1.MfaDevice{
		Name: name(p.id, "mfaDevices", d.Name), Uid: d.UID, Generation: d.Generation, Etag: version, Labels: labels(d.Labels),
		Spec:       &iamv1.MfaDeviceSpec{Path: defaultPath(d.Path)},
		Status:     p.mfaStatus(d, user),
		CreateTime: ts(d.Created), UpdateTime: ts(d.Updated),
	}
}

// mfaStatus reports the lockout state of internal/mfa: failed_attempts
// as stored (reset to 0 when the device locks), locked_until only while
// the lockout runs (vws-proto#32). These are admin fields: MfaDevice
// calls are authorized by console-api before they reach this service.
func (p project) mfaStatus(d iam.MfaDevice, user string) *iamv1.MfaDeviceStatus {
	st := &iamv1.MfaDeviceStatus{
		Observed: ready(d.Generation), SerialNumber: p.mfa.Serial(d.Name), User: user, EnableTime: ts(d.EnableTime),
		FailedAttempts: int32(min(d.FailedAttempts, mfa.MaxFailedAttempts)),
	} //nolint:gosec // bounded by MaxFailedAttempts
	if p.now().Before(d.LockedUntil) {
		st.LockedUntil = ts(d.LockedUntil)
	}
	return st
}

func (p project) mfaGet(ctx context.Context, id string) (*iamv1.MfaDevice, error) {
	v, err := store.Get[iam.MfaDevice](ctx, p.b, id)
	if err != nil {
		return nil, err
	}
	return p.mfaProto(v.Object, v.Version), nil
}

// GetMfaDevice returns a device; the seed is never returned again.
func (s *Server) GetMfaDevice(ctx context.Context, req *iamv1.GetMfaDeviceRequest) (*iamv1.MfaDevice, error) {
	pid, id, err := child(req.GetName(), "mfaDevices")
	if err != nil {
		return nil, err
	}
	out, err := s.project(pid).mfaGet(ctx, id)
	return out, toStatus(ctx, err)
}

// ListMfaDevices lists every device of a project, assigned or not.
func (s *Server) ListMfaDevices(ctx context.Context, req *iamv1.ListMfaDevicesRequest) (*iamv1.ListMfaDevicesResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	all, err := store.List[iam.MfaDevice](ctx, p.b)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	items, next, err := page(all, func(v store.Versioned[iam.MfaDevice]) string { return v.Object.Name }, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListMfaDevicesResponse{NextPageToken: next}
	for _, v := range items {
		out.MfaDevices = append(out.MfaDevices, p.mfaProto(v.Object, v.Version))
	}
	return out, nil
}

// CreateVirtualMfaDevice returns the seed exactly once. Not an operation.
func (s *Server) CreateVirtualMfaDevice(ctx context.Context, req *iamv1.CreateVirtualMfaDeviceRequest) (*iamv1.CreateVirtualMfaDeviceResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	if err := checkID(req.GetMfaDeviceId(), "mfa device"); err != nil {
		return nil, err
	}
	p := s.project(pid)
	enr, err := p.mfa.CreateVirtual(ctx, req.GetMfaDeviceId())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	d, err := store.Mutate(ctx, p.b, req.GetMfaDeviceId(), func(d *iam.MfaDevice) error {
		d.UID, d.Generation, d.Labels, d.Path = iam.NewUID(), 1, req.GetMfaDevice().GetLabels(), req.GetMfaDevice().GetSpec().GetPath()
		return d.Validate()
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &iamv1.CreateVirtualMfaDeviceResponse{MfaDevice: p.mfaProto(d, ""), Base32StringSeed: enr.Base32Seed, OtpauthUri: enr.URI}, nil
}

func userRef(project, s string) (string, error) {
	proj, user, err := child(s, "users")
	if err != nil {
		return "", err
	}
	if proj != project {
		return "", invalidSpec("user " + quote(s) + " is in another project")
	}
	return user, nil
}

// EnableMfaDevice assigns a device after two consecutive codes.
func (s *Server) EnableMfaDevice(ctx context.Context, req *iamv1.EnableMfaDeviceRequest) (*iamv1.EnableMfaDeviceResponse, error) {
	pid, id, err := child(req.GetName(), "mfaDevices")
	if err != nil {
		return nil, err
	}
	user, err := userRef(pid, req.GetUser())
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if err := p.mfa.Enable(ctx, user, id, req.GetAuthenticationCode_1(), req.GetAuthenticationCode_2()); err != nil {
		return nil, toStatus(ctx, err)
	}
	out, err := p.mfaGet(ctx, id)
	return &iamv1.EnableMfaDeviceResponse{MfaDevice: out}, toStatus(ctx, err)
}

// DeactivateMfaDevice unassigns a device from its user.
func (s *Server) DeactivateMfaDevice(ctx context.Context, req *iamv1.DeactivateMfaDeviceRequest) (*iamv1.DeactivateMfaDeviceResponse, error) {
	pid, id, err := child(req.GetName(), "mfaDevices")
	if err != nil {
		return nil, err
	}
	user, err := userRef(pid, req.GetUser())
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if err := p.mfa.Deactivate(ctx, user, id); err != nil {
		return nil, toStatus(ctx, err)
	}
	out, err := p.mfaGet(ctx, id)
	return &iamv1.DeactivateMfaDeviceResponse{MfaDevice: out}, toStatus(ctx, err)
}

// DeleteMfaDevice deletes an unassigned device (AWS DeleteConflict otherwise).
func (s *Server) DeleteMfaDevice(ctx context.Context, req *iamv1.DeleteMfaDeviceRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "mfaDevices")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "DeleteMfaDevice", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	v, _, err := remove(ctx, p.b, id, req.GetEtag(), req.GetAllowMissing(), func(d iam.MfaDevice) error {
		if d.Enabled {
			return deleteConflict("mfa device is enabled for a user")
		}
		return nil
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := &iamv1.MfaDevice{Name: req.GetName()}
	if v.Object.Name != "" {
		resp = p.mfaProto(v.Object, v.Version)
		resp.DeleteTime = timestamppb.New(s.now())
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "DeleteMfaDevice", requestID: req.GetRequestId(), req: req, resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE, generation: v.Object.Generation, response: resp})
	return op, toStatus(ctx, err)
}
