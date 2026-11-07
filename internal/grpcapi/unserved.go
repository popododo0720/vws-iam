package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// RPCs vws-proto carries that this server does not serve yet. Each answers
// UNIMPLEMENTED, as before vws-proto had it, and changes nothing.

// PutRolePermissionsBoundary is not served yet.
//
// TODO(#100): serve it through putRolePermissionsBoundary.
func (s *Server) PutRolePermissionsBoundary(
	context.Context, *iamv1.PutRolePermissionsBoundaryRequest,
) (*iamv1.PutRolePermissionsBoundaryResponse, error) {
	return nil, status.Error(codes.Unimplemented, "PutRolePermissionsBoundary is not served yet")
}

// ResyncMfaDevice is not served yet.
//
// TODO(#102): serve it through resyncMfaDevice.
func (s *Server) ResyncMfaDevice(
	context.Context, *iamv1.ResyncMfaDeviceRequest,
) (*iamv1.ResyncMfaDeviceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ResyncMfaDevice is not served yet")
}

// GetAccessKeyInfo is not served yet.
//
// TODO(#108): serve it through getAccessKeyInfo, with the request's
// source_ip as the console-path address.
func (s *Server) GetAccessKeyInfo(
	context.Context, *iamv1.GetAccessKeyInfoRequest,
) (*iamv1.GetAccessKeyInfoResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GetAccessKeyInfo is not served yet")
}

// unservedField answers UNIMPLEMENTED for a request field vws-proto
// carries that this server does not honor yet, so the request is refused
// before any write and never served as if the field were unset.
func unservedField(field string) error {
	return status.Error(codes.Unimplemented, field+" is not served yet")
}
