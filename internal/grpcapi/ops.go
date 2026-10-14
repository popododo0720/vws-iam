package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// IAM has no reconciler: every operation is returned done, and recorded
// so GetOperation and a request_id replay return it again. Secret-bearing
// RPCs never produce an operation.

// opID is deterministic for a request id, random otherwise.
func opID(project, method, requestID string) string {
	if requestID == "" {
		return "op-" + strings.ReplaceAll(iam.NewUID(), "-", "")
	}
	h := sha256.Sum256([]byte(project + "\x00" + method + "\x00" + requestID))
	return "rq-" + hex.EncodeToString(h[:16])
}

func fingerprint(req proto.Message) string {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(req)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// replay returns the recorded operation of a request id, IDEMPOTENCY_CONFLICT
// when the same id came with a different request, or nil.
func (s *Server) replay(ctx context.Context, project, method, requestID string, req proto.Message) (*longrunningpb.Operation, error) {
	if requestID == "" {
		return nil, nil //nolint:nilnil // no request id: nothing to replay
	}
	rec, err := store.Get[iam.Operation](ctx, s.b, opID(project, method, requestID))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil //nolint:nilnil // first time this request id is seen
	}
	if err != nil {
		return nil, err
	}
	if rec.Object.Fingerprint != fingerprint(req) {
		return nil, fail(codes.Aborted, "IDEMPOTENCY_CONFLICT", "IdempotentParameterMismatch", "request_id was used with a different request")
	}
	op := &longrunningpb.Operation{}
	if err := proto.Unmarshal(rec.Object.Response, op); err != nil {
		return nil, fmt.Errorf("stored operation: %w", err)
	}
	return op, nil
}

type opArgs struct {
	project, method, requestID string
	req                        proto.Message
	resource                   string
	verb                       commonv1.OperationVerb
	generation                 int64
	response                   proto.Message
	validateOnly               bool
}

// done builds the finished operation and records it, unless validate_only.
func (s *Server) done(ctx context.Context, a opArgs) (*longrunningpb.Operation, error) {
	now := timestamppb.New(s.now())
	id := opID(a.project, a.method, a.requestID)
	md, err := anypb.New(&commonv1.OperationMetadata{Resource: a.resource, Verb: a.verb, Generation: a.generation, RequestId: a.requestID, CreateTime: now, EndTime: now})
	if err != nil {
		return nil, fmt.Errorf("operation metadata: %w", err)
	}
	resp, err := anypb.New(a.response)
	if err != nil {
		return nil, fmt.Errorf("operation response: %w", err)
	}
	op := &longrunningpb.Operation{Name: "projects/" + a.project + "/operations/" + id, Metadata: md, Done: true, Result: &longrunningpb.Operation_Response{Response: resp}}
	if a.validateOnly {
		return op, nil
	}
	b, err := proto.Marshal(op)
	if err != nil {
		return nil, fmt.Errorf("operation: %w", err)
	}
	rec := iam.Operation{ID: id, Project: a.project, RequestID: a.requestID, Fingerprint: fingerprint(a.req), Response: b, Created: s.now().UTC()}
	if _, err := store.Create(ctx, s.b, rec); err != nil && !errors.Is(err, store.ErrExists) {
		return nil, err
	}
	return op, nil
}

// GetOperation returns a recorded IAM operation.
func (s *Server) GetOperation(ctx context.Context, req *longrunningpb.GetOperationRequest) (*longrunningpb.Operation, error) {
	project, id, err := child(req.GetName(), "operations")
	if err != nil {
		return nil, err
	}
	rec, err := store.Get[iam.Operation](ctx, s.b, id)
	if err != nil || rec.Object.Project != project {
		return nil, toStatus(ctx, notFound("operation "+quote(req.GetName())))
	}
	op := &longrunningpb.Operation{}
	if err := proto.Unmarshal(rec.Object.Response, op); err != nil {
		return nil, toStatus(ctx, err)
	}
	return op, nil
}

// WaitOperation returns at once: IAM operations are always done.
func (s *Server) WaitOperation(ctx context.Context, req *longrunningpb.WaitOperationRequest) (*longrunningpb.Operation, error) {
	return s.GetOperation(ctx, &longrunningpb.GetOperationRequest{Name: req.GetName()})
}
