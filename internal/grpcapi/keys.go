package grpcapi

import (
	"context"
	"errors"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func keyName(project, user, id string) string {
	return name(project, "users", user) + "/accessKeys/" + id
}

// checkExpectedUserPath enforces the optional precondition on an access key
// write: the key's parent user resource name must be expected. A mismatch is
// a concurrent change of the caller's user binding, so nothing is written.
func checkExpectedUserPath(expected, project string, k iam.AccessKey) error {
	if expected == "" {
		return nil
	}
	pid, user, err := child(expected, "users")
	if err != nil {
		return err
	}
	if err := checkID(user, "user"); err != nil {
		return err
	}
	if pid != project || store.Fold(user) != store.Fold(k.UserName) {
		return fail(codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification",
			"the access key's parent user does not match expected_user_path")
	}
	return nil
}

// errUserARNMismatch is the expected_user_arn mismatch: the parent user's
// ARN changed, for example by an UpdateUser path move, after the caller
// authorized against it.
func errUserARNMismatch() error {
	return fail(codes.Aborted, "GENERATION_CONFLICT", "ConcurrentModification",
		"the access key's parent user ARN does not match expected_user_arn")
}

// parseExpectedUserARN validates the optional expected_user_arn. An empty
// value means no check.
func parseExpectedUserARN(expected string) (account, path, user string, err error) {
	if expected == "" {
		return "", "", "", nil
	}
	account, path, user, ok := iam.SplitUserARN(expected)
	if !ok {
		msg := "expected_user_arn " + quote(expected) + " is not arn:vws:iam::{project}:user{path}{user}"
		return "", "", "", invalidID(msg)
	}
	return account, path, user, nil
}

// checkExpectedUserARN enforces the optional expected_user_arn precondition
// on an access key write. It reads the key's parent user and compares its
// current ARN, which contains the IAM path, so a user that UpdateUser moved
// to another path no longer matches. Callers run it after the key read and
// before the compare-and-swap write guarded by that read, so a retry after a
// key conflict reads the user again and a refused check writes nothing.
// Writes that change state also hold withUserARNLease, which keeps a path
// move from committing between this read and the key write.
func checkExpectedUserARN(ctx context.Context, b store.Backend, expected, project string, k iam.AccessKey) error {
	if expected == "" {
		return nil
	}
	account, path, user, err := parseExpectedUserARN(expected)
	if err != nil {
		return err
	}
	if account != project || store.Fold(user) != store.Fold(k.UserName) {
		return errUserARNMismatch()
	}
	u, err := store.Get[iam.User](ctx, b, k.UserName)
	if errors.Is(err, store.ErrNotFound) {
		return errUserARNMismatch()
	}
	if err != nil {
		return err
	}
	if iam.UserARN(project, u.Object) != iam.UserARN(project, iam.User{Name: u.Object.Name, Path: path}) {
		return errUserARNMismatch()
	}
	return nil
}

func keyState(st iam.KeyStatus) iamv1.AccessKeyState {
	if st == iam.KeyActive {
		return iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE
	}
	return iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE
}

func (p project) keyProto(k iam.AccessKey, version string) *iamv1.AccessKey {
	return &iamv1.AccessKey{
		Name: keyName(p.id, k.UserName, k.ID), Uid: k.UID, Generation: k.Generation, Etag: version, Labels: labels(k.Labels),
		Spec: &iamv1.AccessKeySpec{State: keyState(k.Status)},
		Status: &iamv1.AccessKeyStatus{
			Observed: ready(k.Generation), LastUsedTime: ts(k.LastUsed),
			LastUsedService: k.LastUsedService, LastUsedRegion: k.LastUsedRegion,
		},
		CreateTime: ts(k.Created), UpdateTime: ts(k.Updated),
	}
}

func keyRef(s string) (project, user, id string, err error) {
	project, user, id, err = grandchild(s, "users", "accessKeys")
	if err == nil && !accessKeyID.MatchString(id) {
		err = invalidID("access key id " + quote(id))
	}
	return project, user, id, err
}

// GetAccessKey returns key metadata; the secret is never returned again.
func (s *Server) GetAccessKey(ctx context.Context, req *iamv1.GetAccessKeyRequest) (*iamv1.AccessKey, error) {
	pid, user, id, err := keyRef(req.GetName())
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	k, err := p.keys.Get(ctx, user, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return p.keyProto(k.Object, k.Version), nil
}

// ListAccessKeys lists a user's keys.
func (s *Server) ListAccessKeys(ctx context.Context, req *iamv1.ListAccessKeysRequest) (*iamv1.ListAccessKeysResponse, error) {
	pid, user, err := child(req.GetParent(), "users")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if _, err := store.Get[iam.User](ctx, p.b, user); err != nil {
		return nil, toStatus(ctx, err)
	}
	all, err := p.keys.List(ctx, user)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	items, next, err := page(all, func(k iam.AccessKey) string { return k.ID }, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListAccessKeysResponse{NextPageToken: next}
	for _, k := range items {
		out.AccessKeys = append(out.AccessKeys, p.keyProto(k, ""))
	}
	return out, nil
}

// CreateAccessKey returns the secret exactly once. It is not an operation
// and is never replayed: the secret is not stored anywhere in plaintext,
// so a lost response means creating another key (limit two per user).
func (s *Server) CreateAccessKey(ctx context.Context, req *iamv1.CreateAccessKeyRequest) (*iamv1.CreateAccessKeyResponse, error) {
	pid, user, err := child(req.GetParent(), "users")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	cred, err := p.keys.Create(ctx, user)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	k, err := p.keys.Get(ctx, cred.UserName, cred.AccessKeyID)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	return &iamv1.CreateAccessKeyResponse{AccessKey: p.keyProto(k.Object, k.Version), SecretAccessKey: cred.Secret}, nil
}

// UpdateAccessKey changes the state (Active/Inactive) or labels.
func (s *Server) UpdateAccessKey(ctx context.Context, req *iamv1.UpdateAccessKeyRequest) (*longrunningpb.Operation, error) {
	pid, user, id, err := keyRef(req.GetAccessKey().GetName())
	if err != nil {
		return nil, err
	}
	set, err := paths(req.GetUpdateMask(), "spec.state")
	if err != nil {
		return nil, err
	}
	if req.GetAllowMissing() {
		return nil, invalidSpec("allow_missing is not supported for access keys; use CreateAccessKey")
	}
	if _, _, _, err := parseExpectedUserARN(req.GetExpectedUserArn()); err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "UpdateAccessKey", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	if _, err := p.keys.Get(ctx, user, id); err != nil {
		return nil, toStatus(ctx, err)
	}
	var v store.Versioned[iam.AccessKey]
	lease := req.GetExpectedUserArn()
	if req.GetValidateOnly() {
		lease = ""
	}
	err = s.withUserARNLease(ctx, p.b, lease, pid, user, func(ctx context.Context) error {
		var err error
		bump := func(k *iam.AccessKey) { k.Generation++ }
		etag := req.GetAccessKey().GetEtag()
		v, err = mutateOrValidate(ctx, p.b, id, etag, req.GetValidateOnly(), false, bump, func(k *iam.AccessKey) error {
			if err := checkExpectedUserPath(req.GetExpectedUserPath(), pid, *k); err != nil {
				return err
			}
			if err := checkExpectedUserARN(ctx, p.b, req.GetExpectedUserArn(), pid, *k); err != nil {
				return err
			}
			if set["spec.state"] {
				switch req.GetAccessKey().GetSpec().GetState() {
				case iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE:
					k.Status = iam.KeyActive
				case iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE:
					k.Status = iam.KeyInactive
				default:
					return invalidSpec("spec.state must be ACTIVE or INACTIVE")
				}
			}
			if set["labels"] {
				k.Labels = req.GetAccessKey().GetLabels()
			}
			k.Updated = s.now().UTC()
			return nil
		}, nil)
		return err
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := p.keyProto(v.Object, v.Version)
	op, err := s.done(ctx, opArgs{project: pid, method: "UpdateAccessKey", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// DeleteAccessKey deletes a key and its index entry.
func (s *Server) DeleteAccessKey(ctx context.Context, req *iamv1.DeleteAccessKeyRequest) (*longrunningpb.Operation, error) {
	pid, user, id, err := keyRef(req.GetName())
	if err != nil {
		return nil, err
	}
	if _, _, _, err := parseExpectedUserARN(req.GetExpectedUserArn()); err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "DeleteAccessKey", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	resp := &iamv1.AccessKey{Name: req.GetName()}
	var gen int64
	k, err := p.keys.Get(ctx, user, id)
	switch {
	case errors.Is(err, store.ErrNotFound) && req.GetAllowMissing():
	case err != nil:
		return nil, toStatus(ctx, err)
	default:
		if err := checkEtag(req.GetEtag(), k.Version); err != nil {
			return nil, err
		}
		if err := s.withUserARNLease(ctx, p.b, req.GetExpectedUserArn(), pid, user, func(ctx context.Context) error {
			return p.keys.Delete(ctx, user, id, func(k iam.AccessKey) error {
				if err := checkExpectedUserPath(req.GetExpectedUserPath(), pid, k); err != nil {
					return err
				}
				return checkExpectedUserARN(ctx, p.b, req.GetExpectedUserArn(), pid, k)
			})
		}); err != nil {
			return nil, toStatus(ctx, err)
		}
		resp = p.keyProto(k.Object, k.Version)
		resp.DeleteTime = timestamppb.New(s.now())
		gen = k.Object.Generation
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "DeleteAccessKey", requestID: req.GetRequestId(), req: req, resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE, generation: gen, response: resp})
	return op, toStatus(ctx, err)
}
