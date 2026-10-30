package grpcapi

import (
	"context"
	"errors"
	"fmt"

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

// keyGuard holds the optional preconditions of an access key write
// (vws-proto v0.7.0): expected_user_path, the AIP-122 name of the parent
// user, which never changes, and expected_user_arn, the parent user's ARN,
// which changes when UpdateUser moves the user to another IAM path.
type keyGuard struct {
	project string
	// pathProject and pathUser are expected_user_path parsed; pathSet
	// tells whether it was given.
	pathSet               bool
	pathProject, pathUser string
	// arn is expected_user_arn as given and arnProject, arnPath, arnUser
	// its parts.
	arn                          string
	arnProject, arnPath, arnUser string
	// userEtag is the parent user's version the caller read (#139).
	userEtag string
}

// newKeyGuard parses the preconditions. An empty value means no check.
func newKeyGuard(project, expectedPath, expectedARN, userEtag string) (keyGuard, error) {
	if err := checkUserEtag(userEtag); err != nil {
		return keyGuard{}, err
	}
	g := keyGuard{project: project, arn: expectedARN, userEtag: userEtag}
	if expectedPath != "" {
		pid, user, err := child(expectedPath, "users")
		if err != nil {
			return g, err
		}
		if err := checkID(user, "user"); err != nil {
			return g, err
		}
		g.pathSet, g.pathProject, g.pathUser = true, pid, user
	}
	if expectedARN != "" {
		account, path, user, ok := iam.SplitUserARN(expectedARN)
		if !ok {
			return g, invalidID("expected_user_arn " + quote(expectedARN) + " is not arn:vws:iam::{project}:user{path}{user}")
		}
		g.arnProject, g.arnPath, g.arnUser = account, path, user
	}
	return g, nil
}

// maxEtagLen bounds a user_etag. Store versions are short (a decimal
// counter or a Kubernetes resourceVersion).
const maxEtagLen = 128

// checkUserEtag rejects a user_etag no store version can equal.
func checkUserEtag(etag string) error {
	if len(etag) > maxEtagLen {
		return invalidSpec(fmt.Sprintf("user_etag must be at most %d characters", maxEtagLen))
	}
	for _, r := range etag {
		if r <= ' ' || r > '~' {
			return invalidSpec("user_etag must be printable ASCII without spaces")
		}
	}
	return nil
}

// fenced reports whether a write under g must commit on the parent user's
// read version.
func (g keyGuard) fenced() bool { return g.arn != "" || g.userEtag != "" }

// userMismatch is a precondition that does not hold when it is checked.
func userMismatch(field string) error {
	return fail(codes.FailedPrecondition, "GENERATION_CONFLICT", "ConcurrentModification",
		"the access key's parent user does not match "+field)
}

// check runs the preconditions on k, the key as read for the write. With
// expected_user_arn or a user etag it reads the parent user, compares its
// current ARN and version, and returns the precondition that the user is
// still at the version it read. The caller commits the key write with store.UpdateIf or DeleteIf
// under it, so an UpdateUser path move that lands after this read makes
// the write fail with ErrConflict (ABORTED, ConcurrentModification) and
// change nothing. A user etag that is not the user's version is ABORTED.
// Without either, ok is false: no precondition.
func (g keyGuard) check(ctx context.Context, b store.Backend, k iam.AccessKey) (pre store.Pre, ok bool, err error) {
	if g.pathSet && (g.pathProject != g.project || store.Fold(g.pathUser) != store.Fold(k.UserName)) {
		return pre, false, userMismatch("expected_user_path")
	}
	if !g.fenced() {
		return pre, false, nil
	}
	if g.arn != "" && (g.arnProject != g.project || store.Fold(g.arnUser) != store.Fold(k.UserName)) {
		return pre, false, userMismatch("expected_user_arn")
	}
	u, err := store.Get[iam.User](ctx, b, k.UserName)
	switch {
	case errors.Is(err, store.ErrNotFound) && g.arn != "":
		return pre, false, userMismatch("expected_user_arn")
	case errors.Is(err, store.ErrNotFound):
		return pre, false, userEtagMismatch()
	case err != nil:
		return pre, false, err
	}
	// The name folds like every IAM name; the path is compared exactly.
	want := iam.User{Name: u.Object.Name, Path: g.arnPath}
	if g.arn != "" && iam.UserARN(g.project, u.Object) != iam.UserARN(g.project, want) {
		return pre, false, userMismatch("expected_user_arn")
	}
	if g.userEtag != "" && u.Version != g.userEtag {
		return pre, false, userEtagMismatch()
	}
	return store.PreOf(u), true, nil
}

// updateKeyIf is update for an access key write under a fenced keyGuard:
// the user check and the key write commit together through store.UpdateIf.
// A lost race is not retried: the caller authorized against the ARN it
// sent, so a concurrent change of the user is ConcurrentModification.
func updateKeyIf(
	ctx context.Context, b store.Backend, id, etag string, g keyGuard, fn func(*iam.AccessKey) error,
) (store.Versioned[iam.AccessKey], error) {
	cur, err := store.Get[iam.AccessKey](ctx, b, id)
	if err != nil {
		return cur, err
	}
	if err := checkEtag(etag, cur.Version); err != nil {
		return cur, err
	}
	pre, _, err := g.check(ctx, b, cur.Object)
	if err != nil {
		return cur, err
	}
	if err := fn(&cur.Object); err != nil {
		return cur, err
	}
	cur.Object.Generation++
	v, err := store.UpdateIf(ctx, b, cur.Object, cur.Version, pre)
	if err != nil {
		return cur, err
	}
	cur.Version = v
	return cur, nil
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
// and is never replayed: the secret is not stored anywhere in plaintext.
// A request_id is stored with the key it creates; while that key exists, a
// repeat for the same user is ALREADY_EXISTS naming the key, without the
// secret (vws-proto: after a lost response, delete the key and create
// another). An empty request_id makes every call a new key.
func (s *Server) CreateAccessKey(ctx context.Context, req *iamv1.CreateAccessKeyRequest) (*iamv1.CreateAccessKeyResponse, error) {
	// TODO(#139): pass req.GetUserEtag() once vws-proto has the field.
	return s.createAccessKey(ctx, req, "")
}

// createAccessKey is CreateAccessKey with the optional user etag (#139):
// when not empty, the key is created only while the parent user is at
// that version, else ABORTED and no key is created.
func (s *Server) createAccessKey(
	ctx context.Context, req *iamv1.CreateAccessKeyRequest, userEtag string,
) (*iamv1.CreateAccessKeyResponse, error) {
	pid, user, err := child(req.GetParent(), "users")
	if err != nil {
		return nil, err
	}
	rid := req.GetRequestId()
	if rid != "" && !iam.ValidRequestID(rid) {
		return nil, invalidSpec(fmt.Sprintf("request_id must be 1 to %d characters of [A-Za-z0-9_-]", iam.MaxRequestIDLen))
	}
	if err := checkUserEtag(userEtag); err != nil {
		return nil, err
	}
	p := s.project(pid)
	cred, err := p.createKey(ctx, user, rid, userEtag)
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
	g, err := newKeyGuard(pid, req.GetExpectedUserPath(), req.GetExpectedUserArn(), "")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "UpdateAccessKey", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	if _, err := p.keys.Get(ctx, user, id); err != nil {
		return nil, toStatus(ctx, err)
	}
	apply := func(k *iam.AccessKey) error {
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
	}
	etag := req.GetAccessKey().GetEtag()
	var v store.Versioned[iam.AccessKey]
	if g.fenced() && !req.GetValidateOnly() {
		v, err = updateKeyIf(ctx, p.b, id, etag, g, apply)
	} else {
		bump := func(k *iam.AccessKey) { k.Generation++ }
		v, err = mutateOrValidate(ctx, p.b, id, etag, req.GetValidateOnly(), false, bump, func(k *iam.AccessKey) error {
			if _, _, err := g.check(ctx, p.b, *k); err != nil {
				return err
			}
			return apply(k)
		}, nil)
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := p.keyProto(v.Object, v.Version)
	op, err := s.done(ctx, opArgs{project: pid, method: "UpdateAccessKey", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// DeleteAccessKey deletes a key and its index entry.
func (s *Server) DeleteAccessKey(ctx context.Context, req *iamv1.DeleteAccessKeyRequest) (*longrunningpb.Operation, error) {
	// TODO(#139): pass req.GetUserEtag() once vws-proto has the field.
	return s.deleteAccessKey(ctx, req, "")
}

// deleteAccessKey is DeleteAccessKey with the optional user etag (#139):
// when not empty, the key is deleted only while the parent user is at that
// version, else ABORTED and the key stays.
func (s *Server) deleteAccessKey(
	ctx context.Context, req *iamv1.DeleteAccessKeyRequest, userEtag string,
) (*longrunningpb.Operation, error) {
	pid, user, id, err := keyRef(req.GetName())
	if err != nil {
		return nil, err
	}
	g, err := newKeyGuard(pid, req.GetExpectedUserPath(), req.GetExpectedUserArn(), userEtag)
	if err != nil {
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
		check := func(k iam.AccessKey) (store.Pre, bool, error) { return g.check(ctx, p.b, k) }
		if err := p.keys.DeleteChecked(ctx, user, id, check); err != nil {
			return nil, toStatus(ctx, err)
		}
		resp = p.keyProto(k.Object, k.Version)
		resp.DeleteTime = timestamppb.New(s.now())
		gen = k.Object.Generation
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "DeleteAccessKey", requestID: req.GetRequestId(), req: req, resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE, generation: gen, response: resp})
	return op, toStatus(ctx, err)
}
