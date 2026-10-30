package grpcapi

import (
	"context"
	"errors"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/password"
	"github.com/popododo0720/vws-iam/internal/store"
)

type userExtras struct {
	groups map[string][]string
	mfa    map[string][]string
}

func (p project) extras(ctx context.Context) (userExtras, error) {
	x := userExtras{groups: map[string][]string{}, mfa: map[string][]string{}}
	gs, err := store.List[iam.Group](ctx, p.b)
	if err != nil {
		return x, err
	}
	for _, g := range gs {
		for _, m := range g.Object.Members {
			x.groups[store.Fold(m)] = append(x.groups[store.Fold(m)], name(p.id, "groups", g.Object.Name))
		}
	}
	ds, err := p.mfa.List(ctx, "")
	if err != nil {
		return x, err
	}
	for _, d := range ds {
		if d.Enabled {
			x.mfa[store.Fold(d.UserName)] = append(x.mfa[store.Fold(d.UserName)], p.mfa.Serial(d))
		}
	}
	return x, nil
}

func (p project) userProto(v store.Versioned[iam.User], x userExtras) *iamv1.User {
	u := v.Object
	return &iamv1.User{
		Name: name(p.id, "users", u.Name), Uid: u.UID, Generation: u.Generation, Etag: v.Version, Labels: labels(u.Labels),
		Spec: &iamv1.UserSpec{Path: defaultPath(u.Path), AttachedPolicies: p.policyNames(u.AttachedPolicies), InlinePolicies: u.InlinePolicies},
		Status: &iamv1.UserStatus{
			Observed: ready(u.Generation), Arn: iam.UserARN(p.id, u), UniqueId: u.ID,
			Groups: x.groups[store.Fold(u.Name)], LoginProfile: u.PasswordHash != "", PasswordResetRequired: u.PasswordResetRequired,
			PasswordLastUsedTime: ts(u.PasswordLastUsed), MfaDevices: x.mfa[store.Fold(u.Name)], SessionsRevokeTime: ts(u.SessionsRevokedBefore),
		},
		CreateTime: ts(u.Created), UpdateTime: ts(u.Updated),
	}
}

func (s *Server) userOne(ctx context.Context, p project, v store.Versioned[iam.User]) (*iamv1.User, error) {
	x, err := p.extras(ctx)
	if err != nil {
		return nil, err
	}
	return p.userProto(v, x), nil
}

func bumpUser(u *iam.User) { u.Generation++ }

// GetUser returns one user.
func (s *Server) GetUser(ctx context.Context, req *iamv1.GetUserRequest) (*iamv1.User, error) {
	pid, id, err := child(req.GetName(), "users")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	v, err := store.Get[iam.User](ctx, p.b, id)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	out, err := s.userOne(ctx, p, v)
	return out, toStatus(ctx, err)
}

// ListUsers pages through a project's users ordered by name.
func (s *Server) ListUsers(ctx context.Context, req *iamv1.ListUsersRequest) (*iamv1.ListUsersResponse, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	all, err := store.List[iam.User](ctx, p.b)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	items, next, err := page(all, func(v store.Versioned[iam.User]) string { return v.Object.Name }, req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	x, err := p.extras(ctx)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	out := &iamv1.ListUsersResponse{NextPageToken: next}
	for _, v := range items {
		out.Users = append(out.Users, p.userProto(v, x))
	}
	return out, nil
}

func (p project) userSpec(ctx context.Context, u *iam.User, spec *iamv1.UserSpec, set map[string]bool) error {
	if set["spec.path"] {
		u.Path = spec.GetPath()
	}
	if set["spec.attached_policies"] {
		arns, err := p.attachedARNs(ctx, spec.GetAttachedPolicies())
		if err != nil {
			return err
		}
		u.AttachedPolicies = arns
	}
	if set["spec.inline_policies"] {
		if err := checkInline("user", u.Name, maxInlineUser, spec.GetInlinePolicies()); err != nil {
			return err
		}
		u.InlinePolicies = spec.GetInlinePolicies()
	}
	return nil
}

var userPaths = []string{"spec.path", "spec.attached_policies", "spec.inline_policies"}

func allPaths(ps []string) map[string]bool {
	m := map[string]bool{"labels": true}
	for _, p := range ps {
		m[p] = true
	}
	return m
}

// CreateUser creates a user and returns a done operation.
func (s *Server) CreateUser(ctx context.Context, req *iamv1.CreateUserRequest) (*longrunningpb.Operation, error) {
	pid, err := parent(req.GetParent())
	if err != nil {
		return nil, err
	}
	if err := checkID(req.GetUserId(), "user"); err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "CreateUser", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	now := s.now().UTC()
	u := iam.User{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1, Labels: req.GetUser().GetLabels(), RequestID: req.GetRequestId()}, Name: req.GetUserId(), ID: iam.NewUniqueID("AIDA"), Created: now}
	if err := p.userSpec(ctx, &u, req.GetUser().GetSpec(), allPaths(userPaths)); err != nil {
		return nil, toStatus(ctx, err)
	}
	if err := u.Validate(); err != nil {
		return nil, toStatus(ctx, err)
	}
	var v store.Versioned[iam.User]
	if !req.GetValidateOnly() {
		ver, err := store.Create(ctx, p.b, u)
		if err != nil {
			cur, gerr := store.Get[iam.User](ctx, p.b, u.Name)
			if gerr != nil || adopt(req.GetRequestId(), cur.Object.Meta, err) != nil {
				return nil, toStatus(ctx, err)
			}
			u, ver = cur.Object, cur.Version
		}
		v = store.Versioned[iam.User]{Object: u, Version: ver}
	} else {
		v.Object = u
	}
	resp, err := s.userOne(ctx, p, v)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "CreateUser", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_CREATE, generation: u.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// UpdateUser changes spec and labels. The name cannot change.
func (s *Server) UpdateUser(ctx context.Context, req *iamv1.UpdateUserRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetUser().GetName(), "users")
	if err != nil {
		return nil, err
	}
	set, err := paths(req.GetUpdateMask(), userPaths...)
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "UpdateUser", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	apply := func(u *iam.User) error {
		if err := p.userSpec(ctx, u, req.GetUser().GetSpec(), set); err != nil {
			return err
		}
		if set["labels"] {
			u.Labels = req.GetUser().GetLabels()
		}
		u.Updated = s.now().UTC()
		return u.Validate()
	}
	var v store.Versioned[iam.User]
	if req.GetValidateOnly() {
		v, err = store.Get[iam.User](ctx, p.b, id)
		if err == nil {
			err = apply(&v.Object)
		}
	} else {
		v, _, err = update(ctx, p.b, id, req.GetUser().GetEtag(), req.GetAllowMissing(), bumpUser, apply, func() (iam.User, error) {
			u := iam.User{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: id, ID: iam.NewUniqueID("AIDA"), Created: s.now().UTC()}
			if err := checkID(id, "user"); err != nil {
				return u, err
			}
			return u, apply(&u)
		})
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp, err := s.userOne(ctx, p, v)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "UpdateUser", requestID: req.GetRequestId(), req: req, resource: resp.Name, verb: commonv1.OperationVerb_OPERATION_VERB_UPDATE, generation: v.Object.Generation, response: resp, validateOnly: req.GetValidateOnly()})
	return op, toStatus(ctx, err)
}

// DeleteUser deletes a user with nothing left attached (AWS DeleteConflict).
func (s *Server) DeleteUser(ctx context.Context, req *iamv1.DeleteUserRequest) (*longrunningpb.Operation, error) {
	pid, id, err := child(req.GetName(), "users")
	if err != nil {
		return nil, err
	}
	p := s.project(pid)
	if op, err := s.replay(ctx, pid, "DeleteUser", req.GetRequestId(), req); op != nil || err != nil {
		return op, toStatus(ctx, err)
	}
	var x userExtras
	v, _, err := remove(ctx, p.b, id, req.GetEtag(), req.GetAllowMissing(), func(u iam.User) error {
		keys, err := p.keys.List(ctx, u.Name)
		if err != nil {
			return err
		}
		if x, err = p.extras(ctx); err != nil {
			return err
		}
		fido, err := p.mfa.ListFido(ctx, u.Name)
		if err != nil {
			return err
		}
		switch {
		case len(keys) > 0:
			return deleteConflict("user has access keys")
		case len(x.mfa[store.Fold(u.Name)]) > 0:
			return deleteConflict("user has an enabled MFA device")
		case len(fido) > 0:
			return deleteConflict("user has a FIDO security key")
		case u.PasswordHash != "":
			return deleteConflict("user has a login profile")
		case len(x.groups[store.Fold(u.Name)]) > 0:
			return deleteConflict("user is a member of a group")
		case len(u.AttachedPolicies) > 0 || len(u.InlinePolicies) > 0:
			return deleteConflict("user has attached or inline policies")
		}
		return nil
	})
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	resp := &iamv1.User{Name: req.GetName()}
	if v.Object.Name != "" {
		resp = p.userProto(v, x)
		resp.DeleteTime = timestamppb.New(s.now())
	}
	op, err := s.done(ctx, opArgs{project: pid, method: "DeleteUser", requestID: req.GetRequestId(), req: req, resource: req.GetName(), verb: commonv1.OperationVerb_OPERATION_VERB_DELETE, generation: v.Object.Generation, response: resp})
	return op, toStatus(ctx, err)
}

func checkPassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < 8 || n > 128 {
		return invalidSpec("password must be 8 to 128 characters")
	}
	return nil
}

// SetLoginProfile sets the console password (argon2id at rest). Not an
// operation, so the password never reaches an operation record.
func (s *Server) SetLoginProfile(ctx context.Context, req *iamv1.SetLoginProfileRequest) (*iamv1.SetLoginProfileResponse, error) {
	pid, id, err := child(req.GetName(), "users")
	if err != nil {
		return nil, err
	}
	if err := checkPassword(req.GetPassword()); err != nil {
		return nil, err
	}
	hash, err := password.Hash(req.GetPassword())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	_, err = store.Mutate(ctx, s.project(pid).b, id, func(u *iam.User) error {
		u.PasswordHash, u.PasswordResetRequired, u.Updated = hash, req.GetPasswordResetRequired(), s.now().UTC()
		return nil
	})
	return &iamv1.SetLoginProfileResponse{}, toStatus(ctx, err)
}

// DeleteLoginProfile removes the console password and ends nothing else.
func (s *Server) DeleteLoginProfile(ctx context.Context, req *iamv1.DeleteLoginProfileRequest) (*iamv1.DeleteLoginProfileResponse, error) {
	pid, id, err := child(req.GetName(), "users")
	if err != nil {
		return nil, err
	}
	_, err = store.Mutate(ctx, s.project(pid).b, id, func(u *iam.User) error {
		if u.PasswordHash == "" {
			return notFound("user has no login profile")
		}
		u.PasswordHash, u.PasswordResetRequired, u.Updated = "", false, s.now().UTC()
		return nil
	})
	return &iamv1.DeleteLoginProfileResponse{}, toStatus(ctx, err)
}

// ChangePassword is the user's own change; old_password must verify.
func (s *Server) ChangePassword(ctx context.Context, req *iamv1.ChangePasswordRequest) (*iamv1.ChangePasswordResponse, error) {
	pid, id, err := child(req.GetName(), "users")
	if err != nil {
		return nil, err
	}
	if err := checkPassword(req.GetNewPassword()); err != nil {
		return nil, err
	}
	p := s.project(pid)
	cur, err := store.Get[iam.User](ctx, p.b, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && cur.Object.PasswordHash == "") {
		return nil, invalidCredentials("InvalidClientTokenId", "invalid credentials")
	}
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	if password.Verify(req.GetOldPassword(), cur.Object.PasswordHash) != nil {
		return nil, invalidCredentials("InvalidClientTokenId", "invalid credentials")
	}
	hash, err := password.Hash(req.GetNewPassword())
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	cur.Object.PasswordHash, cur.Object.PasswordResetRequired, cur.Object.Updated = hash, false, s.now().UTC()
	_, err = store.Update(ctx, p.b, cur.Object, cur.Version)
	return &iamv1.ChangePasswordResponse{}, toStatus(ctx, err)
}
