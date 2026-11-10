package grpcapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const (
	slrService = "lex.vws.internal"
	slrTrust   = `{"Version":"2012-10-17","Statement":[` +
		`{"Effect":"Allow","Principal":{"Service":"` + slrService + `"},"Action":"sts:AssumeRole"}]}`
	slrInline = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lex:*","Resource":"*"}]}`
)

// seedLinkedRole stores a service-linked role of slrService in proj, as
// CreateServiceLinkedRole (#103) will, and returns it.
func seedLinkedRole(t *testing.T, b store.Backend, name string) iam.Role {
	t.Helper()
	r := iam.Role{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: name, Path: iam.ServiceRolePath(slrService),
		ID: iam.NewUniqueID("AROA"), Created: time.Now().UTC(), LinkedService: slrService,
		AssumeRolePolicy: slrTrust, InlinePolicies: map[string]string{"svc": slrInline},
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, proj), r); err != nil {
		t.Fatal(err)
	}
	return r
}

func wantNoRole(t *testing.T, e *env, name string) {
	t.Helper()
	_, err := e.roles.GetRole(t.Context(), &iamv1.GetRoleRequest{Name: parentName + "/roles/" + name})
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
}

// TestDeleteServiceLinkedRole: the role is deleted from the store with its
// policies and the AWS DeletionTaskId is returned; every replica then sees
// it gone, and a repeat is NoSuchEntity. On both store backends.
func TestDeleteServiceLinkedRole(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			r := seedLinkedRole(t, b, "VWSServiceRoleForLexBots")

			id, err := e.api.DeleteLinkedRole(ctx, proj, "vwsserviceroleforlexbots")
			if err != nil {
				t.Fatal(err)
			}
			want := "task/aws-service-role/" + slrService + "/VWSServiceRoleForLexBots/" + r.UID
			if id != want {
				t.Fatalf("DeletionTaskId = %q, want %q", id, want)
			}
			wantNoRole(t, e, r.Name)
			wantNoRole(t, newEnvOn(t, b, &now), r.Name)
			_, err = e.api.DeleteLinkedRole(ctx, proj, r.Name)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
		})
	}
}

// TestDeleteServiceLinkedRoleRefusesOtherRoles: a role made by CreateRole
// is never deleted by DeleteServiceLinkedRole, even at a service-role path
// (NoSuchEntity), and DeleteRole refuses a service-linked role
// (UnmodifiableEntity); both roles stay.
func TestDeleteServiceLinkedRoleRefusesOtherRoles(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	plain := &iamv1.Role{Spec: &iamv1.RoleSpec{Path: "/service-role/lex/", AssumeRolePolicy: slrTrust}}
	req := &iamv1.CreateRoleRequest{Parent: parentName, RoleId: "plain", Role: plain}
	if _, err := e.roles.CreateRole(ctx, req); err != nil {
		t.Fatal(err)
	}
	_, err := e.api.DeleteLinkedRole(ctx, proj, "plain")
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	if _, err := e.roles.GetRole(ctx, &iamv1.GetRoleRequest{Name: parentName + "/roles/plain"}); err != nil {
		t.Fatalf("plain role after DeleteServiceLinkedRole: %v", err)
	}

	slr := seedLinkedRole(t, b, "linked")
	_, err = e.roles.DeleteRole(ctx, &iamv1.DeleteRoleRequest{Name: parentName + "/roles/linked"})
	wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
	if _, err := e.api.DeleteLinkedRole(ctx, proj, slr.Name); err != nil {
		t.Fatalf("service-linked role after DeleteRole: %v", err)
	}
}

// TestDeleteServiceLinkedRoleValidation: a RoleName outside the AWS
// pattern or a bad project is ValidationError; an unknown role is
// NoSuchEntity.
func TestDeleteServiceLinkedRoleValidation(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	for _, n := range []string{"", strings.Repeat("r", 65), "a/b", "a b", "rôle"} {
		_, err := e.api.DeleteLinkedRole(ctx, proj, n)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	_, err := e.api.DeleteLinkedRole(ctx, "Bad_Project", "r")
	wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	_, err = e.api.DeleteLinkedRole(ctx, proj, strings.Repeat("r", 64))
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
}

// TestDeleteServiceLinkedRoleConcurrent: requests racing for one role
// delete it once; each gets the role's DeletionTaskId or, after it is
// gone, NoSuchEntity. On both store backends.
func TestDeleteServiceLinkedRoleConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			r := seedLinkedRole(t, b, "racer")
			want := iam.DeletionTaskID(r)
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			var wg sync.WaitGroup
			ids := make([]string, 16)
			errs := make([]error, len(ids))
			for i := range ids {
				wg.Go(func() {
					ids[i], errs[i] = replicas[i%2].api.DeleteLinkedRole(t.Context(), proj, r.Name)
				})
			}
			wg.Wait()
			deleted := 0
			for i, err := range errs {
				if err == nil {
					if ids[i] != want {
						t.Fatalf("DeletionTaskId = %q, want %q", ids[i], want)
					}
					deleted++
					continue
				}
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
			if deleted == 0 {
				t.Fatal("no request deleted the role")
			}
			wantNoRole(t, replicas[0], r.Name)
		})
	}
}

// swapping turns the service-linked role into a plain role between the
// read and the delete of the first DeleteServiceLinkedRole.
type swapping struct {
	store.Backend
	once sync.Once
	t    *testing.T
}

func (s *swapping) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if k == iam.KindRole {
		s.once.Do(func() {
			b, name := store.Scoped(s.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(r *iam.Role) error {
				r.LinkedService, r.Path = "", "/"
				return nil
			}); err != nil {
				s.t.Error(err)
			}
		})
	}
	return s.Backend.Delete(ctx, k, key, version)
}

// TestDeleteServiceLinkedRoleStaleRead: a role that stops being
// service-linked after it was read is read again and kept (NoSuchEntity),
// never deleted at the stale version.
func TestDeleteServiceLinkedRoleStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := &swapping{Backend: bk.open(), t: t}
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedLinkedRole(t, b, "swapped")
			_, err := e.api.DeleteLinkedRole(t.Context(), proj, "swapped")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			got, err := e.roles.GetRole(t.Context(), &iamv1.GetRoleRequest{Name: parentName + "/roles/swapped"})
			if err != nil || got.GetSpec().GetPath() != "/" {
				t.Fatalf("GetRole after a stale delete = %v, %v; want the plain role kept", got, err)
			}
		})
	}
}
