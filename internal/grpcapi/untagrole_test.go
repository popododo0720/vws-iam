package grpcapi_test

import (
	"errors"
	"maps"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestUntagRole: UntagRole removes the named keys from the role, for the
// role name in any case; key case is significant, a key the role does not
// have is ignored, and the role's other fields and timestamps stay. The
// response is the Role. validate_only and keys the role does not have write
// nothing; the same request_id on another server on the same store (a
// replica, or this one restarted) answers the same operation and writes
// nothing. On both store backends.
func TestUntagRole(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			seedTaggedRole(t, b, proj, "App", map[string]string{"Env": "dev", "env": "lower", "Keep": "me", "Team": "a"})
			before := storedRole(t, b, "App")

			req := &iamv1.UntagRoleRequest{
				Name:      parentName + "/roles/APP",
				TagKeys:   []string{"Env", "Team", "missing", "Team"},
				RequestId: "4d7b1f0e-2a6c-4c1b-9e57-3f8d2c6a9b12",
			}
			op, err := e.roles.UntagRole(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			resp := unpack(t, op, &iamv1.Role{})
			if resp.GetName() != parentName+"/roles/App" || resp.GetGeneration() != before.Object.Generation+1 {
				t.Fatalf("response %v, want role App at generation %d", resp, before.Object.Generation+1)
			}
			after := storedRole(t, b, "App")
			if want := map[string]string{"env": "lower", "Keep": "me"}; !maps.Equal(after.Object.Tags, want) {
				t.Fatalf("tags %v, want %v", after.Object.Tags, want)
			}
			if !after.Object.Created.Equal(before.Object.Created) || !after.Object.Updated.Equal(before.Object.Updated) ||
				after.Object.UID != before.Object.UID || after.Object.AssumeRolePolicy != before.Object.AssumeRolePolicy {
				t.Fatalf("UntagRole changed more than the tags: %+v, was %+v", after.Object, before.Object)
			}

			restarted := newEnvOn(t, b, &now)
			again, err := restarted.roles.UntagRole(ctx, req)
			if err != nil || !proto.Equal(again, op) {
				t.Fatalf("replay on another server: %v, %v; want %v", again, err, op)
			}
			if storedRole(t, b, "App").Version != after.Version {
				t.Fatal("a replayed request_id wrote the role")
			}
			_, err = restarted.roles.UntagRole(ctx, &iamv1.UntagRoleRequest{
				Name: req.GetName(), TagKeys: []string{"Keep"}, RequestId: req.GetRequestId(),
			})
			wantErr(t, err, codes.Aborted, "IDEMPOTENCY_CONFLICT", "IdempotentParameterMismatch")

			absent := &iamv1.UntagRoleRequest{Name: parentName + "/roles/app", TagKeys: []string{"Env", "KEEP"}}
			if _, err := restarted.roles.UntagRole(ctx, absent); err != nil {
				t.Fatalf("untag of keys the role does not have: %v", err)
			}
			dry := &iamv1.UntagRoleRequest{Name: req.GetName(), TagKeys: []string{"Keep"}, ValidateOnly: true}
			if _, err := e.roles.UntagRole(ctx, dry); err != nil {
				t.Fatalf("validate_only: %v", err)
			}
			if storedRole(t, b, "App").Version != after.Version {
				t.Fatal("an untag of absent keys or validate_only wrote the role")
			}
		})
	}
}

// TestUntagRoleErrors: a name that is not projects/{project}/roles/{id}, a
// bad project or RoleName, no key or more than 50 are INVALID_ARGUMENT
// (ValidationError) and a key outside the AWS rules (an aws: prefix
// included) is InvalidInput, all before any store access. An unknown role
// is NoSuchEntity with the AWS message. A store failure is INTERNAL without
// backend detail.
func TestUntagRoleErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedTaggedRole(t, b, proj, "App", map[string]string{"k": "v"})
	broken := newEnvOn(t, failingGet{b, iam.KindRole, errors.New("backend exploded")}, &now)
	app := parentName + "/roles/App"
	one := []string{"k"}
	many := make([]string, 51)
	for i := range many {
		many[i] = "k" + strconv.Itoa(i)
	}
	for _, tc := range []struct {
		name string
		req  *iamv1.UntagRoleRequest
		aws  string
	}{
		{"empty name", &iamv1.UntagRoleRequest{TagKeys: one}, "ValidationError"},
		{"wrong collection", &iamv1.UntagRoleRequest{Name: parentName + "/users/App", TagKeys: one}, "ValidationError"},
		{"bad project", &iamv1.UntagRoleRequest{Name: "projects/Bad_Project/roles/App", TagKeys: one}, "ValidationError"},
		{"role bad character", &iamv1.UntagRoleRequest{Name: parentName + "/roles/a b", TagKeys: one}, "ValidationError"},
		{"role too long", &iamv1.UntagRoleRequest{Name: app + strings.Repeat("r", 62), TagKeys: one}, "ValidationError"},
		{"no keys", &iamv1.UntagRoleRequest{Name: app}, "ValidationError"},
		{"51 keys", &iamv1.UntagRoleRequest{Name: app, TagKeys: many}, "ValidationError"},
		{"empty key", &iamv1.UntagRoleRequest{Name: app, TagKeys: []string{""}}, "InvalidInput"},
		{"bad key character", &iamv1.UntagRoleRequest{Name: app, TagKeys: []string{"bad#key"}}, "InvalidInput"},
		{"key too long", &iamv1.UntagRoleRequest{Name: app, TagKeys: []string{strings.Repeat("k", 129)}}, "InvalidInput"},
		{"aws key", &iamv1.UntagRoleRequest{Name: app, TagKeys: []string{"AWS:team"}}, "InvalidInput"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, err := broken.roles.UntagRole(t.Context(), tc.req)
			wantAWS(t, err, codes.InvalidArgument, tc.aws)
			if op != nil {
				t.Fatalf("operation %v with an error", op)
			}
		})
	}

	e := newEnvOn(t, b, &now)
	_, err := e.roles.UntagRole(t.Context(), &iamv1.UntagRoleRequest{Name: parentName + "/roles/Missing", TagKeys: one})
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	if want := "The role with name Missing cannot be found."; status.Convert(err).Message() != want {
		t.Fatalf("message %q, want %q", status.Convert(err).Message(), want)
	}
	if _, err := e.roles.UntagRole(t.Context(), &iamv1.UntagRoleRequest{Name: app, TagKeys: many[:50]}); err != nil {
		t.Fatalf("50 keys: %v", err)
	}

	op, err := broken.roles.UntagRole(t.Context(), &iamv1.UntagRoleRequest{Name: app, TagKeys: one})
	if status.Code(err) != codes.Internal || op != nil || strings.Contains(err.Error(), "backend exploded") {
		t.Fatalf("store failure: %v, %v; want no operation and no backend detail", op, err)
	}
}

// TestUntagRoleConcurrent: UntagRole requests racing on two replicas of one
// store either succeed or are ConcurrentModification and remove nothing;
// the role keeps exactly the tags no successful request removed, so no
// removal is lost to a stale copy.
func TestUntagRoleConcurrent(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
	const n = 20
	want := make(map[string]string, n)
	for i := range n {
		want["k"+strconv.Itoa(i)] = "v"
	}
	seedTaggedRole(t, b, proj, "App", maps.Clone(want))
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, errs[i] = replicas[i%2].roles.UntagRole(t.Context(), &iamv1.UntagRoleRequest{
				Name: parentName + "/roles/App", TagKeys: []string{"k" + strconv.Itoa(i)},
			})
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			continue
		}
		delete(want, "k"+strconv.Itoa(i))
	}
	if len(want) == n {
		t.Fatal("no request succeeded")
	}
	if got := storedRole(t, b, "App").Object.Tags; !maps.Equal(got, want) {
		t.Fatalf("stored tags %v, want those no successful request removed %v", got, want)
	}
}
