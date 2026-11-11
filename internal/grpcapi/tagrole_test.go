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

// roleTags returns n tags k<from>..k<from+n-1>.
func roleTags(from, n int) []*iamv1.Tag {
	out := make([]*iamv1.Tag, 0, n)
	for i := range n {
		out = append(out, tag("k"+strconv.Itoa(from+i), "v"))
	}
	return out
}

// TestTagRole: TagRole stores the tags with the role, for the role name in
// any case; it overwrites a key the role has, keeps a key that differs only
// in case as its own tag, keeps the last value of a key repeated in the
// request, and leaves the role's other fields and timestamps alone. The
// response is the Role. validate_only and tags the role already has write
// nothing; the same request_id on another server on the same store (a
// replica, or this one restarted) answers the same operation and writes
// nothing. On both store backends.
func TestTagRole(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			seedTaggedRole(t, b, proj, "App", map[string]string{"Env": "dev", "Keep": "me"})
			before := storedRole(t, b, "App")

			req := &iamv1.TagRoleRequest{
				Name:      parentName + "/roles/APP",
				Tags:      []*iamv1.Tag{tag("Env", "prod"), tag("env", "lower"), tag("Team", "a"), tag("Team", "b")},
				RequestId: "0b0c7c43-3d1e-4f5e-8f6a-6a1f2b8f7c01",
			}
			op, err := e.roles.TagRole(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			resp := unpack(t, op, &iamv1.Role{})
			if resp.GetName() != parentName+"/roles/App" || resp.GetGeneration() != before.Object.Generation+1 {
				t.Fatalf("response %v, want role App at generation %d", resp, before.Object.Generation+1)
			}
			after := storedRole(t, b, "App")
			want := map[string]string{"Env": "prod", "env": "lower", "Team": "b", "Keep": "me"}
			if !maps.Equal(after.Object.Tags, want) {
				t.Fatalf("tags %v, want %v", after.Object.Tags, want)
			}
			if !after.Object.Created.Equal(before.Object.Created) || !after.Object.Updated.Equal(before.Object.Updated) ||
				after.Object.UID != before.Object.UID || after.Object.AssumeRolePolicy != before.Object.AssumeRolePolicy {
				t.Fatalf("TagRole changed more than the tags: %+v, was %+v", after.Object, before.Object)
			}

			restarted := newEnvOn(t, b, &now)
			again, err := restarted.roles.TagRole(ctx, req)
			if err != nil || !proto.Equal(again, op) {
				t.Fatalf("replay on another server: %v, %v; want %v", again, err, op)
			}
			if storedRole(t, b, "App").Version != after.Version {
				t.Fatal("a replayed request_id wrote the role")
			}
			_, err = restarted.roles.TagRole(ctx, &iamv1.TagRoleRequest{
				Name: req.GetName(), Tags: []*iamv1.Tag{tag("Env", "other")}, RequestId: req.GetRequestId(),
			})
			wantErr(t, err, codes.Aborted, "IDEMPOTENCY_CONFLICT", "IdempotentParameterMismatch")

			same := &iamv1.TagRoleRequest{
				Name: parentName + "/roles/app", Tags: []*iamv1.Tag{tag("Team", "b"), tag("Env", "prod")},
			}
			if _, err := restarted.roles.TagRole(ctx, same); err != nil {
				t.Fatalf("retag with stored values: %v", err)
			}
			dry := &iamv1.TagRoleRequest{Name: req.GetName(), Tags: []*iamv1.Tag{tag("dry", "run")}, ValidateOnly: true}
			if _, err := e.roles.TagRole(ctx, dry); err != nil {
				t.Fatalf("validate_only: %v", err)
			}
			if storedRole(t, b, "App").Version != after.Version {
				t.Fatal("a retag with stored values or validate_only wrote the role")
			}
		})
	}
}

// TestTagRoleErrors: a name that is not projects/{project}/roles/{id}, a bad
// project or RoleName, no tag or more than 50 are INVALID_ARGUMENT
// (ValidationError) and a tag outside the AWS rules (an aws: prefix
// included) is InvalidInput, all before any store access. An unknown role
// is NoSuchEntity with the AWS message. A role that would keep more than 50
// tags is LimitExceeded and keeps its tags, while overwriting a key at the
// limit succeeds. A store failure is INTERNAL without backend detail.
func TestTagRoleErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedTaggedRole(t, b, proj, "App", nil)
	broken := newEnvOn(t, failingGet{b, iam.KindRole, errors.New("backend exploded")}, &now)
	app := parentName + "/roles/App"
	one := []*iamv1.Tag{tag("k", "v")}
	longKey, longValue := strings.Repeat("k", 129), strings.Repeat("v", 257)
	for _, tc := range []struct {
		name string
		req  *iamv1.TagRoleRequest
		aws  string
	}{
		{"empty name", &iamv1.TagRoleRequest{Tags: one}, "ValidationError"},
		{"wrong collection", &iamv1.TagRoleRequest{Name: parentName + "/users/App", Tags: one}, "ValidationError"},
		{"bad project", &iamv1.TagRoleRequest{Name: "projects/Bad_Project/roles/App", Tags: one}, "ValidationError"},
		{"role bad character", &iamv1.TagRoleRequest{Name: parentName + "/roles/a b", Tags: one}, "ValidationError"},
		{"role too long", &iamv1.TagRoleRequest{Name: app + strings.Repeat("r", 62), Tags: one}, "ValidationError"},
		{"no tags", &iamv1.TagRoleRequest{Name: app}, "ValidationError"},
		{"51 tags", &iamv1.TagRoleRequest{Name: app, Tags: roleTags(0, 51)}, "ValidationError"},
		{"empty key", &iamv1.TagRoleRequest{Name: app, Tags: []*iamv1.Tag{tag("", "v")}}, "InvalidInput"},
		{"bad key character", &iamv1.TagRoleRequest{Name: app, Tags: []*iamv1.Tag{tag("bad#key", "v")}}, "InvalidInput"},
		{"key too long", &iamv1.TagRoleRequest{Name: app, Tags: []*iamv1.Tag{tag(longKey, "v")}}, "InvalidInput"},
		{"value too long", &iamv1.TagRoleRequest{Name: app, Tags: []*iamv1.Tag{tag("k", longValue)}}, "InvalidInput"},
		{"aws key", &iamv1.TagRoleRequest{Name: app, Tags: []*iamv1.Tag{tag("AWS:team", "v")}}, "InvalidInput"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op, err := broken.roles.TagRole(t.Context(), tc.req)
			wantAWS(t, err, codes.InvalidArgument, tc.aws)
			if op != nil {
				t.Fatalf("operation %v with an error", op)
			}
		})
	}

	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	_, err := e.roles.TagRole(ctx, &iamv1.TagRoleRequest{Name: parentName + "/roles/Missing", Tags: one})
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	if want := "The role with name Missing cannot be found."; status.Convert(err).Message() != want {
		t.Fatalf("message %q, want %q", status.Convert(err).Message(), want)
	}

	if _, err := e.roles.TagRole(ctx, &iamv1.TagRoleRequest{Name: app, Tags: roleTags(0, 49)}); err != nil {
		t.Fatal(err)
	}
	full := storedRole(t, b, "App")
	_, err = e.roles.TagRole(ctx, &iamv1.TagRoleRequest{Name: app, Tags: roleTags(48, 3)})
	wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
	if want := "Cannot exceed quota for TagsPerRole: 50"; status.Convert(err).Message() != want {
		t.Fatalf("message %q, want %q", status.Convert(err).Message(), want)
	}
	if storedRole(t, b, "App").Version != full.Version {
		t.Fatal("a refused TagRole wrote the role")
	}
	if _, err := e.roles.TagRole(ctx, &iamv1.TagRoleRequest{Name: app, Tags: roleTags(48, 2)}); err != nil {
		t.Fatalf("50th tag: %v", err)
	}
	if _, err := e.roles.TagRole(ctx, &iamv1.TagRoleRequest{Name: app, Tags: []*iamv1.Tag{tag("k0", "new")}}); err != nil {
		t.Fatalf("overwrite at the limit: %v", err)
	}

	op, err := broken.roles.TagRole(ctx, &iamv1.TagRoleRequest{Name: app, Tags: one})
	if status.Code(err) != codes.Internal || op != nil || strings.Contains(err.Error(), "backend exploded") {
		t.Fatalf("store failure: %v, %v; want no operation and no backend detail", op, err)
	}
}

// TestTagRoleConcurrent: TagRole requests racing on two replicas of one
// store either succeed or, after the bounded retries of a role changed in
// between, are ConcurrentModification (an AWS TagRole error) and store
// nothing; the role keeps exactly the tags of the requests that succeeded,
// so no write is lost to a stale copy.
func TestTagRoleConcurrent(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
	seedTaggedRole(t, b, proj, "App", nil)
	const n = 20
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			_, errs[i] = replicas[i%2].roles.TagRole(t.Context(), &iamv1.TagRoleRequest{
				Name: parentName + "/roles/App", Tags: roleTags(i, 1),
			})
		})
	}
	wg.Wait()
	want := map[string]string{}
	for i, err := range errs {
		if err != nil {
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			continue
		}
		want["k"+strconv.Itoa(i)] = "v"
	}
	if len(want) == 0 {
		t.Fatal("no request succeeded")
	}
	if got := storedRole(t, b, "App").Object.Tags; !maps.Equal(got, want) {
		t.Fatalf("stored tags %v, want those of the successful requests %v", got, want)
	}
}
