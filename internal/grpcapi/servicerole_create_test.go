package grpcapi_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const asService = "autoscaling.vws.internal"

// linkedCatalog is the test catalog: autoscaling allows a CustomSuffix,
// lex does not.
var linkedCatalog = grpcapi.WithLinkedServices(
	iam.LinkedService{
		Principal: asService, RoleName: "AutoScaling", CustomSuffix: true, Description: "Default description",
	},
	iam.LinkedService{Principal: slrService, RoleName: "LexBots"},
)

func createSLR(t *testing.T, e *env, req grpcapi.ServiceLinkedRoleRequest) (*iamv1.Role, error) {
	t.Helper()
	return e.api.CreateServiceLinkedRole(t.Context(), proj, req)
}

// TestCreateServiceLinkedRole: the role is stored with the AWS name,
// path and service trust, every replica reads it, a repeat is
// InvalidInput "has been taken", a CustomSuffix makes a second role, and
// the role is service-linked (DeleteRole refuses it, only
// DeleteServiceLinkedRole deletes it). On both store backends.
func TestCreateServiceLinkedRole(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now, linkedCatalog)
			ctx := t.Context()
			req := grpcapi.ServiceLinkedRoleRequest{AWSServiceName: "autoscaling.vws.internal"}
			got, err := createSLR(t, e, req)
			if err != nil {
				t.Fatal(err)
			}
			const name = "AWSServiceRoleForAutoScaling"
			wantARN := "arn:vws:iam::" + proj + ":role/aws-service-role/" + asService + "/" + name
			if got.GetName() != parentName+"/roles/"+name ||
				got.GetSpec().GetPath() != "/aws-service-role/autoscaling.vws.internal/" ||
				got.GetStatus().GetArn() != wantARN || !strings.HasPrefix(got.GetStatus().GetUniqueId(), "AROA") ||
				got.GetSpec().GetDescription() != "Default description" || got.GetCreateTime() == nil ||
				got.GetSpec().GetAssumeRolePolicy() != iam.ServiceTrustPolicy("autoscaling.vws.internal") {
				t.Fatalf("CreateServiceLinkedRole = %v", got)
			}
			read, err := newEnvOn(t, b, &now).roles.GetRole(ctx, &iamv1.GetRoleRequest{Name: got.GetName()})
			if err != nil || read.GetUid() != got.GetUid() || read.GetStatus().GetArn() != wantARN {
				t.Fatalf("GetRole on another replica = %v, %v", read, err)
			}

			_, err = createSLR(t, e, req)
			wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
			req.CustomSuffix, req.Description = "debug-1", "Mine"
			sfx, err := createSLR(t, e, req)
			if err != nil || sfx.GetName() != parentName+"/roles/"+name+"_debug-1" || sfx.GetSpec().GetDescription() != "Mine" {
				t.Fatalf("with CustomSuffix = %v, %v", sfx, err)
			}
			_, err = createSLR(t, e, req)
			wantAWS(t, err, codes.InvalidArgument, "InvalidInput")

			_, err = e.roles.DeleteRole(ctx, &iamv1.DeleteRoleRequest{Name: got.GetName()})
			wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
			if _, err := e.api.DeleteServiceLinkedRole(ctx, proj, name); err != nil {
				t.Fatal(err)
			}
			if _, err := createSLR(t, e, grpcapi.ServiceLinkedRoleRequest{AWSServiceName: asService}); err != nil {
				t.Fatalf("create after delete: %v", err)
			}
		})
	}
}

// TestCreateServiceLinkedRoleTrust: the stored trust policy lets only
// the linked service assume the role.
func TestCreateServiceLinkedRoleTrust(t *testing.T) {
	e := newEnvOn(t, memstore.New(), new(time.Now().UTC()), linkedCatalog)
	got, err := createSLR(t, e, grpcapi.ServiceLinkedRoleRequest{AWSServiceName: slrService})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := policy.ParseTrust(got.GetSpec().GetAssumeRolePolicy())
	if err != nil {
		t.Fatal(err)
	}
	set := []policy.Named{{Name: "trust", Doc: trust}}
	if d := policy.Evaluate(policy.Request{Service: slrService, Action: "sts:AssumeRole"}, set, nil); !d.Allowed {
		t.Fatalf("linked service denied: %v", d)
	}
	for _, r := range []policy.Request{
		{Service: "autoscaling.vws.internal", Action: "sts:AssumeRole"},
		{Principal: "arn:vws:iam::" + proj + ":root", Account: proj, Action: "sts:AssumeRole"},
	} {
		if d := policy.Evaluate(r, set, nil); d.Allowed {
			t.Fatalf("%+v allowed", r)
		}
	}
}

// TestCreateServiceLinkedRoleValidation: AWS length and pattern faults
// are ValidationError; an unknown or differently cased service, a
// CustomSuffix the service does not allow and a name over 64 characters
// are InvalidInput; a catalog entry that cannot name a role is
// ServiceFailure; nothing is stored for any of them.
func TestCreateServiceLinkedRoleValidation(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now, linkedCatalog)
	as := "autoscaling.vws.internal"
	for _, req := range []grpcapi.ServiceLinkedRoleRequest{
		{},
		{AWSServiceName: strings.Repeat("a", 129)},
		{AWSServiceName: "auto scaling.vws.internal"},
		{AWSServiceName: "autoscaling/vws"},
		{AWSServiceName: as, CustomSuffix: strings.Repeat("s", 65)},
		{AWSServiceName: as, CustomSuffix: "a/b"},
		{AWSServiceName: as, CustomSuffix: "sûffix"},
		{AWSServiceName: as, Description: strings.Repeat("d", 1001)},
		{AWSServiceName: as, Description: "emoji \U0001F600"},
		{AWSServiceName: as, Description: "nul \x00"},
	} {
		_, err := createSLR(t, e, req)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	badProject := grpcapi.ServiceLinkedRoleRequest{AWSServiceName: as}
	_, err := e.api.CreateServiceLinkedRole(t.Context(), "Bad_Project", badProject)
	wantAWS(t, err, codes.InvalidArgument, "ValidationError")

	longest := strings.Repeat("s", 64-len("AWSServiceRoleForAutoScaling_"))
	for _, req := range []grpcapi.ServiceLinkedRoleRequest{
		{AWSServiceName: "ec2.vws.internal"},
		{AWSServiceName: "AutoScaling.vws.internal"},
		{AWSServiceName: slrService, CustomSuffix: "x"},
		{AWSServiceName: as, CustomSuffix: longest + "s"},
	} {
		_, err := createSLR(t, e, req)
		wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
	}
	limits := grpcapi.ServiceLinkedRoleRequest{
		AWSServiceName: as, CustomSuffix: longest, Description: strings.Repeat("d", 1000),
	}
	if _, err := createSLR(t, e, limits); err != nil {
		t.Fatalf("64-character name, 1000-character description: %v", err)
	}

	bad := newEnvOn(t, b, &now, grpcapi.WithLinkedServices(iam.LinkedService{Principal: "bad.vws.internal"}))
	_, err = createSLR(t, bad, grpcapi.ServiceLinkedRoleRequest{AWSServiceName: "bad.vws.internal"})
	wantAWS(t, err, codes.Internal, "ServiceFailure")
	list, err := e.roles.ListRoles(t.Context(), &iamv1.ListRolesRequest{Parent: parentName})
	if err != nil || len(list.GetRoles()) != 1 {
		t.Fatalf("ListRoles = %v, %v; want only the valid role", list, err)
	}
}

// TestCreateServiceLinkedRoleFailsClosed: without a catalog (production
// today) every service is InvalidInput and nothing is stored.
func TestCreateServiceLinkedRoleFailsClosed(t *testing.T) {
	e := newEnv(t)
	_, err := createSLR(t, e, grpcapi.ServiceLinkedRoleRequest{AWSServiceName: slrService})
	wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
	wantNoRole(t, e, "AWSServiceRoleForLexBots")
}

// TestCreateServiceLinkedRoleNameTaken: a role made by CreateRole under
// the service role name, in any case, makes the create InvalidInput and
// is kept unchanged and not service-linked.
func TestCreateServiceLinkedRoleNameTaken(t *testing.T) {
	e := newEnvOn(t, memstore.New(), new(time.Now().UTC()), linkedCatalog)
	ctx := t.Context()
	plain := &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: slrTrust}}
	req := &iamv1.CreateRoleRequest{Parent: parentName, RoleId: "awsserviceroleforlexbots", Role: plain}
	if _, err := e.roles.CreateRole(ctx, req); err != nil {
		t.Fatal(err)
	}
	_, err := createSLR(t, e, grpcapi.ServiceLinkedRoleRequest{AWSServiceName: slrService})
	wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
	got, err := e.roles.GetRole(ctx, &iamv1.GetRoleRequest{Name: parentName + "/roles/AWSServiceRoleForLexBots"})
	if err != nil || got.GetSpec().GetPath() != "/" {
		t.Fatalf("GetRole = %v, %v; want the plain role kept", got, err)
	}
	if _, err := e.roles.DeleteRole(ctx, &iamv1.DeleteRoleRequest{Name: got.GetName()}); err != nil {
		t.Fatalf("plain role became service-linked: %v", err)
	}
}

// TestCreateServiceLinkedRoleConcurrent: requests racing on two replicas
// create the role once; every other request is InvalidInput. On both
// store backends.
func TestCreateServiceLinkedRoleConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now, linkedCatalog), newEnvOn(t, b, &now, linkedCatalog)}
			var wg sync.WaitGroup
			roles := make([]*iamv1.Role, 16)
			errs := make([]error, len(roles))
			for i := range roles {
				wg.Go(func() {
					roles[i], errs[i] = replicas[i%2].api.CreateServiceLinkedRole(t.Context(), proj,
						grpcapi.ServiceLinkedRoleRequest{AWSServiceName: slrService})
				})
			}
			wg.Wait()
			var winner *iamv1.Role
			for i, err := range errs {
				if err == nil {
					if winner != nil {
						t.Fatalf("two creates succeeded: %v and %v", winner, roles[i])
					}
					winner = roles[i]
					continue
				}
				wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
			}
			if winner == nil {
				t.Fatal("no request created the role")
			}
			got, err := replicas[1].roles.GetRole(t.Context(), &iamv1.GetRoleRequest{Name: winner.GetName()})
			if err != nil || got.GetUid() != winner.GetUid() {
				t.Fatalf("GetRole = %v, %v; want the winner %s", got, err, winner.GetUid())
			}
		})
	}
}
