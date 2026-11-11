package grpcapi_test

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/store/memstore"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func TestSimulationPolicyExclusions(t *testing.T) {
	type id = grpcapi.PolicyIdentifier
	type inline = grpcapi.InlinePolicyIdentifier
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			seedSim(t, b, nil)
			for _, tc := range []struct {
				name, action, want string
				omit               id
			}{
				{"managed type", "s3:GetObject", "implicitDeny", id{PolicyType: "user-managed"}},
				{"managed ARN", "s3:GetObject", "implicitDeny", id{PolicyARN: simARN + "policy/S3Read"}},
				{
					"managed wildcard",
					"s3:GetObject",
					"implicitDeny",
					id{PolicyARN: simARN + "policy/S3R*?"},
				},
				{"inline type", "ec2:RunInstances", "implicitDeny", id{PolicyType: "inline"}},
				{
					"group inline",
					"ec2:RunInstances",
					"implicitDeny",
					id{
						InlinePolicyIdentifier: &inline{AttachmentType: "group", AttachmentName: "d*?s", PolicyName: "ec2"},
					},
				},
				{
					"inline deny removed",
					"s3:DeleteObject",
					"implicitDeny",
					id{
						InlinePolicyIdentifier: &inline{AttachmentType: "user", AttachmentName: "alice", PolicyName: "nodelete"},
					},
				},
				{"no match", "s3:GetObject", "allowed", id{PolicyARN: simARN + "policy/Absent"}},
				{"RCP ignored", "s3:GetObject", "allowed", id{PolicyType: "rcp"}},
				{"SCP ignored", "s3:GetObject", "allowed", id{PolicyType: "scp"}},
				{"AWS managed ignored", "s3:GetObject", "allowed", id{PolicyType: "aws-managed"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					for range 2 {
						e := newEnvOn(t, b, &now)
						p := simulate(t, e, grpcapi.SimulateInput{
							PolicySourceARN:     simARN + "user/alice",
							ActionNames:         []string{tc.action},
							PolicyExclusionList: []id{tc.omit},
						})
						if p.Results[0].Decision != tc.want {
							t.Fatalf("%s, want %s", p.Results[0].Decision, tc.want)
						}
					}
				})
			}
			sb := store.Scoped(b, proj)
			if _, err := store.Mutate(t.Context(), sb, "alice", func(u *iam.User) error {
				u.PermissionsBoundary = simARN + "policy/S3Read"
				u.InlinePolicies["broken"] = "{bad document"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			e := newEnvOn(t, b, &now)
			in := grpcapi.SimulateInput{
				PolicySourceARN: simARN + "user/alice",
				ActionNames:     []string{"ec2:RunInstances"},
				PolicyExclusionList: []id{
					{PolicyType: "permission-boundary"},
					{
						InlinePolicyIdentifier: &inline{AttachmentType: "user", AttachmentName: "alice", PolicyName: "broken"},
					},
				},
			}
			if p := simulate(t, e, in); p.Results[0].Decision != "allowed" || p.Results[0].AllowedByPermissionsBoundary != nil {
				t.Fatalf("excluded boundary and corrupt inline: %+v", p.Results[0])
			}
			// Explicit input policies are not attachments and must survive exclusions.
			in.PolicyInputList = []string{simDoc("s3:GetObject")}
			in.ActionNames = []string{"s3:GetObject"}
			in.PolicyExclusionList = []id{
				{PolicyType: "inline"},
				{PolicyType: "user-managed"},
				{PolicyType: "permission-boundary"},
			}
			if p := simulate(t, e, in); p.Results[0].Decision != "allowed" {
				t.Fatalf("input policy excluded: %+v", p.Results[0])
			}
			// Filtering is simulation-local, and does not change the stored policies.
			in.PolicyExclusionList = nil
			_, err := e.api.SimulatePrincipal(t.Context(), proj, in)
			wantAWS(t, err, codes.Internal, "PolicyEvaluation")
		})
	}
}

func TestSimulationPolicyExclusionValidation(t *testing.T) {
	type id = grpcapi.PolicyIdentifier
	type inline = grpcapi.InlinePolicyIdentifier
	now := time.Now().UTC()
	e := newEnvOn(t, memstore.New(), &now)
	for _, omit := range []id{
		{},
		{PolicyType: "resource"},
		{PolicyType: "inline", PolicyARN: simARN + "policy/S3Read"},
		{PolicyARN: "garbage"},
		{PolicyARN: "arn:vws:iam::*:policy/Read"},
		{PolicyARN: simARN + "user/alice"},
		{PolicyARN: simARN + "policy/Read**"},
		{
			InlinePolicyIdentifier: &inline{AttachmentType: "root", AttachmentName: "alice", PolicyName: "read"},
		},
		{
			InlinePolicyIdentifier: &inline{AttachmentType: "user", AttachmentName: "a**", PolicyName: "read"},
		},
		{
			InlinePolicyIdentifier: &inline{AttachmentType: "user", AttachmentName: "alice", PolicyName: "*"},
		},
	} {
		_, err := e.api.SimulatePrincipal(t.Context(), proj, grpcapi.SimulateInput{
			PolicySourceARN:     simARN + "user/alice",
			ActionNames:         []string{"s3:GetObject"},
			PolicyExclusionList: []id{omit},
		})
		wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
	}
	tooMany := make([]id, 257)
	for i := range tooMany {
		tooMany[i].PolicyType = "rcp"
	}
	_, err := e.api.SimulatePrincipal(t.Context(), proj, grpcapi.SimulateInput{
		PolicySourceARN:     simARN + "user/alice",
		ActionNames:         []string{"s3:GetObject"},
		PolicyExclusionList: tooMany,
	})
	wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
}
