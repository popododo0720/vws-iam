package grpcapi_test

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
)

func TestSimulationResourceTemplates(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			seedSim(t, b, nil)
			in := grpcapi.SimulateInput{
				PolicySourceARN: simARN + "user/alice",
				ActionNames: []string{
					"s3:GetObject",
					"S3:LISTBUCKET",
					"iam:CreateUser",
					"iam:ListUsers",
					"sts:GetCallerIdentity",
					"unknown:Action",
					"s3:Get*",
				},
				ResourceARNs: []string{"arn:vws:s3:::customer/key"},
			}
			want := []string{
				"arn:vws:s3:::${BucketName}/${ObjectName}",
				"arn:vws:s3:::${BucketName}",
				"arn:vws:iam::${Account}:user/${UserNameWithPath}",
				"*",
				"*",
				"*",
				"*",
			}
			for attempt := range 2 {
				e := newEnvOn(t, b, &now)
				principal := simulate(t, e, in)
				custom := simulateCustom(t, e, grpcapi.CustomSimulateInput{
					PolicyInputList: []string{simDoc("*")},
					ActionNames:     in.ActionNames,
					ResourceARNs:    in.ResourceARNs,
				})
				for _, page := range []grpcapi.SimulationPage{principal, custom} {
					for i, result := range page.Results {
						if result.ResourceName != want[i] {
							t.Errorf("attempt %d action %s: resource %q, want %q", attempt, result.ActionName, result.ResourceName, want[i])
						}
						if len(result.ResourceSpecific) != 1 || result.ResourceSpecific[0].ResourceName != in.ResourceARNs[0] {
							t.Errorf("customer ARN changed: %+v", result.ResourceSpecific)
						}
					}
				}
			}
		})
	}
}
