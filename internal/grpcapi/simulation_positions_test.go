package grpcapi_test

import (
	"slices"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/policy"
)

func TestSimulationStatementPositions(t *testing.T) {
	doc := `{
  "Version":"2012-10-17",
  "Statement": {
    "Effect":"Allow","Action":"s3:GetObject","Resource":"*",
    "Condition":{"StringEquals":{"aws:PrincipalTag/Team":"${aws:PrincipalTag/Expected}"}}
  }
}`
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			seedSim(t, b, nil)
			in := grpcapi.CustomSimulateInput{ActionNames: []string{"s3:GetObject"}, PolicyInputList: []string{doc}}
			e := newEnvOn(t, b, &now)
			p := simulateCustom(t, e, in)
			want := []string{"aws:PrincipalTag/Expected", "aws:PrincipalTag/Team"}
			if !slices.Equal(p.Results[0].MissingContextValues, want) {
				t.Fatalf("missing %v, want %v", p.Results[0].MissingContextValues, want)
			}
			in.ContextEntries = []grpcapi.ContextEntry{
				{Key: "AWS:PRINCIPALTAG/TEAM", Type: "string", Values: []string{"dev"}},
				{Key: "AWS:PRINCIPALTAG/EXPECTED", Type: "string", Values: []string{"dev"}},
			}
			for range 2 {
				e = newEnvOn(t, b, &now)
				p = simulateCustom(t, e, in)
				if len(p.Results[0].MatchedStatements) != 1 {
					t.Fatalf("matched %+v", p.Results[0])
				}
				m := p.Results[0].MatchedStatements[0]
				if m.StartPosition != (policy.Position{Line: 3, Column: 16}) ||
					m.EndPosition != (policy.Position{Line: 6, Column: 3}) {
					t.Errorf("positions %v to %v", m.StartPosition, m.EndPosition)
				}
				principal := simulate(t, e, grpcapi.SimulateInput{
					PolicySourceARN: simARN + "user/alice",
					ActionNames:     in.ActionNames,
					PolicyInputList: in.PolicyInputList,
					ContextEntries:  in.ContextEntries,
				})
				found := false
				for _, m := range principal.Results[0].MatchedStatements {
					if m.SourcePolicyID == "PolicyInputList.1" {
						found = true
						if m.StartPosition != (policy.Position{Line: 3, Column: 16}) ||
							m.EndPosition != (policy.Position{Line: 6, Column: 3}) {
							t.Errorf("principal positions %+v", m)
						}
					}
				}
				if !found {
					t.Fatal("input statement missing")
				}
			}
		})
	}
}
