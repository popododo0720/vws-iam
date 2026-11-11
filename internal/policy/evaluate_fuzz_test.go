package policy_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/policy"
)

type evaluationInput struct {
	Action      string
	Resource    string
	Context     map[string][]string
	Identity    []json.RawMessage
	Restriction []json.RawMessage
}

// The reference covers Action/NotAction, Resource/NotResource, StringEquals,
// and Bool. Its quadratic table is independent of the production glob matcher.
func referenceMatch(pattern, value string, fold bool) bool {
	if fold {
		pattern, value = strings.ToLower(pattern), strings.ToLower(value)
	}
	previous := make([]bool, len(value)+1)
	previous[0] = true
	for i := range len(pattern) {
		current := make([]bool, len(value)+1)
		for j := range current {
			if pattern[i] == '*' {
				current[j] = previous[j] || (j > 0 && current[j-1])
			} else if j > 0 && (pattern[i] == '?' || pattern[i] == value[j-1]) {
				current[j] = previous[j-1]
			}
		}
		previous = current
	}
	return previous[len(value)]
}

func referenceStatement(s policy.Statement, r policy.Request) bool {
	matches := func(patterns []string, value string, fold bool) bool {
		for _, pattern := range patterns {
			if referenceMatch(pattern, value, fold) {
				return true
			}
		}
		return false
	}
	if matches(s.Actions, r.Action, true) == s.NotAction {
		return false
	}
	if s.Resources != nil && matches(s.Resources, r.Resource, false) == s.NotRes {
		return false
	}
	for _, c := range s.Conditions {
		var values []string
		for key, vs := range r.Context {
			if strings.EqualFold(key, c.Key) {
				values = vs
			}
		}
		if len(values) == 0 && c.IfExists {
			continue
		}
		found := false
		for _, value := range values {
			for _, want := range c.Values {
				found = found || (c.Op == "Bool" && strings.EqualFold(value, want)) || (c.Op == "StringEquals" && value == want)
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func referenceEvaluation(r policy.Request, identity, restriction []policy.Named) (allowed, explicit bool) {
	scan := func(set []policy.Named) (allow, deny bool) {
		for _, p := range set {
			for _, s := range p.Doc.Statements {
				if referenceStatement(s, r) {
					allow = allow || s.Effect == policy.Allow
					deny = deny || s.Effect == policy.Deny
				}
			}
		}
		return allow, deny
	}
	allow, deny := scan(identity)
	if restriction != nil {
		restrictedAllow, restrictedDeny := scan(restriction)
		allow, deny = allow && restrictedAllow, deny || restrictedDeny
	}
	return allow && !deny, deny
}

func generatedEvaluation(data []byte) (policy.Request, []policy.Named, []policy.Named) {
	index := 0
	next := func() byte {
		if len(data) == 0 {
			return 0
		}
		b := data[index%len(data)]
		index++
		return b
	}
	actions := []string{"s3:GetObject", "s3:PutObject", "ec2:DescribeInstances", "S3:GETOBJECT"}
	resources := []string{"arn:vws:s3:::one/key", "arn:vws:s3:::two/KEY", "*"}
	actionPatterns := []string{"*", "s3:*", "s3:GetObject", "s3:PutObject", "ec2:Describe?nstanc*"}
	resourcePatterns := []string{"*", "arn:vws:s3:::one/*", "arn:vws:s3:::two/key", "arn:vws:s3:::two/?EY"}
	r := policy.Request{Action: actions[int(next())%len(actions)], Resource: resources[int(next())%len(resources)]}
	r.Context = map[string][]string{}
	if next()%2 != 0 {
		r.Context["aws:SecureTransport"] = []string{[]string{"false", "true"}[next()%2]}
	}
	makeSet := func(name string) []policy.Named {
		doc := policy.Document{Version: policy.Version}
		for range int(next() % 7) {
			bits := next()
			s := policy.Statement{
				Effect: policy.Allow, Actions: []string{actionPatterns[int(next())%len(actionPatterns)]},
				Resources: []string{resourcePatterns[int(next())%len(resourcePatterns)]},
				NotAction: bits&2 != 0, NotRes: bits&4 != 0,
			}
			if bits&1 != 0 {
				s.Effect = policy.Deny
			}
			if bits&8 != 0 {
				s.Conditions = []policy.Condition{{
					Op: "Bool", Key: "aws:SecureTransport",
					Values: []string{[]string{"false", "true"}[next()%2]}, IfExists: bits&16 != 0,
				}}
			}
			doc.Statements = append(doc.Statements, s)
		}
		return []policy.Named{{Name: name, Doc: &doc}}
	}
	identity := makeSet("identity")
	var restriction []policy.Named
	if next()%2 != 0 {
		restriction = makeSet("restriction")
	}
	return r, identity, restriction
}

func corpusEvaluation(data []byte) (policy.Request, []policy.Named, []policy.Named, bool) {
	var in evaluationInput
	if json.Unmarshal(data, &in) != nil || in.Action == "" || in.Resource == "" {
		return policy.Request{}, nil, nil, false
	}
	var keys []string
	for key := range in.Context {
		for _, other := range keys {
			if strings.EqualFold(key, other) {
				return policy.Request{}, nil, nil, false
			}
		}
		keys = append(keys, key)
	}
	parse := func(raw []json.RawMessage) ([]policy.Named, bool) {
		if raw == nil {
			return nil, true
		}
		out := make([]policy.Named, 0, len(raw))
		for i, v := range raw {
			doc, err := policy.Parse(string(v))
			if err != nil {
				return nil, false
			}
			for _, s := range doc.Statements {
				if s.Principals != nil {
					return nil, false
				}
				for _, c := range s.Conditions {
					if c.Set != policy.SetNone || (c.Op != "Bool" && c.Op != "StringEquals") {
						return nil, false
					}
					for _, value := range c.Values {
						if strings.Contains(value, "${") {
							return nil, false
						}
					}
				}
				// Policy variables are outside this reference model.
				for _, resource := range s.Resources {
					if strings.Contains(resource, "${") {
						return nil, false
					}
				}
			}
			out = append(out, policy.Named{Name: fmt.Sprintf("corpus-%d", i), Doc: doc})
		}
		return out, true
	}
	identity, ok := parse(in.Identity)
	if !ok {
		return policy.Request{}, nil, nil, false
	}
	restriction, ok := parse(in.Restriction)
	return policy.Request{Action: in.Action, Resource: in.Resource, Context: in.Context}, identity, restriction, ok
}

func FuzzEvaluate(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	f.Add([]byte{255, 255, 255, 0, 1, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		r, identity, restriction := generatedEvaluation(data)
		if len(data) > 0 && data[0] == '{' {
			var ok bool
			r, identity, restriction, ok = corpusEvaluation(data)
			if !ok {
				return
			}
		}
		base := policy.Evaluate(r, identity, nil)
		got := policy.Evaluate(r, identity, restriction)
		wantAllow, wantDeny := referenceEvaluation(r, identity, restriction)
		if got.Allowed != wantAllow || got.Explicit != wantDeny {
			t.Fatalf("differential mismatch input=%x request=%+v identity=%+v restriction=%+v got=%+v want=(%v,%v)",
				data, r, identity, restriction, got, wantAllow, wantDeny)
		}
		if got.Allowed && !base.Allowed {
			t.Fatal("session policy widened identity permissions")
		}
		boundary := policy.Simulate(r, identity, restriction)
		if boundary.Decision == policy.DecisionAllowed && !base.Allowed {
			t.Fatal("boundary widened identity permissions")
		}
		if (boundary.Decision == policy.DecisionAllowed) != wantAllow ||
			(boundary.Decision == policy.DecisionExplicitDeny) != wantDeny {
			t.Fatal("boundary/reference disagreement")
		}
		added := func(effect policy.Effect) []policy.Named {
			out := append([]policy.Named{}, identity...)
			return append(out, policy.Named{Name: "added", Doc: &policy.Document{
				Version:    policy.Version,
				Statements: []policy.Statement{{Effect: effect, Actions: []string{"*"}, Resources: []string{"*"}}},
			}})
		}
		denied := policy.Evaluate(r, added(policy.Deny), restriction)
		if denied.Allowed || !denied.Explicit {
			t.Fatal("matching explicit deny did not win")
		}
		allowed := policy.Evaluate(r, added(policy.Allow), nil)
		if base.Allowed && !allowed.Allowed {
			t.Fatal("adding an allow removed an existing allow")
		}
		if !base.Allowed && denied.Allowed {
			t.Fatal("adding a deny turned a refusal into an allow")
		}
		noAllow, explicit := referenceEvaluation(r, identity, nil)
		if !noAllow && !explicit && (base.Allowed || base.Explicit) {
			t.Fatal("missing allow was not implicit deny")
		}
	})
}

func TestMatchWildcardInValue(t *testing.T) {
	for _, value := range []string{"*suffix", "arn:vws:s3:::bucket/*suffix"} {
		if !policy.Match("*", value, false) {
			t.Fatalf("wildcard did not match %q", value)
		}
	}
	if !policy.Match("arn:vws:s3:::bucket/*", "arn:vws:s3:::bucket/*suffix", false) {
		t.Fatal("resource wildcard treated the object's asterisk as a literal pattern token")
	}
}
