package policy

import (
	"slices"
	"strings"
)

// Simulator decisions, the AWS EvalDecision values.
const (
	DecisionAllowed      = "allowed"
	DecisionExplicitDeny = "explicitDeny"
	DecisionImplicitDeny = "implicitDeny"
)

// MatchedStatement names one statement that decided a simulation.
type MatchedStatement struct {
	// Policy is the policy the statement is in.
	Policy Named
	// Index is the statement's 0-based position in the policy.
	Index int
}

// Simulation is the result of Simulate for one action and resource.
type Simulation struct {
	// Decision is DecisionAllowed, DecisionExplicitDeny or
	// DecisionImplicitDeny.
	Decision string
	// Matched are the statements that decided it: every explicit deny
	// when one applies (only those, as in AWS), else every allow when the
	// action is allowed, else none.
	Matched []MatchedStatement
	// Missing are the condition keys of statements that match the action
	// and resource but that the request context does not carry, each once,
	// sorted (condition order in a document is not kept). Keys are
	// case-insensitive, so they are reported lowercase.
	Missing []string
	// Boundary reports whether a permissions boundary was given and,
	// if so, AllowedByBoundary whether it allows the request.
	Boundary          bool
	AllowedByBoundary bool
}

// Simulate evaluates r like Evaluate, against identity policies and a
// permissions boundary (none when boundary is nil), and reports every
// statement that decided the result, as the IAM policy simulator does. An
// explicit deny in either set wins; otherwise the request is allowed only
// when an identity policy allows it and, with a boundary, the boundary
// allows it too.
func Simulate(r Request, identity []Named, boundary []Named) Simulation {
	var out Simulation
	deny, allow := matches(identity, r, &out.Missing)
	if boundary != nil {
		bdeny, ballow := matches(boundary, r, &out.Missing)
		out.Boundary = true
		out.AllowedByBoundary = len(bdeny) == 0 && len(ballow) > 0
		deny = append(deny, bdeny...)
		if len(ballow) == 0 {
			allow = nil
		}
	}
	slices.Sort(out.Missing)
	switch {
	case len(deny) > 0:
		out.Decision, out.Matched = DecisionExplicitDeny, deny
	case len(allow) > 0:
		out.Decision, out.Matched = DecisionAllowed, allow
	default:
		out.Decision = DecisionImplicitDeny
	}
	return out
}

// matches returns the statements of set that apply to r, by effect, and
// adds to missing the condition keys of statements matching the action
// and resource that r lacks.
func matches(set []Named, r Request, missing *[]string) (deny, allow []MatchedStatement) {
	for _, n := range set {
		vars := n.Doc.Version == Version
		for i, s := range n.Doc.Statements {
			if !s.matchAction(r.Action) || !s.matchResource(r, vars) {
				continue
			}
			for _, c := range s.Conditions {
				k := strings.ToLower(c.Key)
				if _, ok := r.value(k); !ok && !slices.Contains(*missing, k) {
					*missing = append(*missing, k)
				}
			}
			if !s.applies(r, vars) {
				continue
			}
			m := MatchedStatement{Policy: n, Index: i}
			if s.Effect == Deny {
				deny = append(deny, m)
			} else {
				allow = append(allow, m)
			}
		}
	}
	return deny, allow
}
