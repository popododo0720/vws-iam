package policy

import "fmt"

// EvaluateBounded intersects identity and session permissions with a permissions
// boundary. A nil boundary imposes no limit. A non-nil empty one allows nothing.
func EvaluateBounded(r Request, identity, session, boundary []Named) Decision {
	d := Evaluate(r, identity, session)
	if boundary == nil {
		return d
	}
	b := Evaluate(r, boundary, nil)
	if d.Explicit {
		return d
	}
	if b.Explicit {
		return b
	}
	if d.Allowed && !b.Allowed {
		b.Reason = fmt.Sprintf("no permissions boundary allows %s on %s", r.Action, r.Resource)
		return b
	}
	return d
}
