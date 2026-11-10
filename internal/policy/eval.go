package policy

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

type opKind int

const (
	kindString opKind = iota
	kindArn
	kindBool
	kindIP
	kindDate
	kindNull
	kindNumeric
)

type op struct {
	kind   opKind
	negate bool
	match  func(ctxVal, polVal string) bool
}

var operators = map[string]op{}

func init() {
	eq := func(a, b string) bool { return a == b }
	fold := strings.EqualFold
	like := func(a, b string) bool { return Match(b, a, false) }
	arnLike := func(a, b string) bool { return arnMatch(b, a) }
	ip := func(a, b string) bool {
		p, err := parseIP(b)
		addr, aerr := parseIP(a)
		return err == nil && aerr == nil && p.Contains(addr.Addr())
	}
	date := func(cmp func(a, b time.Time) bool) func(string, string) bool {
		return func(a, b string) bool {
			ta, err1 := parseDate(a)
			tb, err2 := parseDate(b)
			return err1 == nil && err2 == nil && cmp(ta, tb)
		}
	}
	add := func(name string, k opKind, f func(string, string) bool) {
		operators[name] = op{kind: k, match: f}
		if k != kindBool && k != kindDate {
			operators[notName(name)] = op{kind: k, negate: true, match: f}
		}
	}
	add("StringEquals", kindString, eq)
	add("StringEqualsIgnoreCase", kindString, fold)
	add("StringLike", kindString, like)
	add("ArnEquals", kindArn, eq)
	add("ArnLike", kindArn, arnLike)
	add("IpAddress", kindIP, ip)
	num := func(cmp func(a, b float64) bool) func(string, string) bool {
		return func(a, b string) bool {
			x, err1 := strconv.ParseFloat(a, 64)
			y, err2 := strconv.ParseFloat(b, 64)
			return err1 == nil && err2 == nil && cmp(x, y)
		}
	}
	operators["NumericEquals"] = op{kind: kindNumeric, match: num(func(a, b float64) bool { return a == b })}
	operators["NumericNotEquals"] = op{kind: kindNumeric, negate: true, match: num(func(a, b float64) bool { return a == b })}
	operators["NumericLessThan"] = op{kind: kindNumeric, match: num(func(a, b float64) bool { return a < b })}
	operators["NumericLessThanEquals"] = op{kind: kindNumeric, match: num(func(a, b float64) bool { return a <= b })}
	operators["NumericGreaterThan"] = op{kind: kindNumeric, match: num(func(a, b float64) bool { return a > b })}
	operators["NumericGreaterThanEquals"] = op{kind: kindNumeric, match: num(func(a, b float64) bool { return a >= b })}
	operators["Bool"] = op{kind: kindBool, match: fold}
	operators["Null"] = op{kind: kindNull}
	operators["DateEquals"] = op{kind: kindDate, match: date(time.Time.Equal)}
	operators["DateNotEquals"] = op{kind: kindDate, negate: true, match: date(time.Time.Equal)}
	operators["DateLessThan"] = op{kind: kindDate, match: date(time.Time.Before)}
	operators["DateLessThanEquals"] = op{kind: kindDate, match: date(func(a, b time.Time) bool { return !a.After(b) })}
	operators["DateGreaterThan"] = op{kind: kindDate, match: date(time.Time.After)}
	operators["DateGreaterThanEquals"] = op{kind: kindDate, match: date(func(a, b time.Time) bool { return !a.Before(b) })}
}

func notName(name string) string {
	switch name {
	case "IpAddress":
		return "NotIpAddress"
	case "StringEquals", "StringEqualsIgnoreCase", "StringLike", "ArnEquals", "ArnLike":
		for _, p := range []string{"String", "Arn"} {
			if rest, ok := strings.CutPrefix(name, p); ok {
				return p + "Not" + rest
			}
		}
	}
	return "Not" + name
}

// Match reports whether s matches pattern with * (any run) and ? (one
// character), in linear time. fold makes it case-insensitive.
func Match(pattern, s string, fold bool) bool {
	if fold {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// arnMatch compares the six ARN components separately, as ArnLike does.
func arnMatch(pattern, arn string) bool {
	pp := strings.SplitN(pattern, ":", 6)
	ap := strings.SplitN(arn, ":", 6)
	if len(pp) != 6 || len(ap) != 6 {
		return false
	}
	for i := range pp {
		if !Match(pp[i], ap[i], false) {
			return false
		}
	}
	return true
}

// Request is what is being authorized. Context keys are matched
// case-insensitively (aws:SourceIp, aws:MultiFactorAuthPresent, ...).
type Request struct {
	Principal string // ARN of the caller
	Account   string // the caller's account
	Service   string // a service principal, for trust policies
	// Federated is the identity provider ARN (saml-provider) of a
	// federated caller, matched by a trust policy's "Federated" principal.
	Federated string
	Action    string // e.g. ec2:RunInstances
	Resource  string // ARN
	Context   map[string][]string
}

func (r Request) value(key string) ([]string, bool) {
	for k, v := range r.Context {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// expand substitutes ${key} policy variables when vars is set (Version
// 2012-10-17); otherwise s is literal. ok is false when a variable is not
// in the request, which makes the element not match.
func (r Request) expand(s string, vars bool) (string, bool) {
	if !vars || !strings.Contains(s, "${") {
		return s, true
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		b.WriteString(s[:i])
		name := s[i+2 : i+j]
		switch name {
		case "*", "?", "$":
			b.WriteString(name)
		default:
			v, ok := r.value(name)
			if !ok || len(v) != 1 {
				return "", false
			}
			b.WriteString(v[0])
		}
		s = s[i+j+1:]
	}
}

// unresolved returns the policy variables of s (Version 2012-10-17) that
// the request does not carry, lowercase, and s with each of them replaced
// by "*" and the others substituted, so a caller can tell whether s could
// match once they are given.
func (r Request) unresolved(s string) (string, []string) {
	var missing []string
	var b strings.Builder
	for {
		i := strings.Index(s, "${")
		j := -1
		if i >= 0 {
			j = strings.IndexByte(s[i:], '}')
		}
		if j < 0 {
			b.WriteString(s)
			return b.String(), missing
		}
		b.WriteString(s[:i])
		name := s[i+2 : i+j]
		switch v, ok := r.value(name); {
		case name == "*" || name == "?" || name == "$":
			b.WriteString(name)
		case ok && len(v) == 1:
			b.WriteString(v[0])
		default:
			b.WriteByte('*')
			if !ok {
				missing = append(missing, strings.ToLower(name))
			}
		}
		s = s[i+j+1:]
	}
}

func (s Statement) matchAction(a string) bool {
	m := false
	for _, p := range s.Actions {
		if Match(p, a, true) {
			m = true
			break
		}
	}
	return m != s.NotAction
}

func (s Statement) matchResource(r Request, vars bool) bool {
	if s.Resources == nil {
		return true // trust policies name no resource
	}
	m := false
	for _, p := range s.Resources {
		if p, ok := r.expand(p, vars); ok && Match(p, r.Resource, false) {
			m = true
			break
		}
	}
	return m != s.NotRes
}

func (s Statement) matchPrincipal(r Request) bool {
	if s.Principals == nil {
		return true
	}
	m := false
	for typ, vals := range s.Principals {
		for _, v := range vals {
			switch {
			case typ == "*" || v == "*":
				m = true
			case typ == "Service":
				m = m || (r.Service != "" && v == r.Service)
			case typ == "Federated":
				m = m || (r.Federated != "" && v == r.Federated)
			case typ == "AWS":
				root := "arn:" + Partition + ":iam::" + r.Account + ":root"
				m = m || (r.Principal != "" && v == r.Principal) || (r.Account != "" && (v == r.Account || v == root))
			}
		}
	}
	return m != s.NotPrincipal
}

// Partition is the ARN partition used for account roots.
const Partition = "vws"

func (c Condition) eval(r Request, vars bool) bool {
	o := operators[c.Op]
	got, present := r.value(c.Key)
	if o.kind == kindNull {
		want := c.Values[0] == "true"
		return (!present || len(got) == 0) == want
	}
	if !present || len(got) == 0 {
		switch c.Set {
		case ForAllValues:
			// Every value of an empty set passes.
			return true
		case ForAnyValue:
			// No value can pass, negated or not; IfExists passes.
			return c.IfExists
		}
		// A missing key fails a positive operator and passes a negated
		// one; IfExists passes either way.
		return c.IfExists || o.negate
	}
	// matches reports whether one request value matches some policy value.
	matches := func(g string) bool {
		for _, v := range c.Values {
			if v, ok := r.expand(v, vars); ok && o.match(g, v) {
				return true
			}
		}
		return false
	}
	// A request value passes a negated operator when it matches none of
	// the policy values (a NOR).
	switch c.Set {
	case ForAnyValue:
		return slices.ContainsFunc(got, func(g string) bool { return matches(g) != o.negate })
	case ForAllValues:
		return !slices.ContainsFunc(got, func(g string) bool { return matches(g) == o.negate })
	}
	// Without a set operator, a positive operator holds when any request
	// value matches and a negated one when none does.
	return slices.ContainsFunc(got, matches) != o.negate
}

// applies reports whether s matches r. vars enables policy variables.
func (s Statement) applies(r Request, vars bool) bool {
	if !s.matchAction(r.Action) || !s.matchResource(r, vars) || !s.matchPrincipal(r) {
		return false
	}
	for _, c := range s.Conditions {
		if !c.eval(r, vars) {
			return false
		}
	}
	return true
}

// Named is a parsed policy with the name used in reasons.
type Named struct {
	Name string
	Doc  *Document
	// ID and Type name the policy in simulator results (AWS
	// SourcePolicyId and SourcePolicyType); evaluation ignores them.
	ID, Type string
	// Holder is the identity the policy is attached to, reported with a
	// matched statement; evaluation ignores it.
	Holder Holder
}

// Holder is the unique id of the user, role or (Group) group that holds
// a policy. A session or trust policy has none.
type Holder struct {
	ID    string
	Group bool
}

// Decision is the result of an evaluation.
type Decision struct {
	Allowed bool
	// Explicit is true for an explicit deny.
	Explicit bool
	// Policy and Statement name what decided ALLOW or an explicit deny:
	// the policy name and the statement Sid, or its index as "#n".
	Policy    string
	Statement string
	Reason    string
	// Matched is the statement Policy and Statement name, nil when none.
	Matched *Matched
	// Context is the request context the decision evaluated.
	Context map[string][]string
}

// Matched is the statement that decided an evaluation and the identity
// holding its policy.
type Matched struct {
	Statement Statement
	Holder    Holder
}

type hit struct {
	policy, stmt string
	matched      *Matched
}

func (h hit) String() string {
	if h.policy == "" {
		return ""
	}
	return h.policy + "/" + h.stmt
}

// scan returns the first explicit deny and the first allow in set.
func scan(set []Named, r Request) (deny, allow hit) {
	for _, n := range set {
		vars := n.Doc.Version == Version
		for i, s := range n.Doc.Statements {
			if !s.applies(r, vars) {
				continue
			}
			id := s.Sid
			if id == "" {
				id = "#" + strconv.Itoa(i)
			}
			h := hit{n.Name, id, &Matched{Statement: s, Holder: n.Holder}}
			if s.Effect == Deny && deny.policy == "" {
				deny = h
			}
			if s.Effect == Allow && allow.policy == "" {
				allow = h
			}
		}
	}
	return deny, allow
}

// Evaluate applies identity policies and, when sessionPolicies is non-nil,
// session policies that can only narrow the identity's permissions. The
// decision carries r.Context, the context it evaluated.
func Evaluate(r Request, identity []Named, sessionPolicies []Named) Decision {
	d := decide(r, identity, sessionPolicies)
	d.Context = r.Context
	return d
}

func decide(r Request, identity []Named, sessionPolicies []Named) Decision {
	deny, allow := scan(identity, r)
	var sdeny, sallow hit
	if sessionPolicies != nil {
		sdeny, sallow = scan(sessionPolicies, r)
	}
	switch {
	case deny.policy != "":
		return Decision{
			Explicit: true, Policy: deny.policy, Statement: deny.stmt, Matched: deny.matched,
			Reason: "explicit deny in " + deny.String(),
		}
	case sdeny.policy != "":
		return Decision{
			Explicit: true, Policy: sdeny.policy, Statement: sdeny.stmt, Matched: sdeny.matched,
			Reason: "explicit deny in session policy " + sdeny.String(),
		}
	case allow.policy == "":
		return Decision{Reason: fmt.Sprintf("no identity-based policy allows %s on %s", r.Action, r.Resource)}
	case sessionPolicies != nil && sallow.policy == "":
		return Decision{Reason: fmt.Sprintf("no session policy allows %s on %s", r.Action, r.Resource)}
	}
	return Decision{
		Allowed: true, Policy: allow.policy, Statement: allow.stmt, Matched: allow.matched,
		Reason: "allowed by " + allow.String(),
	}
}
