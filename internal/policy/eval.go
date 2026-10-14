package policy

import (
	"fmt"
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
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
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

// expand substitutes ${key} policy variables. ok is false when a variable
// is not in the request, which makes the element not match.
func (r Request) expand(s string) (string, bool) {
	if !strings.Contains(s, "${") {
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

func (s Statement) matchResource(r Request) bool {
	if s.Resources == nil {
		return true // trust policies name no resource
	}
	m := false
	for _, p := range s.Resources {
		if p, ok := r.expand(p); ok && Match(p, r.Resource, false) {
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

func (c Condition) eval(r Request) bool {
	o := operators[c.Op]
	got, present := r.value(c.Key)
	if o.kind == kindNull {
		want := c.Values[0] == "true"
		return (!present || len(got) == 0) == want
	}
	if !present || len(got) == 0 {
		// A missing key fails a positive operator and passes a negated
		// one; IfExists passes either way.
		return c.IfExists || o.negate
	}
	hit := false
	for _, g := range got {
		for _, v := range c.Values {
			if v, ok := r.expand(v); ok && o.match(g, v) {
				hit = true
			}
		}
	}
	return hit != o.negate
}

func (s Statement) applies(r Request) bool {
	if !s.matchAction(r.Action) || !s.matchResource(r) || !s.matchPrincipal(r) {
		return false
	}
	for _, c := range s.Conditions {
		if !c.eval(r) {
			return false
		}
	}
	return true
}

// Named is a parsed policy with the name used in reasons.
type Named struct {
	Name string
	Doc  *Document
}

// Decision is the result of an evaluation.
type Decision struct {
	Allowed bool
	Reason  string
}

func label(n Named, s Statement) string {
	if s.Sid != "" {
		return n.Name + "/" + s.Sid
	}
	return n.Name
}

// scan returns the first explicit deny and the first allow in set.
func scan(set []Named, r Request) (deny, allow string) {
	for _, n := range set {
		for _, s := range n.Doc.Statements {
			if !s.applies(r) {
				continue
			}
			if s.Effect == Deny && deny == "" {
				deny = label(n, s)
			}
			if s.Effect == Allow && allow == "" {
				allow = label(n, s)
			}
		}
	}
	return deny, allow
}

// Evaluate applies identity policies and, when sessionPolicies is non-nil,
// session policies that can only narrow the identity's permissions.
func Evaluate(r Request, identity []Named, sessionPolicies []Named) Decision {
	deny, allow := scan(identity, r)
	var sdeny, sallow string
	if sessionPolicies != nil {
		sdeny, sallow = scan(sessionPolicies, r)
	}
	switch {
	case deny != "":
		return Decision{Reason: "explicit deny in " + deny}
	case sdeny != "":
		return Decision{Reason: "explicit deny in session policy " + sdeny}
	case allow == "":
		return Decision{Reason: fmt.Sprintf("no identity-based policy allows %s on %s", r.Action, r.Resource)}
	case sessionPolicies != nil && sallow == "":
		return Decision{Reason: fmt.Sprintf("no session policy allows %s on %s", r.Action, r.Resource)}
	}
	return Decision{Allowed: true, Reason: "allowed by " + allow}
}
