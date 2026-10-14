// Package policy parses and evaluates IAM JSON policy documents with AWS
// semantics: an explicit Deny beats an Allow, and anything not allowed is
// implicitly denied. It is pure.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// ErrMalformed is MalformedPolicyDocument.
var ErrMalformed = errors.New("MalformedPolicyDocument")

// Version is the only accepted policy language version.
const Version = "2012-10-17"

// MaxSize bounds a document, like the AWS managed-policy limit.
const MaxSize = 6144

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, a...))
}

// Effect is Allow or Deny.
type Effect string

// Effects.
const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Document is a parsed policy.
type Document struct {
	ID         string
	Statements []Statement
}

// Statement is one parsed statement.
type Statement struct {
	Sid       string
	Effect    Effect
	Actions   []string
	NotAction bool
	Resources []string
	NotRes    bool
	// Principals maps a principal type (AWS, Service, *) to patterns.
	Principals   map[string][]string
	NotPrincipal bool
	Conditions   []Condition
}

// Condition is one operator, key and value set.
type Condition struct {
	Op       string // base operator, e.g. StringLike
	IfExists bool
	Key      string
	Values   []string
}

type rawStatement struct {
	Sid          string                                `json:"Sid"`
	Effect       string                                `json:"Effect"`
	Action       json.RawMessage                       `json:"Action"`
	NotAction    json.RawMessage                       `json:"NotAction"`
	Resource     json.RawMessage                       `json:"Resource"`
	NotResource  json.RawMessage                       `json:"NotResource"`
	Principal    json.RawMessage                       `json:"Principal"`
	NotPrincipal json.RawMessage                       `json:"NotPrincipal"`
	Condition    map[string]map[string]json.RawMessage `json:"Condition"`
}

type rawDoc struct {
	Version   string          `json:"Version"`
	ID        string          `json:"Id"`
	Statement json.RawMessage `json:"Statement"`
}

func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return malformed("%v", err)
	}
	if dec.More() {
		return malformed("trailing data")
	}
	return nil
}

// stringOrList decodes "x" or ["x","y"]; scalars like true or 1 become strings.
func stringOrList(b json.RawMessage) ([]string, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, nil
	}
	if b[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, malformed("%v", err)
		}
		if len(raw) == 0 {
			return nil, malformed("empty list")
		}
		out := make([]string, 0, len(raw))
		for _, r := range raw {
			s, err := scalar(r)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	s, err := scalar(b)
	if err != nil {
		return nil, err
	}
	return []string{s}, nil
}

func scalar(b json.RawMessage) (string, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", malformed("%v", err)
	}
	switch v := v.(type) {
	case string:
		return v, nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case float64:
		return string(bytes.TrimSpace(b)), nil
	}
	return "", malformed("value %s is not a string", b)
}

// Parse validates and parses a policy document.
func Parse(doc string) (*Document, error) {
	if len(doc) > MaxSize {
		return nil, malformed("document is %d bytes, limit %d", len(doc), MaxSize)
	}
	var rd rawDoc
	if err := strictDecode([]byte(doc), &rd); err != nil {
		return nil, err
	}
	if rd.Version != Version {
		return nil, malformed("Version must be %q", Version)
	}
	var raws []rawStatement
	st := bytes.TrimSpace(rd.Statement)
	switch {
	case len(st) == 0:
		return nil, malformed("no Statement")
	case st[0] == '[':
		var list []json.RawMessage
		if err := json.Unmarshal(st, &list); err != nil {
			return nil, malformed("%v", err)
		}
		for _, r := range list {
			var s rawStatement
			if err := strictDecode(r, &s); err != nil {
				return nil, err
			}
			raws = append(raws, s)
		}
	default:
		var s rawStatement
		if err := strictDecode(st, &s); err != nil {
			return nil, err
		}
		raws = append(raws, s)
	}
	if len(raws) == 0 {
		return nil, malformed("no Statement")
	}
	d := &Document{ID: rd.ID}
	sids := map[string]bool{}
	for i, r := range raws {
		s, err := statement(r)
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		if s.Sid != "" {
			if sids[s.Sid] {
				return nil, malformed("duplicate Sid %q", s.Sid)
			}
			sids[s.Sid] = true
		}
		d.Statements = append(d.Statements, s)
	}
	return d, nil
}

func exactlyOne(a, b json.RawMessage, what string) (json.RawMessage, bool, error) {
	ha, hb := len(bytes.TrimSpace(a)) > 0, len(bytes.TrimSpace(b)) > 0
	switch {
	case ha && hb:
		return nil, false, malformed("both %s and Not%s", what, what)
	case hb:
		return b, true, nil
	}
	return a, false, nil
}

func statement(r rawStatement) (Statement, error) {
	s := Statement{Sid: r.Sid, Effect: Effect(r.Effect)}
	if s.Effect != Allow && s.Effect != Deny {
		return s, malformed("Effect %q", r.Effect)
	}
	act, not, err := exactlyOne(r.Action, r.NotAction, "Action")
	if err != nil {
		return s, err
	}
	if s.Actions, err = stringOrList(act); err != nil {
		return s, err
	}
	if len(s.Actions) == 0 {
		return s, malformed("no Action")
	}
	s.NotAction = not
	for _, a := range s.Actions {
		if a != "*" && (strings.Count(a, ":") != 1 || strings.HasPrefix(a, ":") || strings.HasSuffix(a, ":")) {
			return s, malformed("Action %q is not service:action", a)
		}
	}
	res, notRes, err := exactlyOne(r.Resource, r.NotResource, "Resource")
	if err != nil {
		return s, err
	}
	if s.Resources, err = stringOrList(res); err != nil {
		return s, err
	}
	s.NotRes = notRes
	for _, x := range s.Resources {
		if x != "*" && !strings.HasPrefix(x, "arn:") {
			return s, malformed("Resource %q is not an ARN", x)
		}
	}
	pr, notPr, err := exactlyOne(r.Principal, r.NotPrincipal, "Principal")
	if err != nil {
		return s, err
	}
	if len(bytes.TrimSpace(pr)) > 0 {
		if s.Principals, err = principals(pr); err != nil {
			return s, err
		}
	}
	s.NotPrincipal = notPr
	if len(s.Resources) == 0 && s.Principals == nil {
		return s, malformed("statement has neither Resource nor Principal")
	}
	for op, keys := range r.Condition {
		base, ifExists := strings.CutSuffix(op, "IfExists")
		if _, ok := operators[base]; !ok {
			return s, malformed("condition operator %q is not supported", op)
		}
		if len(keys) == 0 {
			return s, malformed("condition %q has no keys", op)
		}
		for k, raw := range keys {
			vals, err := stringOrList(raw)
			if err != nil {
				return s, err
			}
			if err := checkValues(base, vals); err != nil {
				return s, err
			}
			s.Conditions = append(s.Conditions, Condition{Op: base, IfExists: ifExists, Key: strings.ToLower(k), Values: vals})
		}
	}
	return s, nil
}

func principals(b json.RawMessage) (map[string][]string, error) {
	b = bytes.TrimSpace(b)
	var star string
	if json.Unmarshal(b, &star) == nil {
		if star != "*" {
			return nil, malformed("Principal %q", star)
		}
		return map[string][]string{"*": {"*"}}, nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, malformed("Principal: %v", err)
	}
	out := map[string][]string{}
	for typ, raw := range m {
		if typ != "AWS" && typ != "Service" && typ != "Federated" {
			return nil, malformed("Principal type %q", typ)
		}
		vals, err := stringOrList(raw)
		if err != nil {
			return nil, err
		}
		out[typ] = vals
	}
	return out, nil
}

func checkValues(op string, vals []string) error {
	for _, v := range vals {
		switch operators[op].kind {
		case kindBool, kindNull:
			if v != "true" && v != "false" {
				return malformed("%s value %q", op, v)
			}
		case kindIP:
			if _, err := parseIP(v); err != nil {
				return malformed("%s value %q", op, v)
			}
		case kindNumeric:
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				return malformed("%s value %q", op, v)
			}
		case kindDate:
			if _, err := parseDate(v); err != nil {
				return malformed("%s value %q", op, v)
			}
		}
	}
	return nil
}

func parseIP(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("prefix: %w", err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("address: %w", err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parseDate(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04Z07:00", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	var epoch int64
	if _, err := fmt.Sscanf(s, "%d", &epoch); err == nil && fmt.Sprint(epoch) == s {
		return time.Unix(epoch, 0), nil
	}
	return time.Time{}, errors.New("not a date")
}
