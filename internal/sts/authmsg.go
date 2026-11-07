package sts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
)

// ErrInvalidAuthorizationMessage is AWS InvalidAuthorizationMessageException:
// the encoded message is malformed, tampered with, from another project,
// sealed under an unknown KEK, or expired.
var ErrInvalidAuthorizationMessage = errors.New("InvalidAuthorizationMessageException")

// Encoded authorization message limits.
const (
	// MaxEncodedMessageLen is the AWS EncodedMessage length limit.
	MaxEncodedMessageLen = 10240
	// AuthorizationMessageTTL is how long an encoded message can be
	// decoded. AWS documents that a message expires but not when; VWS
	// keeps it as long as a default GetSessionToken session.
	AuthorizationMessageTTL = DefaultSessionDuration
	authMessageAAD          = "sts/authorization-message"
	// DecodeAction is the permission DecodeAuthorizationMessage needs.
	DecodeAction = "sts:DecodeAuthorizationMessage"
)

// Items is the AWS list wrapper of a decoded message: {"items":[...]}.
type Items[T any] struct {
	Items []T `json:"items"`
}

// MarshalJSON writes no items as [], never null, also for a message
// sealed by a release whose statements had fewer lists.
func (i Items[T]) MarshalJSON() ([]byte, error) {
	if i.Items == nil {
		i.Items = []T{}
	}
	b, err := json.Marshal(struct {
		Items []T `json:"items"`
	}{i.Items})
	if err != nil {
		return nil, fmt.Errorf("authorization message items: %w", err)
	}
	return b, nil
}

// Value is one AWS list value: {"value":"..."}.
type Value struct {
	Value string `json:"value"`
}

// MatchedStatement is a statement that decided the request, in the AWS
// shape. A NotAction, NotResource or NotPrincipal statement lists no
// actions, resources or principals: AWS has no field for the negation.
type MatchedStatement struct {
	StatementID string `json:"statementId"`
	// Effect is "ALLOW" or "DENY", as AWS writes it.
	Effect string `json:"effect"`
	// SourcePolicyName names the policy that holds the statement.
	SourcePolicyName string `json:"sourcePolicyName,omitempty"`
	// Principals is the unique id of the user or role that holds the
	// policy, and the patterns of the statement's Principal element;
	// PrincipalGroups the unique id of the group that holds it.
	Principals      Items[Value]     `json:"principals"`
	PrincipalGroups Items[Value]     `json:"principalGroups"`
	Actions         Items[Value]     `json:"actions"`
	Resources       Items[Value]     `json:"resources"`
	Conditions      Items[Condition] `json:"conditions"`
}

// Condition is one condition key of the request context.
type Condition struct {
	Key    string       `json:"key"`
	Values Items[Value] `json:"values"`
}

// MessagePrincipal is the caller of the denied request.
type MessagePrincipal struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	ARN  string `json:"arn"`
}

// MessageContext is what the request asked for.
type MessageContext struct {
	Principal  MessagePrincipal `json:"principal"`
	Action     string           `json:"action"`
	Resource   string           `json:"resource"`
	Conditions Items[Condition] `json:"conditions"`
}

// AuthorizationMessage is the decoded message, in the JSON shape AWS
// DecodeAuthorizationMessage returns.
type AuthorizationMessage struct {
	Allowed           bool                    `json:"allowed"`
	ExplicitDeny      bool                    `json:"explicitDeny"`
	MatchedStatements Items[MatchedStatement] `json:"matchedStatements"`
	Failures          Items[Value]            `json:"failures"`
	Context           MessageContext          `json:"context"`
}

// NewAuthorizationMessage describes the decision d on action and resource
// for principal, with the context d evaluated (keys sorted, so the same
// request always reads the same).
func NewAuthorizationMessage(
	principal MessagePrincipal, action, resource string, d policy.Decision,
) AuthorizationMessage {
	m := AuthorizationMessage{
		Allowed:           d.Allowed,
		ExplicitDeny:      d.Explicit,
		MatchedStatements: Items[MatchedStatement]{Items: []MatchedStatement{}},
		Failures:          Items[Value]{Items: []Value{}},
		Context: MessageContext{
			Principal: principal, Action: action, Resource: resource,
			Conditions: Items[Condition]{Items: []Condition{}},
		},
	}
	if d.Policy != "" {
		m.MatchedStatements.Items = append(m.MatchedStatements.Items, matchedStatement(d))
	}
	for _, k := range slices.Sorted(maps.Keys(d.Context)) {
		m.Context.Conditions.Items = append(m.Context.Conditions.Items, condition(k, d.Context[k]))
	}
	return m
}

func matchedStatement(d policy.Decision) MatchedStatement {
	effect := "ALLOW"
	if d.Explicit {
		effect = "DENY"
	}
	st := MatchedStatement{
		StatementID: d.Statement, Effect: effect, SourcePolicyName: d.Policy,
		Principals: values(nil), PrincipalGroups: values(nil), Actions: values(nil), Resources: values(nil),
		Conditions: Items[Condition]{Items: []Condition{}},
	}
	if d.Matched == nil {
		return st
	}
	s, h := d.Matched.Statement, d.Matched.Holder
	switch {
	case h.ID != "" && h.Group:
		st.PrincipalGroups = values([]string{h.ID})
	case h.ID != "":
		st.Principals = values([]string{h.ID})
	}
	if !s.NotPrincipal {
		for _, t := range slices.Sorted(maps.Keys(s.Principals)) {
			st.Principals.Items = append(st.Principals.Items, values(s.Principals[t]).Items...)
		}
	}
	if !s.NotAction {
		st.Actions = values(s.Actions)
	}
	if !s.NotRes {
		st.Resources = values(s.Resources)
	}
	for _, c := range s.Conditions {
		st.Conditions.Items = append(st.Conditions.Items, condition(c.Key, c.Values))
	}
	return st
}

func condition(key string, vs []string) Condition {
	return Condition{Key: key, Values: values(vs)}
}

func values(vs []string) Items[Value] {
	out := Items[Value]{Items: make([]Value, 0, len(vs))}
	for _, v := range vs {
		out.Items = append(out.Items, Value{Value: v})
	}
	return out
}

// envelope is the sealed plaintext of an encoded message.
type envelope struct {
	Project  string               `json:"project"`
	IssuedAt time.Time            `json:"issuedAt"`
	Message  AuthorizationMessage `json:"message"`
}

// EncodeAuthorizationMessage seals m for this project with AES-256-GCM
// under the active KEK, so only DecodeAuthorizationMessage in the same
// project can read it and any change is detected. Until the encoded
// message fits MaxEncodedMessageLen, items are dropped from the end of
// the context's condition keys, then of each matched statement's
// conditions, resources, actions, principal groups and principals, in
// that order; a message that still does not fit is an error.
func (s *Service) EncodeAuthorizationMessage(m AuthorizationMessage) (string, error) {
	env := envelope{Project: s.account, IssuedAt: s.now().UTC(), Message: m}
	msg := &env.Message
	msg.Context.Conditions.Items = slices.Clone(m.Context.Conditions.Items)
	msg.MatchedStatements.Items = slices.Clone(m.MatchedStatements.Items)
	trims := []func() bool{func() bool { return pop(&msg.Context.Conditions.Items) }}
	for i := range msg.MatchedStatements.Items {
		st := &msg.MatchedStatements.Items[i]
		st.Conditions.Items = slices.Clone(st.Conditions.Items)
		st.Resources.Items = slices.Clone(st.Resources.Items)
		st.Actions.Items = slices.Clone(st.Actions.Items)
		st.PrincipalGroups.Items = slices.Clone(st.PrincipalGroups.Items)
		st.Principals.Items = slices.Clone(st.Principals.Items)
		trims = append(trims,
			func() bool { return pop(&st.Conditions.Items) },
			func() bool { return pop(&st.Resources.Items) },
			func() bool { return pop(&st.Actions.Items) },
			func() bool { return pop(&st.PrincipalGroups.Items) },
			func() bool { return pop(&st.Principals.Items) },
		)
	}
	for {
		enc, err := s.seal(env)
		if err != nil {
			return "", err
		}
		if len(enc) <= MaxEncodedMessageLen {
			return enc, nil
		}
		for len(trims) > 0 && !trims[0]() {
			trims = trims[1:]
		}
		if len(trims) == 0 {
			return "", fmt.Errorf("%w: authorization message is longer than %d characters",
				ErrInvalidRequest, MaxEncodedMessageLen)
		}
	}
}

// pop drops the last item of s, false when s is empty.
func pop[T any](s *[]T) bool {
	if len(*s) == 0 {
		return false
	}
	*s = (*s)[:len(*s)-1]
	return true
}

func (s *Service) seal(env envelope) (string, error) {
	b, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("authorization message: %w", err)
	}
	sealed, err := s.keys.Seal(b, authMessageAAD+"/"+s.account)
	if err != nil {
		return "", err
	}
	return sealed.KeyID + "." + base64.RawURLEncoding.EncodeToString(sealed.Ciphertext), nil
}

// DecodeAuthorizationMessage returns the decoded JSON of an encoded
// message to a caller whose policies allow sts:DecodeAuthorizationMessage.
// The permission is checked before the message is opened, so a caller
// without it learns nothing about the message, not even whether it is
// valid. It only reads, so a repeat returns the same JSON.
func (s *Service) DecodeAuthorizationMessage(
	ctx context.Context, c Caller, reqCtx map[string][]string, encoded string,
) (_ string, err error) {
	ctx, end := start(ctx, "DecodeAuthorizationMessage")
	defer end(&err)
	if c.principalID == "" {
		return "", fmt.Errorf("%w: unresolved caller", ErrAccessDenied)
	}
	if n := len(encoded); n < 1 || n > MaxEncodedMessageLen {
		return "", fmt.Errorf("%w: EncodedMessage length %d outside [1, %d]", ErrInvalidRequest, n, MaxEncodedMessageLen)
	}
	d, err := s.authz.Authorize(ctx, c.principal, DecodeAction, "*", s.callerContext(c, reqCtx))
	if err != nil {
		return "", err
	}
	if !d.Allowed {
		return "", fmt.Errorf("%w: not authorized to perform %s", ErrAccessDenied, DecodeAction)
	}
	env, err := s.openMessage(encoded)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(env.Message)
	if err != nil {
		return "", fmt.Errorf("authorization message: %w", err)
	}
	return string(out), nil
}

// notMessageChar reports a rune outside the alphabet of an encoded message: a KEK id, ".", and
// unpadded base64url. Anything else, such as a line break (which the
// base64 decoder would skip), makes the message invalid, as in AWS.
func notMessageChar(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		return false
	}
	return true
}

func (s *Service) openMessage(encoded string) (envelope, error) {
	i := strings.LastIndexByte(encoded, '.')
	if i <= 0 || strings.ContainsFunc(encoded, notMessageChar) {
		return envelope{}, fmt.Errorf("%w: malformed message", ErrInvalidAuthorizationMessage)
	}
	// Strict: a changed trailing bit of the last character is tampering
	// too, not another spelling of the same ciphertext.
	ct, err := base64.RawURLEncoding.Strict().DecodeString(encoded[i+1:])
	if err != nil {
		return envelope{}, fmt.Errorf("%w: malformed message", ErrInvalidAuthorizationMessage)
	}
	plain, err := s.keys.Open(iam.Sealed{KeyID: encoded[:i], Ciphertext: ct}, authMessageAAD+"/"+s.account)
	if err != nil {
		return envelope{}, fmt.Errorf("%w: the message cannot be opened", ErrInvalidAuthorizationMessage)
	}
	var env envelope
	if err := json.Unmarshal(plain, &env); err != nil || env.Project != s.account {
		return envelope{}, fmt.Errorf("%w: the message cannot be opened", ErrInvalidAuthorizationMessage)
	}
	if !s.now().Before(env.IssuedAt.Add(AuthorizationMessageTTL)) {
		return envelope{}, fmt.Errorf("%w: the message has expired", ErrInvalidAuthorizationMessage)
	}
	return env, nil
}
