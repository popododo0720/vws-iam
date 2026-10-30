// Package authz answers Authorize: it gathers a principal's identity
// policies from the store (user inline and managed, its groups' inline and
// managed, or a role's) and evaluates them with package policy.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

// PrincipalKind says whether a principal is a user or an assumed role.
type PrincipalKind int

// Principal kinds.
const (
	User PrincipalKind = iota
	Role
	// Root is the project's root user: not subject to identity policies.
	Root
)

// Principal is the authenticated caller.
type Principal struct {
	Kind PrincipalKind
	Name string // user or role name
	// ARN overrides the computed ARN, e.g. an assumed-role session ARN.
	ARN string
	// SessionPolicies narrow an STS session; nil means none.
	SessionPolicies []string
}

// Authorizer evaluates requests against stored policies.
type Authorizer struct {
	b       store.Backend
	account string
	now     func() time.Time
}

// New returns an Authorizer for account. now may be nil.
func New(b store.Backend, account string, now func() time.Time) *Authorizer {
	if now == nil {
		now = time.Now
	}
	return &Authorizer{b: b, account: account, now: now}
}

// ErrNoSuchEntity is an unknown principal or policy.
var ErrNoSuchEntity = errors.New("NoSuchEntity")

func (a *Authorizer) managed(ctx context.Context, arn string) (policy.Named, error) {
	i := strings.LastIndex(arn, "/")
	if !strings.HasPrefix(arn, "arn:vws:iam::"+a.account+":policy/") || i < 0 {
		return policy.Named{}, fmt.Errorf("policy %q: %w", arn, ErrNoSuchEntity)
	}
	p, err := store.Get[iam.Policy](ctx, a.b, arn[i+1:])
	if errors.Is(err, store.ErrNotFound) {
		return policy.Named{}, fmt.Errorf("policy %q: %w", arn, ErrNoSuchEntity)
	}
	if err != nil {
		return policy.Named{}, err
	}
	d, err := policy.ParseIdentity(p.Object.Default())
	if err != nil {
		return policy.Named{}, fmt.Errorf("stored policy %q: %w", arn, err)
	}
	return policy.Named{Name: arn, Doc: d}, nil
}

func (a *Authorizer) collect(ctx context.Context, owner string, attached []string, inline map[string]string, out []policy.Named) ([]policy.Named, error) {
	for _, arn := range attached {
		n, err := a.managed(ctx, arn)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	for name, doc := range inline {
		// Inline documents are held to the aggregate size quota on write,
		// not to policy.MaxSize, so parse them the way the write path did.
		d, err := policy.ParseInline(doc)
		if err != nil {
			return nil, fmt.Errorf("inline policy %s/%s: %w", owner, name, err)
		}
		out = append(out, policy.Named{Name: owner + ":inline/" + name, Doc: d})
	}
	return out, nil
}

// IdentityPolicies returns every identity policy that applies to p.
func (a *Authorizer) IdentityPolicies(ctx context.Context, p Principal) ([]policy.Named, string, error) {
	var out []policy.Named
	switch p.Kind {
	case User:
		u, err := store.Get[iam.User](ctx, a.b, p.Name)
		if errors.Is(err, store.ErrNotFound) {
			return nil, "", fmt.Errorf("user %q: %w", p.Name, ErrNoSuchEntity)
		}
		if err != nil {
			return nil, "", err
		}
		arn := iam.UserARN(a.account, u.Object)
		if out, err = a.collect(ctx, arn, u.Object.AttachedPolicies, u.Object.InlinePolicies, out); err != nil {
			return nil, "", err
		}
		// While a rename is in flight some groups may still list the
		// other name; both name this user (#134).
		partner, err := RenamePartner(ctx, a.b, u.Object)
		if err != nil {
			return nil, "", err
		}
		groups, err := GroupsOf(ctx, a.b, u.Object.Name, partner)
		if err != nil {
			return nil, "", err
		}
		for _, g := range groups {
			if out, err = a.collect(ctx, iam.GroupARN(a.account, g), g.AttachedPolicies, g.InlinePolicies, out); err != nil {
				return nil, "", err
			}
		}
		return out, arn, nil
	case Role:
		r, err := store.Get[iam.Role](ctx, a.b, p.Name)
		if errors.Is(err, store.ErrNotFound) {
			return nil, "", fmt.Errorf("role %q: %w", p.Name, ErrNoSuchEntity)
		}
		if err != nil {
			return nil, "", err
		}
		arn := iam.RoleARN(a.account, r.Object)
		out, err = a.collect(ctx, arn, r.Object.AttachedPolicies, r.Object.InlinePolicies, out)
		return out, arn, err
	}
	return nil, "", fmt.Errorf("principal kind %d: %w", p.Kind, ErrNoSuchEntity)
}

// Authorize decides whether p may perform action on resource. reqCtx
// carries request keys such as aws:SourceIp and aws:MultiFactorAuthPresent;
// aws:username, aws:PrincipalArn, aws:userid and aws:CurrentTime are set here.
func (a *Authorizer) Authorize(ctx context.Context, p Principal, action, resource string, reqCtx map[string][]string) (policy.Decision, error) {
	if p.Kind == Root {
		return policy.Decision{Allowed: true, Reason: "root user"}, nil
	}
	ids, arn, err := a.IdentityPolicies(ctx, p)
	if err != nil {
		return policy.Decision{}, err
	}
	if p.ARN != "" {
		arn = p.ARN
	}
	var session []policy.Named
	if p.SessionPolicies != nil {
		session = []policy.Named{}
		for i, doc := range p.SessionPolicies {
			d, err := policy.ParseIdentity(doc)
			if err != nil {
				return policy.Decision{}, fmt.Errorf("session policy %d: %w", i, err)
			}
			session = append(session, policy.Named{Name: fmt.Sprintf("session-%d", i), Doc: d})
		}
	}
	c := make(map[string][]string, len(reqCtx)+4)
	for k, v := range reqCtx {
		c[strings.ToLower(k)] = v
	}
	c["aws:principalarn"] = []string{arn}
	c["aws:currenttime"] = []string{a.now().UTC().Format(time.RFC3339)}
	if p.Kind == User {
		c["aws:username"] = []string{p.Name}
	}
	r := policy.Request{Principal: arn, Account: a.account, Action: action, Resource: resource, Context: c}
	return policy.Evaluate(r, ids, session), nil
}

// RenamePartner returns the other name of u's in-flight rename while that
// name still holds u's counterpart: the same UID with the reciprocal
// marker (RenameTo naming u on the old object, RenamedFrom on the new
// one). Otherwise it is "": a rename that deleted the old object moved
// every reference first, and a user created again under the old name is
// someone else, whose groups u must not inherit (#134).
func RenamePartner(ctx context.Context, b store.Backend, u iam.User) (string, error) {
	other := u.RenamePartner()
	if other == "" {
		return "", nil
	}
	v, err := store.Get[iam.User](ctx, b, other)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	back := v.Object.RenameTo
	if u.RenameTo != "" {
		back = v.Object.RenamedFrom
	}
	if v.Object.UID != u.UID || store.Fold(back) != store.Fold(u.Name) {
		return "", nil
	}
	return other, nil
}

// GroupsOf returns the groups whose members include one of names. The
// new copy of a group whose rename has not committed is left out
// (store.Visible).
func GroupsOf(ctx context.Context, b store.Backend, names ...string) ([]iam.Group, error) {
	all, err := store.List[iam.Group](ctx, b)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, n := range names {
		if n != "" {
			want[store.Fold(n)] = true
		}
	}
	var out []iam.Group
	for _, g := range store.Visible(all) {
		for _, m := range g.Object.Members {
			if want[store.Fold(m)] {
				out = append(out, g.Object)
				break
			}
		}
	}
	return out, nil
}
