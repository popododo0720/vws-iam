// Package authz answers Authorize: it gathers a principal's identity
// policies from the store (user inline and managed, its groups' inline and
// managed, or a role's) and evaluates them with package policy.
package authz

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
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
	// Root is the project's root user: not subject to identity policies
	// (a root federated session is still narrowed by its session policies).
	Root
)

// Principal is the authenticated caller.
type Principal struct {
	Kind PrincipalKind
	Name string // user or role name
	// ID is the unique id the principal was resolved as. When set, a
	// stored user or role of that name with another id is a different
	// principal (one deleted and created again), so it is ErrNoSuchEntity.
	ID string
	// ARN overrides the computed ARN, e.g. an assumed-role session ARN.
	ARN string
	// SessionPolicies narrow an STS session; nil means none.
	SessionPolicies []string
	// SessionPolicyARNs are managed session policies, read from the store
	// at each evaluation like attached policies; one that no longer
	// exists fails the evaluation closed (ErrNoSuchEntity), since
	// skipping it could drop a Deny and widen the session.
	SessionPolicyARNs []string
	// Federated marks a GetFederationToken session. Session policies
	// always narrow it, so one without any has no permissions; it cannot
	// call IAM or any STS action except sts:GetCallerIdentity; a root
	// caller's federated session is bounded by its session policies too.
	Federated bool
	// SessionToken marks a GetSessionToken session and SessionMFA says
	// whether MFA was verified when it was issued. Such a session cannot
	// call IAM without that MFA, nor any STS action except
	// sts:AssumeRole and sts:GetCallerIdentity, as in AWS (#233).
	SessionToken bool
	SessionMFA   bool
}

// sessionDenied returns why p's session is refused action whatever its
// policies say, as in AWS, or "" when its policies decide.
// iam:PassRole is a permission, not an IAM API operation, so a
// GetSessionToken session keeps it.
func sessionDenied(p Principal, action string) string {
	a := strings.ToLower(action)
	iamAPI := strings.HasPrefix(a, "iam:")
	stsAPI := strings.HasPrefix(a, "sts:")
	switch {
	case p.Federated && (iamAPI || stsAPI && a != "sts:getcalleridentity"):
		return "a federated user session cannot call " + action
	case p.SessionToken && iamAPI && !p.SessionMFA && a != "iam:passrole":
		return "a GetSessionToken session issued without MFA cannot call " + action
	case p.SessionToken && stsAPI && a != "sts:assumerole" && a != "sts:getcalleridentity":
		return "a GetSessionToken session cannot call " + action
	}
	return ""
}

// allowAll is the identity side of a root user's federated session,
// which its session policies alone narrow.
var allowAll = func() []policy.Named {
	d, err := policy.ParseIdentity(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	if err != nil {
		panic(err) // a constant document
	}
	return []policy.Named{{Name: "root user", Doc: d}}
}()

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
		return policy.Named{}, fmt.Errorf("get policy %q: %w", arn, err)
	}
	if iam.PolicyARN(a.account, p.Object) != arn {
		return policy.Named{}, fmt.Errorf("policy %q: %w", arn, ErrNoSuchEntity)
	}
	d, err := policy.ParseIdentity(p.Object.Default())
	if err != nil {
		return policy.Named{}, fmt.Errorf("stored policy %q: %w", arn, err)
	}
	return policy.Named{Name: arn, Doc: d, ID: p.Object.Name, Type: "user-managed"}, nil
}

// source is the user, group or role a policy is attached to: its
// simulator policy type ("user", "group" or "role"), name and ARN.
type source struct{ kind, name, arn, id string }

func (s source) holder() policy.Holder {
	return policy.Holder{ID: s.id, Group: s.kind == "group"}
}

func (a *Authorizer) collect(
	ctx context.Context, src source, attached []string, inline map[string]string, out []policy.Named,
) ([]policy.Named, error) {
	for _, arn := range attached {
		n, err := a.managed(ctx, arn)
		if err != nil {
			return nil, err
		}
		n.Holder = src.holder()
		out = append(out, n)
	}
	for _, name := range slices.Sorted(maps.Keys(inline)) {
		// Inline documents are held to the aggregate size quota on write,
		// not to policy.MaxSize, so parse them the way the write path did.
		d, err := policy.ParseInline(inline[name])
		if err != nil {
			return nil, fmt.Errorf("inline policy %s/%s: %w", src.arn, name, err)
		}
		out = append(out, policy.Named{
			Name: src.arn + ":inline/" + name, Doc: d,
			ID: src.kind + "_" + src.name + "_" + name, Type: src.kind, Holder: src.holder(),
		})
	}
	return out, nil
}

// IdentityPolicies returns every identity policy that applies to p.
func (a *Authorizer) IdentityPolicies(ctx context.Context, p Principal) ([]policy.Named, string, error) {
	var out []policy.Named
	switch p.Kind {
	case User:
		u, err := store.Get[iam.User](ctx, a.b, p.Name)
		if errors.Is(err, store.ErrNotFound) || (err == nil && p.ID != "" && u.Object.ID != p.ID) {
			return nil, "", fmt.Errorf("user %q: %w", p.Name, ErrNoSuchEntity)
		}
		if err != nil {
			return nil, "", fmt.Errorf("get user %q: %w", p.Name, err)
		}
		arn := iam.UserARN(a.account, u.Object)
		src := source{"user", u.Object.Name, arn, u.Object.ID}
		if out, err = a.collect(ctx, src, u.Object.AttachedPolicies, u.Object.InlinePolicies, out); err != nil {
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
		if partner != "" {
			// The rename may have committed since the partner check,
			// and a new user under the partner name joined a group
			// before the group read. A partner that still matches after
			// the read matched during it: the old object never returns.
			again, err := RenamePartner(ctx, a.b, u.Object)
			if err != nil {
				return nil, "", err
			}
			if store.Fold(again) != store.Fold(partner) {
				groups = memberOf(groups, u.Object.Name)
			}
		}
		for _, g := range groups {
			src := source{"group", g.Name, iam.GroupARN(a.account, g), g.ID}
			if out, err = a.collect(ctx, src, g.AttachedPolicies, g.InlinePolicies, out); err != nil {
				return nil, "", err
			}
		}
		return out, arn, nil
	case Role:
		r, err := store.Get[iam.Role](ctx, a.b, p.Name)
		if errors.Is(err, store.ErrNotFound) || (err == nil && p.ID != "" && r.Object.ID != p.ID) {
			return nil, "", fmt.Errorf("role %q: %w", p.Name, ErrNoSuchEntity)
		}
		if err != nil {
			return nil, "", fmt.Errorf("get role %q: %w", p.Name, err)
		}
		arn := iam.RoleARN(a.account, r.Object)
		src := source{"role", r.Object.Name, arn, r.Object.ID}
		out, err = a.collect(ctx, src, r.Object.AttachedPolicies, r.Object.InlinePolicies, out)
		return out, arn, err
	}
	return nil, "", fmt.Errorf("principal kind %d: %w", p.Kind, ErrNoSuchEntity)
}

// GroupPolicies returns the identity policies of group name and its ARN,
// for the policy simulator: a group is not a principal, so Authorize
// never evaluates one.
func (a *Authorizer) GroupPolicies(ctx context.Context, name string) ([]policy.Named, string, error) {
	g, err := store.Get[iam.Group](ctx, a.b, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", fmt.Errorf("group %q: %w", name, ErrNoSuchEntity)
	}
	if err != nil {
		return nil, "", fmt.Errorf("get group %q: %w", name, err)
	}
	arn := iam.GroupARN(a.account, g.Object)
	src := source{"group", g.Object.Name, arn, g.Object.ID}
	out, err := a.collect(ctx, src, g.Object.AttachedPolicies, g.Object.InlinePolicies, nil)
	return out, arn, err
}

// ManagedPolicy returns managed policy arn of this project, parsed; an
// unknown one is ErrNoSuchEntity.
func (a *Authorizer) ManagedPolicy(ctx context.Context, arn string) (policy.Named, error) {
	return a.managed(ctx, arn)
}

// Authorize decides whether p may perform action on resource. reqCtx
// carries request keys such as aws:SourceIp and aws:MultiFactorAuthPresent;
// aws:username, aws:PrincipalArn, aws:CurrentTime (RFC 3339, UTC) and
// aws:EpochTime (Unix seconds) are set here, replacing any key of reqCtx
// that differs from one of them only in case. The decision carries the
// context it evaluated.
func (a *Authorizer) Authorize(
	ctx context.Context, p Principal, action, resource string, reqCtx map[string][]string,
) (d policy.Decision, err error) {
	ctx, end := observe(ctx)
	defer func() { end(d, err) }()
	return a.authorize(ctx, p, action, resource, reqCtx)
}

func (a *Authorizer) authorize(
	ctx context.Context, p Principal, action, resource string, reqCtx map[string][]string,
) (policy.Decision, error) {
	if why := sessionDenied(p, action); why != "" {
		return policy.Decision{Reason: why, Context: a.context(p, p.ARN, reqCtx)}, nil
	}
	if p.Kind == Root && !p.Federated {
		return policy.Decision{Allowed: true, Reason: "root user", Context: a.context(p, p.ARN, reqCtx)}, nil
	}
	var ids []policy.Named
	var arn string
	if p.Kind == Root {
		ids = allowAll
	} else {
		var err error
		if ids, arn, err = a.IdentityPolicies(ctx, p); err != nil {
			return policy.Decision{}, err
		}
	}
	if p.ARN != "" {
		arn = p.ARN
	}
	session, err := a.sessionPolicies(ctx, p)
	if err != nil {
		return policy.Decision{}, err
	}
	c := a.context(p, arn, reqCtx)
	r := policy.Request{Principal: arn, Account: a.account, Action: action, Resource: resource, Context: c}
	if p.Kind == User {
		boundary, err := a.userBoundary(ctx, p)
		if err != nil {
			return policy.Decision{}, err
		}
		return policy.EvaluateBounded(r, ids, session, boundary), nil
	}
	return policy.Evaluate(r, ids, session), nil
}

// authzKeys are the context keys Authorize sets itself.
var authzKeys = []string{"aws:PrincipalArn", "aws:CurrentTime", "aws:EpochTime", "aws:username"}

// context is reqCtx with the keys Authorize sets for p, whose ARN is
// arn ("" when not resolved, as for a session refused before its
// policies are read). Request keys keep their spelling, so a decoded authorization
// message shows them as sent.
func (a *Authorizer) context(p Principal, arn string, reqCtx map[string][]string) map[string][]string {
	c := make(map[string][]string, len(reqCtx)+len(authzKeys))
	for k, v := range reqCtx {
		if !slices.ContainsFunc(authzKeys, func(s string) bool { return strings.EqualFold(s, k) }) {
			c[k] = v
		}
	}
	if arn != "" {
		c["aws:PrincipalArn"] = []string{arn}
	}
	now := a.now().UTC()
	c["aws:CurrentTime"] = []string{now.Format(time.RFC3339)}
	c["aws:EpochTime"] = []string{strconv.FormatInt(now.Unix(), 10)}
	if p.Kind == User && !p.Federated {
		c["aws:username"] = []string{p.Name}
	}
	return c
}

// sessionPolicies returns p's session policies: nil when p has none, so
// they do not narrow it, and non-nil (perhaps empty, which allows
// nothing) for a federated session.
func (a *Authorizer) sessionPolicies(ctx context.Context, p Principal) ([]policy.Named, error) {
	if p.SessionPolicies == nil && p.SessionPolicyARNs == nil && !p.Federated {
		return nil, nil
	}
	out := []policy.Named{}
	for i, doc := range p.SessionPolicies {
		d, err := policy.ParseIdentity(doc)
		if err != nil {
			return nil, fmt.Errorf("session policy %d: %w", i, err)
		}
		out = append(out, policy.Named{Name: fmt.Sprintf("session-%d", i), Doc: d})
	}
	for _, arn := range p.SessionPolicyARNs {
		n, err := a.managed(ctx, arn)
		if err != nil {
			return nil, fmt.Errorf("managed session policy: %w", err)
		}
		out = append(out, n)
	}
	return out, nil
}

// ManagedPolicyExists reports whether arn is a managed policy of this
// project that can be used as a managed session policy.
func (a *Authorizer) ManagedPolicyExists(ctx context.Context, arn string) (bool, error) {
	_, err := a.managed(ctx, arn)
	if errors.Is(err, ErrNoSuchEntity) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
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
		return "", fmt.Errorf("get rename partner %q of user %q: %w", other, u.Name, err)
	}
	if !u.IsRenamePartner(v.Object) {
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
		return nil, fmt.Errorf("list groups: %w", err)
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

// memberOf returns the groups of gs whose members include name.
func memberOf(gs []iam.Group, name string) []iam.Group {
	var out []iam.Group
	for _, g := range gs {
		for _, m := range g.Members {
			if store.Fold(m) == store.Fold(name) {
				out = append(out, g)
				break
			}
		}
	}
	return out
}
