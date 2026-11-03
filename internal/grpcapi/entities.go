package grpcapi

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// The EntityFilter values of AWS ListEntitiesForPolicy (the EntityType
// enum). Entities are only users, groups and roles, so the two policy
// values select nothing.
const (
	EntityFilterUser               = "User"
	EntityFilterRole               = "Role"
	EntityFilterGroup              = "Group"
	EntityFilterLocalManagedPolicy = "LocalManagedPolicy"
	EntityFilterAWSManagedPolicy   = "AWSManagedPolicy"
)

// The PolicyUsageFilter values of AWS ListEntitiesForPolicy.
const (
	PolicyUsagePermissionsPolicy   = "PermissionsPolicy"
	PolicyUsagePermissionsBoundary = "PermissionsBoundary"
)

// entityPathPrefixRE is the AWS ListEntitiesForPolicy PathPrefix pattern
// (\u002F)|(\u002F[\u0021-\u007E]+\u002F): a slash alone, or a path that
// starts and ends with one. Unlike the other IAM list calls it must end
// with a slash.
var entityPathPrefixRE = regexp.MustCompile(`^(/|/[\x21-\x7e]+/)$`)

// entitiesQuery is the request of ListEntitiesForPolicy. An empty field
// is not set: every entity type, the path "/", any usage, the first
// page, and MaxItems 0 is the AWS default of 100.
type entitiesQuery struct {
	PolicyARN         string
	EntityFilter      string
	PathPrefix        string
	PolicyUsageFilter string
	Marker            string
	MaxItems          int
}

// policyEntity is an AWS PolicyUser, PolicyGroup or PolicyRole: the
// entity's name as stored and its unique id.
type policyEntity struct {
	Name string
	ID   string
}

// policyEntities is one page of ListEntitiesForPolicy. When IsTruncated
// is set, Marker continues the listing.
type policyEntities struct {
	PolicyGroups []policyEntity
	PolicyRoles  []policyEntity
	PolicyUsers  []policyEntity
	IsTruncated  bool
	Marker       string
}

// listedEntity is one entity of a ListEntitiesForPolicy listing; key
// orders the listing and is what a marker carries.
type listedEntity struct {
	key  string
	kind byte
	e    policyEntity
}

// The kind prefixes of a listing key. They sort groups, then roles, then
// users, the order of the AWS response elements.
const (
	entityKeyGroup = 'g'
	entityKeyRole  = 'r'
	entityKeyUser  = 'u'
)

// listEntitiesForPolicy is IAM ListEntitiesForPolicy: the users, groups
// and roles of project pid that the managed policy q.PolicyARN is
// attached to (PolicyUsageFilter PermissionsPolicy), is the permissions
// boundary of (PermissionsBoundary; users and roles only), or either
// (not set), in pages.
//
// A bad project id, a PolicyArn outside 20 to 2048 characters, an
// EntityFilter or PolicyUsageFilter outside its AWS values (case
// sensitive), a PathPrefix outside 1 to 512 characters of
// (\u002F)|(\u002F[\u0021-\u007E]+\u002F), a MaxItems outside 1 to 1000
// or a Marker character outside [\u0020-\u00FF] is ValidationError. A
// PolicyArn that is not a managed policy ARN and a marker this call did
// not return are InvalidInput. All before any store access. A policy
// that is not a managed policy of pid (path included) is NoSuchEntity:
// VWS has no AWS managed policies, so an arn:vws:iam::aws:policy/ ARN is
// one too (#260). Any other failure is ServiceFailure.
//
// The listing is ordered groups, roles, then users, each by case-folded
// name, so a marker (the last entity of the previous page) continues
// after that entity even when entities change in between: every entity
// that holds the policy for the whole listing is returned once. Users
// and groups in a rename are listed once (store.Visible). Paths match
// case-sensitively; an entity stored without a path has the path "/".
// The call only reads. Authorization (iam:ListEntitiesForPolicy) is
// console-api's, as for the other IAM reads.
//
// TODO(#85): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#133).
func (s *Server) listEntitiesForPolicy(ctx context.Context, pid string, q entitiesQuery) (policyEntities, error) {
	if !iam.ValidProject(pid) {
		return policyEntities{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if n := len(q.PolicyARN); n < minBoundaryARN || n > maxBoundaryARN {
		return policyEntities{}, invalidSpec("policyArn must be 20 to 2048 characters")
	}
	kinds, err := entityKinds(q.EntityFilter)
	if err != nil {
		return policyEntities{}, err
	}
	attached, bound, err := policyUsage(q.PolicyUsageFilter)
	if err != nil {
		return policyEntities{}, err
	}
	prefix := q.PathPrefix
	if prefix == "" {
		prefix = "/"
	}
	if len(prefix) > iam.MaxPathPrefixLen || !entityPathPrefixRE.MatchString(prefix) {
		return policyEntities{}, invalidSpec(
			"pathPrefix must be 1 to 512 characters of (\\u002F)|(\\u002F[\\u0021-\\u007E]+\\u002F)")
	}
	maxItems, err := listPageSize(q.MaxItems)
	if err != nil {
		return policyEntities{}, err
	}
	after, err := decodeNameMarker(q.Marker, validEntityKey)
	if err != nil {
		return policyEntities{}, err
	}
	if !iam.ValidPolicyARN(q.PolicyARN) {
		return policyEntities{}, invalidInput("ARN " + q.PolicyARN + " is not valid.")
	}
	p := s.project(pid)
	found, err := p.managedPolicy(ctx, q.PolicyARN)
	if err != nil {
		return policyEntities{}, readFailure(ctx, err)
	}
	if !found {
		return policyEntities{}, notFound("Policy " + q.PolicyARN + " was not found.")
	}
	holds := func(path string, policies []string, boundary string) bool {
		if path == "" {
			path = "/"
		}
		if !strings.HasPrefix(path, prefix) {
			return false
		}
		return (attached && slices.Contains(policies, q.PolicyARN)) || (bound && boundary == q.PolicyARN)
	}
	var match []listedEntity
	add := func(kind byte, name, id string) {
		k := string(kind) + ":" + store.Fold(name)
		if after == "" || k > after {
			match = append(match, listedEntity{key: k, kind: kind, e: policyEntity{Name: name, ID: id}})
		}
	}
	if kinds[entityKeyGroup] {
		gs, err := store.List[iam.Group](ctx, p.b)
		if err != nil {
			return policyEntities{}, readFailure(ctx, err)
		}
		for _, g := range store.Visible(gs) {
			if o := g.Object; holds(o.Path, o.AttachedPolicies, "") {
				add(entityKeyGroup, o.Name, o.ID)
			}
		}
	}
	if kinds[entityKeyRole] {
		rs, err := store.List[iam.Role](ctx, p.b)
		if err != nil {
			return policyEntities{}, readFailure(ctx, err)
		}
		for _, r := range rs {
			if o := r.Object; holds(o.Path, o.AttachedPolicies, o.PermissionsBoundary) {
				add(entityKeyRole, o.Name, o.ID)
			}
		}
	}
	if kinds[entityKeyUser] {
		us, err := store.List[iam.User](ctx, p.b)
		if err != nil {
			return policyEntities{}, readFailure(ctx, err)
		}
		for _, u := range store.Visible(us) {
			if o := u.Object; holds(o.Path, o.AttachedPolicies, o.PermissionsBoundary) {
				add(entityKeyUser, o.Name, o.ID)
			}
		}
	}
	return pageEntities(match, maxItems), nil
}

// entityKinds returns the entity kinds (by key prefix) that EntityFilter
// f selects; "" selects users, groups and roles. Any other value is
// ValidationError, as for an AWS enum.
func entityKinds(f string) (map[byte]bool, error) {
	switch f {
	case "":
		return map[byte]bool{entityKeyGroup: true, entityKeyRole: true, entityKeyUser: true}, nil
	case EntityFilterUser:
		return map[byte]bool{entityKeyUser: true}, nil
	case EntityFilterRole:
		return map[byte]bool{entityKeyRole: true}, nil
	case EntityFilterGroup:
		return map[byte]bool{entityKeyGroup: true}, nil
	case EntityFilterLocalManagedPolicy, EntityFilterAWSManagedPolicy:
		return map[byte]bool{}, nil
	}
	return nil, invalidSpec("entityFilter must be one of User, Role, Group, LocalManagedPolicy, AWSManagedPolicy")
}

// policyUsage reports which uses PolicyUsageFilter f selects: attached as
// a permissions policy, as a permissions boundary, or both for "". Any
// other value is ValidationError.
func policyUsage(f string) (attached, boundary bool, err error) {
	switch f {
	case "":
		return true, true, nil
	case PolicyUsagePermissionsPolicy:
		return true, false, nil
	case PolicyUsagePermissionsBoundary:
		return false, true, nil
	}
	return false, false, invalidSpec("policyUsageFilter must be one of PermissionsPolicy, PermissionsBoundary")
}

// validEntityKey reports whether k is a listing key this service issues:
// a kind prefix, a colon, and a valid name of that kind.
func validEntityKey(k string) bool {
	kind, name, ok := strings.Cut(k, ":")
	if !ok || len(kind) != 1 {
		return false
	}
	switch kind[0] {
	case entityKeyGroup:
		return iam.ValidGroupName(name)
	case entityKeyRole, entityKeyUser:
		return iam.ValidName(name)
	}
	return false
}

// pageEntities orders es by key and returns the first n, split by kind.
// When more remain, the page is truncated and its marker continues after
// the last one returned (see pageByFoldedName).
func pageEntities(es []listedEntity, n int) policyEntities {
	es, truncated, marker := pageByFoldedName(es, func(e listedEntity) string { return e.key }, n)
	out := policyEntities{IsTruncated: truncated, Marker: marker}
	for _, e := range es {
		switch e.kind {
		case entityKeyGroup:
			out.PolicyGroups = append(out.PolicyGroups, e.e)
		case entityKeyRole:
			out.PolicyRoles = append(out.PolicyRoles, e.e)
		default:
			out.PolicyUsers = append(out.PolicyUsers, e.e)
		}
	}
	return out
}

// readFailure maps a store error of a read to the wire as toStatus does,
// except that an unknown failure is AWS ServiceFailure, the fault the
// IAM list actions document, rather than InternalFailure. toStatus has
// logged its cause without request data.
func readFailure(ctx context.Context, err error) error {
	out := toStatus(ctx, err)
	if status.Code(out) == codes.Internal {
		return serviceFailure("The request processing has failed because of an unknown error, exception or failure.")
	}
	return out
}

// managedPolicy reports whether arn names a managed policy of project p,
// path included, as the authorizer resolves attached policies.
func (p project) managedPolicy(ctx context.Context, arn string) (bool, error) {
	id := arn[strings.LastIndexByte(arn, '/')+1:]
	if !strings.HasPrefix(arn, iam.ARN("iam", "", p.id, "policy/")) || !iam.ValidPolicyName(id) {
		return false, nil
	}
	pol, err := store.Get[iam.Policy](ctx, p.b, id)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return iam.PolicyARN(p.id, pol.Object) == arn, nil
}
