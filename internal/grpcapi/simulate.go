package grpcapi

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

// simulateInput is the request of IAM SimulatePrincipalPolicy. The
// resource-policy inputs (ResourcePolicy, ResourceOwner,
// ResourceHandlingOption) and PolicyExclusionList are not taken yet
// (#253).
type simulateInput struct {
	PolicySourceARN string
	ActionNames     []string
	// ResourceARNs defaults to "*".
	ResourceARNs           []string
	PolicyInputList        []string
	PermissionsBoundaryInp []string // PermissionsBoundaryPolicyInputList
	CallerARN              string
	ContextEntries         []contextEntry
	Marker                 string
	MaxItems               int
}

// contextEntry is an AWS ContextEntry.
type contextEntry struct {
	Key    string
	Type   string
	Values []string
}

// matchedStatement is an AWS Statement of a simulation result.
type matchedStatement struct {
	StartPosition    policy.Position
	EndPosition      policy.Position
	SourcePolicyID   string
	SourcePolicyType string
}

// resourceResult is the result for one action and resource (AWS
// ResourceSpecificResult), or the aggregate of an action over every
// resource (the top level of an AWS EvaluationResult).
type resourceResult struct {
	ResourceName         string
	Decision             string
	MatchedStatements    []matchedStatement
	MissingContextValues []string
	// AllowedByPermissionsBoundary is nil when no boundary applies.
	AllowedByPermissionsBoundary *bool
}

// evaluationResult is an AWS EvaluationResult: one per action, whatever
// the number of resources. Its top level aggregates every resource (see
// aggregate) and ResourceSpecific holds the result of each resource of
// ResourceArns, in order, when ResourceArns was given.
type evaluationResult struct {
	ActionName string
	resourceResult
	ResourceSpecific []resourceResult
}

// simulationPage is one page of SimulatePrincipalPolicy results.
type simulationPage struct {
	Results     []evaluationResult
	IsTruncated bool
	Marker      string
}

var contextKeyTypes = map[string]bool{
	"string": true, "stringList": true, "numeric": true, "numericList": true, "boolean": true, "booleanList": true,
	"ip": true, "ipList": true, "binary": true, "binaryList": true, "date": true, "dateList": true,
}

// policyText reports whether s is 1 to 131072 characters of the AWS
// policy pattern [\u0009\u000A\u000D\u0020-\u00FF]+.
func policyText(s string) bool {
	if s == "" || utf8.RuneCountInString(s) > policy.MaxInlineLength {
		return false
	}
	for _, c := range s {
		if c != '\t' && c != '\n' && c != '\r' && (c < 0x20 || c > 0xFF) {
			return false
		}
	}
	return true
}

// splitIdentityARN splits a user, group or role ARN into its type, account,
// path and name; ok is false for any other ARN.
func splitIdentityARN(arn string) (kind, account, path, name string, ok bool) {
	rest, ok := strings.CutPrefix(arn, "arn:"+iam.Partition+":iam::")
	if !ok {
		return "", "", "", "", false
	}
	account, rest, _ = strings.Cut(rest, ":")
	kind, rest, _ = strings.Cut(rest, "/")
	i := strings.LastIndexByte(rest, '/')
	path, name = "/"+rest[:i+1], rest[i+1:]
	valid := iam.ValidName
	if kind == "group" {
		valid = iam.ValidGroupName
	}
	ok = (kind == "user" || kind == "group" || kind == "role") &&
		iam.ValidProject(account) && valid(name) && iam.ValidPath(path)
	return kind, account, path, name, ok
}

// checkContextEntry validates one entry; a value that is not of its type is
// InvalidInput.
func checkContextEntry(e contextEntry) error {
	if n := len(e.Key); n < 5 || n > 256 {
		return invalidSpec("ContextKeyName must be 5 to 256 characters")
	}
	if !contextKeyTypes[e.Type] {
		return invalidSpec("ContextKeyType " + quote(e.Type) + " is not a context key type")
	}
	base, list := strings.CutSuffix(e.Type, "List")
	if !list && len(e.Values) != 1 {
		return invalidInput("context key " + quote(e.Key) + " of type " + e.Type + " takes exactly one value")
	}
	for _, v := range e.Values {
		var err error
		switch base {
		case "numeric":
			_, err = strconv.ParseFloat(v, 64)
		case "boolean":
			if !strings.EqualFold(v, "true") && !strings.EqualFold(v, "false") {
				err = errors.New("not a boolean")
			}
		case "ip":
			if _, perr := netip.ParsePrefix(v); perr != nil {
				_, err = netip.ParseAddr(v)
			}
		case "binary":
			_, err = base64.StdEncoding.DecodeString(v)
		case "date":
			if _, perr := strconv.ParseInt(v, 10, 64); perr != nil {
				_, err = time.Parse(time.RFC3339, v)
			}
		}
		if err != nil {
			return invalidInput("context key " + quote(e.Key) + " value " + quote(v) + " is not of type " + e.Type)
		}
	}
	return nil
}

// parseInputs parses policy documents given as strings, named
// "<param>.<n>" as in AWS. A malformed one is InvalidInput.
func parseInputs(param string, docs []string) ([]policy.Named, error) {
	out := make([]policy.Named, 0, len(docs))
	for i, doc := range docs {
		id := param + "." + strconv.Itoa(i+1)
		if !policyText(doc) {
			return nil, invalidSpec(id + " must be 1 to 131072 characters of [\\u0009\\u000A\\u000D\\u0020-\\u00FF]")
		}
		d, err := policy.ParseInline(doc)
		if err != nil {
			return nil, invalidInput(id + " is not a valid policy: " + err.Error())
		}
		out = append(out, policy.Named{Name: id, Doc: d, ID: id, Type: "none"})
	}
	return out, nil
}

// simulateRequest validates in and returns the request context and the
// page offset, all before any store access.
func simulateRequest(pid string, in *simulateInput) (map[string][]string, int, int, error) {
	if !iam.ValidProject(pid) {
		return nil, 0, 0, invalidID("project " + quote(pid) + " is not a project id")
	}
	if n := len(in.PolicySourceARN); n < 20 || n > 2048 {
		return nil, 0, 0, invalidSpec("PolicySourceArn must be 20 to 2048 characters")
	}
	return checkSimulation(in)
}

// checkSimulation validates the inputs SimulatePrincipalPolicy and
// SimulateCustomPolicy share and returns the request context, the page
// offset and the page size. ResourceARNs defaults to "*".
func checkSimulation(in *simulateInput) (map[string][]string, int, int, error) {
	if len(in.ActionNames) == 0 {
		return nil, 0, 0, invalidSpec("ActionNames is required")
	}
	for _, a := range in.ActionNames {
		if n := len(a); n < 3 || n > 128 {
			return nil, 0, 0, invalidSpec("each ActionNames member must be 3 to 128 characters")
		}
		if svc, act, ok := strings.Cut(a, ":"); !ok || svc == "" || act == "" {
			return nil, 0, 0, invalidInput("action " + quote(a) + " must include the service identifier, such as iam:CreateUser")
		}
	}
	if len(in.ResourceARNs) == 0 {
		in.ResourceARNs = []string{"*"}
	}
	for _, r := range in.ResourceARNs {
		if n := len(r); n < 1 || n > 2048 {
			return nil, 0, 0, invalidSpec("each ResourceArns member must be 1 to 2048 characters")
		}
	}
	if len(in.PermissionsBoundaryInp) > 1 {
		return nil, 0, 0, invalidInput("PermissionsBoundaryPolicyInputList takes only one policy")
	}
	if in.CallerARN != "" {
		if !policyText(in.CallerARN) || len(in.CallerARN) > 2048 {
			return nil, 0, 0, invalidSpec("CallerArn must be 1 to 2048 characters")
		}
		if _, _, _, _, ok := splitIdentityARN(in.CallerARN); !ok {
			return nil, 0, 0, invalidInput("CallerArn " + quote(in.CallerARN) + " must be the ARN of an IAM user, group or role")
		}
	}
	ctxVals := make(map[string][]string, len(in.ContextEntries))
	for _, e := range in.ContextEntries {
		if err := checkContextEntry(e); err != nil {
			return nil, 0, 0, err
		}
		k := strings.ToLower(e.Key)
		if _, dup := ctxVals[k]; dup {
			return nil, 0, 0, invalidInput("context key " + quote(e.Key) + " is given more than once")
		}
		ctxVals[k] = e.Values
	}
	size, err := listPageSize(in.MaxItems)
	if err != nil {
		return nil, 0, 0, err
	}
	off, err := decodeOffset(in.Marker, len(in.ActionNames))
	return ctxVals, off, size, err
}

// decodeOffset reads a marker from simulatePrincipalPolicy: the base64url
// of the index of the next result. One it did not issue for total
// results is InvalidInput.
func decodeOffset(marker string, total int) (int, error) {
	if marker == "" {
		return 0, nil
	}
	for _, c := range marker {
		if c < 0x20 || c > 0xFF {
			return 0, invalidSpec("marker must be characters of [\\u0020-\\u00FF]")
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(marker)
	off, aerr := strconv.Atoi(string(raw))
	if err != nil || aerr != nil || strconv.Itoa(off) != string(raw) || off < 1 || off >= total {
		return 0, invalidInput("marker is not valid")
	}
	return off, nil
}

// simulatePrincipalPolicy is IAM SimulatePrincipalPolicy: it evaluates
// the policies of the user (with its groups'), group or role
// PolicySourceArn of project pid, plus PolicyInputList, for every action
// of ActionNames on every resource of ResourceArns ("*" when not set),
// and reports, one result per action and in pages of actions, the
// decision (allowed, explicitDeny, implicitDeny), the statements that
// decided it and the context keys it lacked, aggregated over the
// resources, with the result of each listed resource. The permissions boundary is
// PermissionsBoundaryPolicyInputList when given, else the stored boundary
// of the user or role. Context keys come only from ContextEntries.
//
// Any malformed input is ValidationError (length, pattern, enum) or
// InvalidInput (a malformed policy, an action without a service, a
// CallerArn that is not a user, group or role ARN, a context value not of
// its type, a second boundary, a marker not issued here), all before any
// store access. A PolicySourceArn that is not a user, group or role ARN
// is InvalidInput; one of another account or that does not exist is
// NoSuchEntity. A stored policy that cannot be evaluated is
// PolicyEvaluation; other store failures are internal errors. It only
// reads. Authorization (iam:SimulatePrincipalPolicy) is console-api's.
//
// TODO(#86): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#131).
func (s *Server) simulatePrincipalPolicy(ctx context.Context, pid string, in simulateInput) (simulationPage, error) {
	explicit := len(in.ResourceARNs) > 0
	reqCtx, off, size, err := simulateRequest(pid, &in)
	if err != nil {
		return simulationPage{}, err
	}
	extra, err := parseInputs("PolicyInputList", in.PolicyInputList)
	if err != nil {
		return simulationPage{}, err
	}
	boundary, err := parseInputs("PermissionsBoundaryPolicyInputList", in.PermissionsBoundaryInp)
	if err != nil {
		return simulationPage{}, err
	}
	kind, account, path, name, ok := splitIdentityARN(in.PolicySourceARN)
	if !ok {
		return simulationPage{}, invalidInput("PolicySourceArn " + quote(in.PolicySourceARN) +
			" must be the ARN of an IAM user, group or role")
	}
	if account != pid {
		return simulationPage{}, notFound("The entity " + quote(in.PolicySourceARN) + " cannot be found.")
	}
	p := s.project(pid)
	ids, stored, err := sourcePolicies(ctx, p, kind, path, name, in.PolicySourceARN)
	if err != nil {
		return simulationPage{}, err
	}
	if len(boundary) == 0 {
		boundary = nil
		if stored != "" {
			b, err := p.authz.ManagedPolicy(ctx, stored)
			if err != nil {
				return simulationPage{}, simulationError(ctx, err)
			}
			boundary = []policy.Named{b}
		}
	}
	ids = append(ids, extra...)
	caller := in.CallerARN
	if caller == "" {
		caller = in.PolicySourceARN
	}
	base := policy.Request{Principal: caller, Account: pid, Context: reqCtx}
	out := simulateActions(base, in.ActionNames, in.ResourceARNs, explicit, off, size, ids, boundary)
	slog.Default().LogAttrs(ctx, slog.LevelInfo, "simulated principal policy",
		slog.String("project", pid), slog.String("policy_source", in.PolicySourceARN),
		slog.Int("results", len(out.Results)), slog.Bool("truncated", out.IsTruncated))
	return out, nil
}

// simulateActions evaluates base with identity and boundary (nil for
// none) for the page of actions from off of at most size, each on every
// resource, and returns one result per action, with the result of each
// resource when explicit (ResourceArns was given).
func simulateActions(
	base policy.Request, actions, resources []string, explicit bool, off, size int, identity, boundary []policy.Named,
) simulationPage {
	total := len(actions)
	var out simulationPage
	for _, action := range actions[off:min(total, off+size)] {
		per := make([]resourceResult, 0, len(resources))
		for _, resource := range resources {
			r := base
			r.Action, r.Resource = action, resource
			per = append(per, toResult(resource, policy.Simulate(r, identity, boundary)))
		}
		e := evaluationResult{ActionName: action, resourceResult: aggregate(per)}
		if template := simulationResourceTemplates[strings.ToLower(action)]; template != "" {
			e.ResourceName = template
		}
		if explicit {
			e.ResourceSpecific = per
		}
		out.Results = append(out.Results, e)
	}
	if next := off + size; next < total {
		out.IsTruncated, out.Marker = true, base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(next)))
	}
	return out
}

// sourcePolicies returns the identity policies of the user, group or role
// at arn and the ARN of its stored permissions boundary ("" for none).
func sourcePolicies(ctx context.Context, p project, kind, path, name, arn string) ([]policy.Named, string, error) {
	var ids []policy.Named
	var got, boundary string
	var err error
	switch kind {
	case "group":
		if _, err = store.Get[iam.Group](ctx, p.b, name); err == nil {
			ids, got, err = p.authz.GroupPolicies(ctx, name)
		}
	case "user":
		var u store.Versioned[iam.User]
		if u, err = store.Get[iam.User](ctx, p.b, name); err == nil {
			boundary = u.Object.PermissionsBoundary
			ids, got, err = p.authz.IdentityPolicies(ctx, authz.Principal{Kind: authz.User, Name: name})
		}
	default:
		var r store.Versioned[iam.Role]
		if r, err = store.Get[iam.Role](ctx, p.b, name); err == nil {
			boundary = r.Object.PermissionsBoundary
			ids, got, err = p.authz.IdentityPolicies(ctx, authz.Principal{Kind: authz.Role, Name: name})
		}
	}
	if errors.Is(err, store.ErrNotFound) { // the entity itself; a missing policy is NoSuchEntity naming it
		return nil, "", notFound("The entity " + quote(arn) + " cannot be found.")
	}
	if err != nil {
		return nil, "", simulationError(ctx, err)
	}
	gk, ga, gp, gn, _ := splitIdentityARN(got)
	if gk != kind || ga != p.id || gp != path || store.Fold(gn) != store.Fold(name) {
		return nil, "", notFound("The entity " + quote(arn) + " cannot be found.")
	}
	return ids, boundary, nil
}

// simulationError maps a failure to read or parse stored policies: one
// that cannot be evaluated is AWS PolicyEvaluation.
func simulationError(ctx context.Context, err error) error {
	if errors.Is(err, policy.ErrMalformed) {
		return fail(codes.Internal, "", "PolicyEvaluation", "a stored policy could not be evaluated")
	}
	return toStatus(ctx, err)
}

// decisionRank orders decisions from least to most restrictive.
var decisionRank = map[string]int{
	policy.DecisionAllowed: 0, policy.DecisionImplicitDeny: 1, policy.DecisionExplicitDeny: 2,
}

// aggregate is the top level of the EvaluationResult of one action over
// the results of each resource, as in AWS: the most restrictive decision
// (explicitDeny, then implicitDeny, then allowed), the union of the
// statements of the resources with that decision (only those that
// contributed to it), the union of the missing context values of every
// resource, and the boundary allowing it only when it allows every
// resource. simulateActions replaces the default resource name with a
// catalog template when one is known.
func aggregate(per []resourceResult) resourceResult {
	top := resourceResult{ResourceName: "*", Decision: policy.DecisionAllowed}
	for _, r := range per {
		if decisionRank[r.Decision] > decisionRank[top.Decision] {
			top.Decision = r.Decision
		}
	}
	for _, r := range per {
		if r.Decision == top.Decision {
			for _, m := range r.MatchedStatements {
				if !slices.Contains(top.MatchedStatements, m) {
					top.MatchedStatements = append(top.MatchedStatements, m)
				}
			}
		}
		for _, k := range r.MissingContextValues {
			if !slices.Contains(top.MissingContextValues, k) {
				top.MissingContextValues = append(top.MissingContextValues, k)
			}
		}
		if b := r.AllowedByPermissionsBoundary; b != nil {
			allowed := *b && (top.AllowedByPermissionsBoundary == nil || *top.AllowedByPermissionsBoundary)
			top.AllowedByPermissionsBoundary = &allowed
		}
	}
	slices.Sort(top.MissingContextValues)
	return top
}

func toResult(resource string, sim policy.Simulation) resourceResult {
	r := resourceResult{ResourceName: resource, Decision: sim.Decision, MissingContextValues: sim.Missing}
	for _, m := range sim.Matched {
		statement := m.Policy.Doc.Statements[m.Index]
		ms := matchedStatement{
			SourcePolicyID: m.Policy.ID, SourcePolicyType: m.Policy.Type,
			StartPosition: statement.StartPosition, EndPosition: statement.EndPosition,
		}
		r.MatchedStatements = append(r.MatchedStatements, ms)
	}
	if sim.Boundary {
		r.AllowedByPermissionsBoundary = &sim.AllowedByBoundary
	}
	return r
}
