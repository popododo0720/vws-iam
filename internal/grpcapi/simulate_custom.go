package grpcapi

import (
	"context"
	"log/slog"
	"strings"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
)

// customSimulateInput is the request of IAM SimulateCustomPolicy.
// OrderedOrganizationPolicyInputList is not taken: VWS has no
// organizations (#257).
type customSimulateInput struct {
	PolicyInputList        []string
	PermissionsBoundaryInp []string // PermissionsBoundaryPolicyInputList
	ActionNames            []string
	// ResourceARNs defaults to "*".
	ResourceARNs []string
	// ResourcePolicy and ResourceHandlingOption are validated, then
	// refused with InvalidInput until resource-based policy simulation
	// exists (#257).
	ResourcePolicy         string
	ResourceOwner          string
	CallerARN              string
	ContextEntries         []contextEntry
	ResourceHandlingOption string
	Marker                 string
	MaxItems               int
}

// checkResourceOwner validates ResourceOwner: 1 to 2048 characters that
// name an account root, arn:vws:iam::<project>:root.
func checkResourceOwner(owner string) error {
	if len(owner) > 2048 {
		return invalidSpec("ResourceOwner must be 1 to 2048 characters")
	}
	rest, prefixed := strings.CutPrefix(owner, "arn:"+iam.Partition+":iam::")
	account, rooted := strings.CutSuffix(rest, ":root")
	if !prefixed || !rooted || !iam.ValidProject(account) {
		return invalidInput("ResourceOwner " + quote(owner) + " must be an account ARN, arn:" +
			iam.Partition + ":iam::<account>:root")
	}
	return nil
}

// simulateCustomPolicy is IAM SimulateCustomPolicy: it evaluates the
// policies of PolicyInputList, and the permissions boundary of
// PermissionsBoundaryPolicyInputList when given, for every action of
// ActionNames on every resource of ResourceArns ("*" when not set), with
// the engine of simulatePrincipalPolicy: one result per action, in pages
// of actions, aggregated over the resources, with the result of each
// listed resource. CallerArn, when given, is the request principal.
// Context keys come only from ContextEntries. It reads no stored object.
//
// Any malformed input is ValidationError (a missing PolicyInputList or
// ActionNames, length, pattern, enum) or InvalidInput (a malformed policy,
// an action without a service, a CallerArn that is not a user, group or
// role ARN, a ResourceOwner that is not an account ARN, a ResourcePolicy
// without CallerArn, a context value not of its type, a second boundary,
// a marker not issued here). ResourcePolicy and ResourceHandlingOption
// are InvalidInput until resource-based policy simulation exists
// (#257), never ignored. Authorization (iam:SimulateCustomPolicy) is
// console-api's.
//
// TODO(#87): serve this as an RPC once vws-proto carries it
// (popododo0720/vws-proto#132).
func (s *Server) simulateCustomPolicy(ctx context.Context, pid string, in customSimulateInput) (simulationPage, error) {
	if !iam.ValidProject(pid) {
		return simulationPage{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if len(in.PolicyInputList) == 0 {
		return simulationPage{}, invalidSpec("PolicyInputList is required")
	}
	sim := simulateInput{
		ActionNames: in.ActionNames, ResourceARNs: in.ResourceARNs, CallerARN: in.CallerARN,
		ContextEntries: in.ContextEntries, Marker: in.Marker, MaxItems: in.MaxItems,
		PermissionsBoundaryInp: in.PermissionsBoundaryInp,
	}
	explicit := len(in.ResourceARNs) > 0
	reqCtx, off, size, err := checkSimulation(&sim)
	if err != nil {
		return simulationPage{}, err
	}
	if err := checkResourceInputs(in); err != nil {
		return simulationPage{}, err
	}
	identity, err := parseInputs("PolicyInputList", in.PolicyInputList)
	if err != nil {
		return simulationPage{}, err
	}
	boundary, err := parseInputs("PermissionsBoundaryPolicyInputList", in.PermissionsBoundaryInp)
	if err != nil {
		return simulationPage{}, err
	}
	if len(boundary) == 0 {
		boundary = nil
	}
	base := policy.Request{Principal: in.CallerARN, Account: pid, Context: reqCtx}
	out := simulateActions(base, sim.ActionNames, sim.ResourceARNs, explicit, off, size, identity, boundary)
	slog.Default().LogAttrs(ctx, slog.LevelInfo, "simulated custom policy",
		slog.String("project", pid), slog.Int("policies", len(identity)),
		slog.Int("results", len(out.Results)), slog.Bool("truncated", out.IsTruncated))
	return out, nil
}

// checkResourceInputs validates ResourcePolicy, ResourceOwner and
// ResourceHandlingOption and refuses the inputs that are not simulated
// yet (#257).
func checkResourceInputs(in customSimulateInput) error {
	if in.ResourcePolicy != "" && !policyText(in.ResourcePolicy) {
		return invalidSpec("ResourcePolicy must be 1 to 131072 characters of [\\u0009\\u000A\\u000D\\u0020-\\u00FF]")
	}
	if len(in.ResourceHandlingOption) > 64 {
		return invalidSpec("ResourceHandlingOption must be 1 to 64 characters")
	}
	if in.ResourceOwner != "" {
		if err := checkResourceOwner(in.ResourceOwner); err != nil {
			return err
		}
	}
	switch {
	case in.ResourcePolicy != "" && in.CallerARN == "":
		return invalidInput("CallerArn is required when ResourcePolicy is given")
	case in.ResourcePolicy != "":
		return invalidInput("ResourcePolicy simulation is not supported")
	case in.ResourceHandlingOption != "":
		return invalidInput("ResourceHandlingOption is not supported")
	}
	return nil
}
