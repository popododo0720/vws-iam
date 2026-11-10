package grpcapi

import (
	"strings"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
)

// policyIdentifier is the AWS PolicyIdentifier union. Exactly one member is set.
type policyIdentifier struct {
	PolicyType             string
	PolicyARN              string
	InlinePolicyIdentifier *inlinePolicyIdentifier
}

type inlinePolicyIdentifier struct {
	AttachmentName string
	AttachmentType string
	PolicyName     string
}

func wildcardName(name string, limit int) bool {
	if len(name) < 1 || len(name) > limit || strings.Count(name, "*") > 1 {
		return false
	}
	// Wildcards are allowed only in the entity name or policy ARN resource.
	return iam.ValidPolicyName(strings.NewReplacer("*", "x", "?", "x").Replace(name))
}

func validateExclusions(ids []policyIdentifier) error {
	if len(ids) > 256 {
		return invalidInput("PolicyExclusionList takes at most 256 identifiers")
	}
	for _, id := range ids {
		count := 0
		if id.PolicyType != "" {
			count++
		}
		if id.PolicyARN != "" {
			count++
		}
		if id.InlinePolicyIdentifier != nil {
			count++
		}
		if count != 1 {
			return invalidInput("a PolicyIdentifier must specify exactly one member")
		}
		switch {
		case id.PolicyType != "":
			switch id.PolicyType {
			case "inline", "aws-managed", "user-managed", "permission-boundary", "scp", "rcp":
			default:
				return invalidInput("invalid exclusion PolicyType")
			}
		case id.PolicyARN != "":
			parts := strings.SplitN(id.PolicyARN, ":", 6)
			if len(id.PolicyARN) < 20 || len(id.PolicyARN) > 2048 ||
				len(parts) != 6 || parts[0] != "arn" || parts[1] != iam.Partition ||
				parts[2] != "iam" || parts[3] != "" ||
				(parts[4] != "aws" && !iam.ValidProject(parts[4])) {
				return invalidInput("invalid exclusion policy ARN")
			}
			path, ok := strings.CutPrefix(parts[5], "policy/")
			if !ok || strings.Count(path, "*") > 1 {
				return invalidInput("invalid exclusion policy ARN resource")
			}
			i := strings.LastIndexByte(path, '/')
			prefix, name := "/"+path[:i+1], path[i+1:]
			if !iam.ValidPath(strings.NewReplacer("*", "x", "?", "x").Replace(prefix)) ||
				!wildcardName(name, iam.MaxPolicyNameLen) {
				return invalidInput("invalid exclusion policy ARN resource")
			}
		default:
			in := id.InlinePolicyIdentifier
			if in.AttachmentType != "user" && in.AttachmentType != "group" && in.AttachmentType != "role" {
				return invalidInput("invalid exclusion attachment type")
			}
			if !wildcardName(in.AttachmentName, 128) || !iam.ValidPolicyName(in.PolicyName) {
				return invalidInput("invalid inline policy identifier")
			}
		}
	}
	return nil
}

func excludedPolicy(ids []policyIdentifier, name, kind string) bool {
	for _, id := range ids {
		if id.PolicyType == kind || id.PolicyType == "inline" && (kind == "user" || kind == "group" || kind == "role") {
			return true
		}
		if id.PolicyARN != "" && (kind == "user-managed" || kind == "aws-managed" || kind == "permission-boundary") &&
			policy.Match(id.PolicyARN, name, false) {
			return true
		}
		if in := id.InlinePolicyIdentifier; in != nil && in.AttachmentType == kind {
			arn, policyName, ok := strings.Cut(name, ":inline/")
			_, _, _, entity, valid := splitIdentityARN(arn)
			if ok && valid && in.PolicyName == policyName && policy.Match(in.AttachmentName, entity, true) {
				return true
			}
		}
	}
	return false
}
