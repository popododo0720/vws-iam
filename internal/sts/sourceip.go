package sts

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/popododo0720/vws-iam/internal/policy"
)

// setFederatedSourceIP binds a transport address to a federated trust evaluation.
// It is independent of assertion/token parsing so federated entry points share
// one validation and missing-address rule.
func setFederatedSourceIP(trust *policy.Document, ctx map[string][]string, sourceIP string) error {
	if sourceIP != "" {
		addr, err := netip.ParseAddr(sourceIP)
		if err != nil || addr.Zone() != "" {
			return fmt.Errorf("%w: invalid source IP", ErrAccessDenied)
		}
		ctx["aws:SourceIp"] = []string{addr.Unmap().String()}
		return nil
	}
	for _, statement := range trust.Statements {
		for _, condition := range statement.Conditions {
			if strings.EqualFold(condition.Key, "aws:SourceIp") {
				return fmt.Errorf("%w: source IP required by trust policy", ErrAccessDenied)
			}
		}
	}
	return nil
}
