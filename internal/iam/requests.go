package iam

import "regexp"

// MaxRequests bounds Meta.Requests.
const MaxRequests = 32

var requestTokenRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (m Meta) validRequests(what, name string) error {
	if len(m.Requests) > MaxRequests {
		return invalid("%s %q has %d request tokens, at most %d", what, name, len(m.Requests), MaxRequests)
	}
	for _, t := range m.Requests {
		if !requestTokenRE.MatchString(t) {
			return invalid("%s %q request token %q", what, name, t)
		}
	}
	return nil
}
