package iam

import "regexp"

// MaxRequests bounds Meta.Requests.
const MaxRequests = 32

var requestTokenRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (m Meta) validRequests() error {
	if len(m.Requests) > MaxRequests {
		return invalid("%d request tokens, at most %d", len(m.Requests), MaxRequests)
	}
	for _, t := range m.Requests {
		if !requestTokenRE.MatchString(t) {
			return invalid("request token %q", t)
		}
	}
	return nil
}
