package policy

// ParseIdentity parses a policy attached to a user, group, or role, or a
// session policy: it names resources and no principal.
func ParseIdentity(doc string) (*Document, error) {
	d, err := Parse(doc)
	if err != nil {
		return nil, err
	}
	for i, s := range d.Statements {
		if s.Principals != nil {
			return nil, malformed("statement %d: identity policies take no Principal", i)
		}
		if s.Resources == nil {
			return nil, malformed("statement %d: no Resource", i)
		}
	}
	return d, nil
}

// ParseTrust parses a role trust policy: principals and no resources.
func ParseTrust(doc string) (*Document, error) {
	d, err := Parse(doc)
	if err != nil {
		return nil, err
	}
	for i, s := range d.Statements {
		if s.Principals == nil {
			return nil, malformed("statement %d: trust policies need a Principal", i)
		}
		if s.Resources != nil {
			return nil, malformed("statement %d: trust policies take no Resource", i)
		}
	}
	return d, nil
}
