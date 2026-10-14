package grpcapi

// AttemptCounterHash is the store key of the attempt counter of scope
// (iam.AttemptUser, Key, IP) and id, for tests that seed a counter: a
// user's "project/name", an access key id, or a source IP as given.
func AttemptCounterHash(scope, id string) string {
	if j, ok := ipSubject(id); ok && scope == j.scope {
		return j.hash()
	}
	return subject{scope, id}.hash()
}
