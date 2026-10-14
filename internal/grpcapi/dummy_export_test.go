package grpcapi

import "testing"

// SetDummyHash replaces the hash burn verifies against for unknown users
// until t ends. Tests in this package do not run in parallel.
func SetDummyHash(t *testing.T, phc string) {
	old := dummyHash
	dummyHash = func() string { return phc }
	t.Cleanup(func() { dummyHash = old })
}
