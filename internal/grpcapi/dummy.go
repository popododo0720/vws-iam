package grpcapi

import (
	"runtime"
	"sync"

	"github.com/popododo0720/vws-iam/internal/password"
)

// dummyHash is an argon2id hash of a random value, verified when a login
// names an unknown user so both paths cost the same.
var dummyHash = sync.OnceValue(func() string {
	h, err := password.Hash("vws-iam-unknown-user-placeholder")
	if err != nil {
		return ""
	}
	return h
})

// burn verifies pw against dummyHash and discards the result.
func burn(pw string) {
	err := password.Verify(pw, dummyHash())
	runtime.KeepAlive(err)
}
