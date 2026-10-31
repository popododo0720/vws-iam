package sts

import (
	"testing"
	"time"
)

// TestSetTimeKeys: the server's time keys replace any copy of them in
// another letter case.
func TestSetTimeKeys(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.FixedZone("KST", 9*3600))
	m := map[string][]string{"AWS:CurrentTime": {"2000-01-01T00:00:00Z"}, "aws:epochtime": {"1"}, "SAML:sub": {"a"}}
	setTimeKeys(m, now)
	want := map[string]string{"aws:CurrentTime": "2026-10-31T03:00:00Z", "aws:EpochTime": "1793415600", "SAML:sub": "a"}
	if len(m) != len(want) {
		t.Fatalf("got %v", m)
	}
	for k, v := range want {
		if got := m[k]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want %s", k, got, v)
		}
	}
}
