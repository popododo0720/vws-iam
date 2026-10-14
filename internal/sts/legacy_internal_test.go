package sts

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/sigv4"
)

// TestLegacyTokenRevocationWidensBySkew: a token sealed before #46 carries
// no generation, so it falls back to clocks widened by sigv4.MaxSkew.
func TestLegacyTokenRevocationWidensBySkew(t *testing.T) {
	rev := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		issued time.Time
		want   bool
	}{
		{rev.Add(-time.Hour), true},
		{rev, true},
		{rev.Add(sigv4.MaxSkew - time.Second), true}, // revoker up to MaxSkew behind
		{rev.Add(sigv4.MaxSkew), true},
		{rev.Add(sigv4.MaxSkew + time.Second), false},
	} {
		if got := sessionRevoked(session{IssuedAt: c.issued}, rev, 7); got != c.want {
			t.Errorf("issued %v: revoked = %v, want %v", c.issued.Sub(rev), got, c.want)
		}
	}
	if sessionRevoked(session{IssuedAt: rev}, time.Time{}, 0) {
		t.Error("never revoked, yet revoked")
	}
	g := uint64(3)
	for gen, want := range map[uint64]bool{2: false, 3: false, 4: true} {
		// IssuedAt is ignored once a token has a generation.
		if got := sessionRevoked(session{IssuedAt: rev.Add(-time.Hour), RevokeGen: &g}, rev, gen); got != want {
			t.Errorf("token gen 3, stored %d: revoked = %v, want %v", gen, got, want)
		}
	}
}
