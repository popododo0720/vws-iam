package totp_test

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/totp"
)

// RFC 6238 Appendix B, SHA-1 column, 8 digits.
func TestRFC6238Vectors(t *testing.T) {
	seed := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		code string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	} {
		if got := totp.Code(seed, totp.Step(time.Unix(v.unix, 0)), 8); got != v.code {
			t.Errorf("T=%d: %s, want %s", v.unix, got, v.code)
		}
	}
}

// RFC 4226 Appendix D, 6 digits.
func TestRFC4226Vectors(t *testing.T) {
	seed := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := totp.Code(seed, int64(i), 6); got != w {
			t.Errorf("count %d: %s, want %s", i, got, w)
		}
	}
}

func TestMatchWindow(t *testing.T) {
	seed := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	s := totp.Step(now)
	for _, d := range []int64{-1, 0, 1} {
		if got, ok := totp.Match(seed, totp.Code(seed, s+d, 6), now, 1); !ok || got != s+d {
			t.Errorf("offset %d: %d %v", d, got, ok)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := totp.Match(seed, totp.Code(seed, s+d, 6), now, 1); ok {
			t.Errorf("offset %d accepted", d)
		}
	}
	for _, c := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := totp.Match(seed, c, now, 1); ok {
			t.Errorf("%q accepted", c)
		}
	}
}

// TestMatchPair: only two consecutive codes inside [lo, hi] match, at the
// step of the first; reversed, split, malformed and out-of-window pairs
// do not.
func TestMatchPair(t *testing.T) {
	seed := []byte("12345678901234567890")
	const at = 1_800_000_000 / 30
	c := func(s int64) string { return totp.Code(seed, s, totp.Digits) }
	for _, tc := range []struct {
		name         string
		code1, code2 string
		lo, hi       int64
		want         int64
		ok           bool
	}{
		{"consecutive", c(at + 5), c(at + 6), at - 20, at + 19, at + 5, true},
		{"at lo", c(at - 20), c(at - 19), at - 20, at + 19, at - 20, true},
		{"at hi", c(at + 19), c(at + 20), at - 20, at + 19, at + 19, true},
		{"below lo", c(at - 21), c(at - 20), at - 20, at + 19, 0, false},
		{"above hi", c(at + 20), c(at + 21), at - 20, at + 19, 0, false},
		{"reversed", c(at + 6), c(at + 5), at - 20, at + 19, 0, false},
		{"gap", c(at + 5), c(at + 7), at - 20, at + 19, 0, false},
		{"same code", c(at), c(at), at - 20, at + 19, 0, false},
		{"short", c(at)[:5], c(at + 1), at - 20, at + 19, 0, false},
		{"empty window", c(at), c(at + 1), at + 1, at, 0, false},
	} {
		got, ok := totp.MatchPair(seed, tc.code1, tc.code2, tc.lo, tc.hi)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: MatchPair = %d, %v; want %d, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}
