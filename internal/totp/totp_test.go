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
