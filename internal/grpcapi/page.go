package grpcapi

import (
	"encoding/base64"
	"slices"
	"strings"

	"github.com/popododo0720/vws-iam/internal/store"
)

// pageByFoldedName orders xs by the case-folded name of each, whatever
// order the backend listed them in, and returns the first n of them.
// When more remain, truncated is set and marker continues after the last
// one returned: the base64url of its folded name, which decodeNameMarker
// reads back.
func pageByFoldedName[T any](xs []T, name func(T) string, n int) (page []T, truncated bool, marker string) {
	slices.SortFunc(xs, func(a, b T) int {
		return strings.Compare(store.Fold(name(a)), store.Fold(name(b)))
	})
	if len(xs) <= n {
		return xs, false, ""
	}
	xs = xs[:n]
	return xs, true, base64.RawURLEncoding.EncodeToString([]byte(store.Fold(name(xs[n-1]))))
}

// decodeNameMarker returns the case-folded name a listing marker from
// pageByFoldedName continues after; "" for no marker. valid reports
// whether a name is one the listing holds.
// A marker outside the AWS pattern [\u0020-\u00FF]+ is ValidationError;
// one this service did not issue (not base64url of a valid, folded name)
// is InvalidInput.
func decodeNameMarker(marker string, valid func(string) bool) (string, error) {
	if marker == "" {
		return "", nil
	}
	for _, c := range marker {
		if c < 0x20 || c > 0xFF {
			return "", invalidSpec("marker must be characters of [\\u0020-\\u00FF]")
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(marker)
	if err != nil || !valid(string(raw)) || store.Fold(string(raw)) != string(raw) {
		return "", invalidInput("marker is not valid")
	}
	return string(raw), nil
}
