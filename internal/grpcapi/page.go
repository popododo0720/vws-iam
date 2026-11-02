package grpcapi

import (
	"encoding/base64"
	"slices"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-iam/internal/store"
)

// List page sizes: the AWS default and maximum MaxItems of the IAM list
// actions served here.
const (
	DefaultListPageSize = 100
	MaxListPageSize     = 1000
)

// listPageSize returns the page size of a listing for maxItems: 0 means
// not set, the AWS default of 100; a value outside 1 to 1000 is
// ValidationError.
func listPageSize(maxItems int) (int, error) {
	switch {
	case maxItems == 0:
		return DefaultListPageSize, nil
	case maxItems < 1 || maxItems > MaxListPageSize:
		return 0, invalidSpec("maxItems must be 1 to " + strconv.Itoa(MaxListPageSize))
	}
	return maxItems, nil
}

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
