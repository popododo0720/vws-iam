package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func TestTypedHelperErrorsNameOperationAndKind(t *testing.T) {
	b := memstore.New()
	obj := iam.User{Name: "alice", ID: "AIDAALICE"}
	version, err := store.Create(t.Context(), b, obj)
	if err != nil {
		t.Fatal(err)
	}
	pre := store.Pre{Kind: iam.KindUser, Key: obj.Name, Version: version}
	if _, err := b.Create(t.Context(), iam.KindUser, "corrupt", []byte("{")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		op    string
		cause error
		run   func() error
	}{
		{"create", store.ErrExists, func() error {
			_, err := store.Create(t.Context(), b, obj)
			return err
		}},
		{"update", store.ErrConflict, func() error {
			_, err := store.Update(t.Context(), b, obj, "stale")
			return err
		}},
		{"update if", store.ErrConflict, func() error {
			_, err := store.UpdateIf(t.Context(), b, obj, "stale", pre)
			return err
		}},
		{"create marked", store.ErrExists, func() error {
			_, err := store.CreateMarked(t.Context(), b, obj)
			return err
		}},
		{"update marked", store.ErrConflict, func() error {
			_, err := store.UpdateMarked(t.Context(), b, obj, "stale")
			return err
		}},
		{"update marked if", store.ErrConflict, func() error {
			_, err := store.UpdateMarkedIf(t.Context(), b, obj, "stale", pre)
			return err
		}},
		{"get", store.ErrNotFound, func() error {
			_, err := store.Get[iam.User](t.Context(), b, "missing")
			return err
		}},
		{"list", nil, func() error {
			_, err := store.List[iam.User](t.Context(), b)
			return err
		}},
		{"list page", nil, func() error {
			_, _, err := store.ListPage[iam.User](t.Context(), b, 0, "")
			return err
		}},
		{"delete", store.ErrNotFound, func() error { return store.Delete[iam.User](t.Context(), b, "missing", "") }},
		{"delete if", store.ErrNoVersion, func() error {
			return store.DeleteIf[iam.User](t.Context(), b, obj.Name, "", pre)
		}},
		{"mutate", store.ErrNotFound, func() error {
			_, err := store.Mutate(t.Context(), b, "missing", func(*iam.User) error { return nil })
			return err
		}},
		{"mutate while alive", store.ErrNotFound, func() error {
			_, err := store.MutateWhileAlive(t.Context(), b, "missing", func(*iam.User) error { return nil })
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.op, func(t *testing.T) {
			err := tc.run()
			checkStoreError(t, tc.op, err, tc.cause)
			if tc.cause == nil {
				var syntax *json.SyntaxError
				if !errors.As(err, &syntax) {
					t.Fatalf("decode cause lost: %v", err)
				}
			}
		})
	}
	_, err = store.Create(t.Context(), b, iam.User{Name: "bad name!"})
	checkStoreError(t, "create", err, iam.ErrInvalid)
}

type listFailure struct{ store.Backend }

func (b listFailure) List(context.Context, iam.Kind) ([]store.Entry, error) {
	return nil, store.ErrUnavailable
}

func TestAdapterErrorsNameOperationAndKind(t *testing.T) {
	for _, adapter := range []string{"scoped", "retry"} {
		t.Run(adapter, func(t *testing.T) {
			var b store.Backend = listFailure{memstore.New()}
			if adapter == "scoped" {
				b = store.Scoped(b, "acme")
			} else {
				b = store.WithRetry(b, 2, 0)
			}
			spec := []byte("{}")
			version, err := b.Create(t.Context(), iam.KindUser, "alice", spec)
			if err != nil {
				t.Fatal(err)
			}
			pre := store.Pre{Kind: iam.KindUser, Key: "alice", Version: version}
			tests := []struct {
				op    string
				cause error
				run   func() error
			}{
				{"create", store.ErrExists, func() error {
					_, err := b.Create(t.Context(), iam.KindUser, "alice", spec)
					return err
				}},
				{"update", store.ErrConflict, func() error {
					_, err := b.Update(t.Context(), iam.KindUser, "alice", spec, "stale")
					return err
				}},
				{"get", store.ErrNotFound, func() error {
					_, err := b.Get(t.Context(), iam.KindUser, "missing")
					return err
				}},
				{"list", store.ErrUnavailable, func() error {
					_, err := b.List(t.Context(), iam.KindUser)
					return err
				}},
				{"delete", store.ErrNotFound, func() error { return b.Delete(t.Context(), iam.KindUser, "missing", "") }},
				{"update if", store.ErrConflict, func() error {
					_, err := b.UpdateIf(t.Context(), iam.KindUser, "alice", spec, "stale", pre)
					return err
				}},
				{"delete if", store.ErrNoVersion, func() error {
					return b.DeleteIf(t.Context(), iam.KindUser, "alice", "", pre)
				}},
			}
			for _, tc := range tests {
				t.Run(tc.op, func(t *testing.T) { checkStoreError(t, adapter+" "+tc.op, tc.run(), tc.cause) })
			}
		})
	}
}

func checkStoreError(t *testing.T, operation string, err, cause error) {
	t.Helper()
	if err == nil || !strings.HasPrefix(err.Error(), "store "+operation+" IamUser: ") {
		t.Fatalf("operation or kind missing: %v", err)
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("cause lost: %v", err)
	}
}

func TestMutatePreservesCallbackFault(t *testing.T) {
	for _, unbounded := range []bool{false, true} {
		b := memstore.New()
		obj := iam.User{Name: "alice", ID: "AIDAALICE"}
		before, err := store.Create(t.Context(), b, obj)
		if err != nil {
			t.Fatal(err)
		}
		cause := errors.New("application refusal")
		callback := func(*iam.User) error { return cause }
		if unbounded {
			_, err = store.MutateWhileAlive(t.Context(), b, obj.Name, callback)
		} else {
			_, err = store.Mutate(t.Context(), b, obj.Name, callback)
		}
		if !errors.Is(err, cause) || err.Error() != cause.Error() {
			t.Fatalf("callback fault changed: %v", err)
		}
		after, err := store.Get[iam.User](t.Context(), b, obj.Name)
		if err != nil || after.Version != before {
			t.Fatalf("refused mutation wrote state: %v", err)
		}
	}
}
