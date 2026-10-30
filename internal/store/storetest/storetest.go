// Package storetest is the suite every store.Backend passes. It is the one
// production-tree package allowed to import testing.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func sealed() iam.Sealed { return iam.Sealed{KeyID: "kek-1", Ciphertext: []byte{1, 2, 3}} }

// Samples has one valid object of every kind.
func Samples() []iam.Object {
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	return []iam.Object{
		iam.User{Name: "Alice", ID: "AIDA1", Created: now, Meta: iam.Meta{UID: "u-1", Generation: 1, Labels: map[string]string{"team": "a"}}, InlinePolicies: map[string]string{"p": `{}`}},
		iam.Group{Name: "admins", ID: "AGPA1", Created: now, Members: []string{"Alice"}, AttachedPolicies: []string{"arn:vws:iam::000000000000:policy/x"}},
		iam.Role{Name: "deployer", ID: "AROA1", Created: now, AssumeRolePolicy: `{"Version":"2012-10-17","Statement":[]}`, MaxSessionDuration: time.Hour},
		iam.Policy{Name: "x", ID: "ANPA1", Created: now, DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1", Document: `{}`, Created: now}}},
		iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "Alice", Status: iam.KeyActive, Created: now, Secret: sealed()},
		iam.MfaDevice{Name: "alice-phone", UserName: "Alice", Created: now, Seed: sealed()},
		iam.KeyIndex{ID: "AKIAABCDEFGHIJKLMNOP", Project: "proj-a"},
		iam.Session{Hash: strings.Repeat("ab", 32), Project: "proj-a", UserName: "Alice", AuthTime: now, Expires: now.Add(time.Hour)},
		iam.Operation{ID: "op-1", Project: "proj-a", Response: []byte{1}, Created: now},
		iam.ReplayEntry{Hash: strings.Repeat("cd", 32), Expires: now.Add(time.Hour)},
		iam.AttemptCounter{Hash: strings.Repeat("ef", 32), Scope: iam.AttemptIP, Failures: 1, WindowStart: now},
		iam.FidoDevice{
			ID: iam.FidoID([]byte("credential-id-0001")), UserName: "Alice", UserUID: "u-1", Label: "yubikey",
			CredentialID: []byte("credential-id-0001"), PublicKey: []byte{0xa5, 1, 2},
			AAGUID:    "cb69481e-8ff7-4039-93ec-0a2729a154a8",
			SignCount: 7, EnableTime: now, Certifications: map[string]string{"FIDO": "L1", "FIDO-FIPS-140-2": "L2"},
			Meta: iam.Meta{UID: "f-1", Generation: 1},
		},
	}
}

func roundTrip[T iam.Object](t *testing.T, b store.Backend, obj T, changed T) {
	ctx := context.Background()
	v1, err := store.Create(ctx, b, obj)
	if err != nil {
		t.Fatalf("create %s: %v", obj.Kind(), err)
	}
	if _, err := store.Create(ctx, b, obj); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second create %s: %v, want ErrExists", obj.Kind(), err)
	}
	got, err := store.Get[T](ctx, b, obj.Key())
	if err != nil || got.Version != v1 {
		t.Fatalf("get %s: %v version %q want %q", obj.Kind(), err, got.Version, v1)
	}
	if a, b := mustJSON(t, got.Object), mustJSON(t, obj); a != b {
		t.Fatalf("%s round trip:\n got %s\nwant %s", obj.Kind(), a, b)
	}
	v2, err := store.Update(ctx, b, changed, v1)
	if err != nil || v2 == v1 {
		t.Fatalf("update %s: %v (%q -> %q)", obj.Kind(), err, v1, v2)
	}
	if _, err := store.Update(ctx, b, obj, v1); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update %s: %v, want ErrConflict", obj.Kind(), err)
	}
	all, err := store.List[T](ctx, b)
	if err != nil || len(all) != 1 {
		t.Fatalf("list %s: %v %d", obj.Kind(), err, len(all))
	}
	if err := store.Delete[T](ctx, b, obj.Key(), v1); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale delete %s: %v", obj.Kind(), err)
	}
	if err := store.Delete[T](ctx, b, obj.Key(), v2); err != nil {
		t.Fatalf("delete %s: %v", obj.Kind(), err)
	}
	if _, err := store.Get[T](ctx, b, obj.Key()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get deleted %s: %v", obj.Kind(), err)
	}
	if err := store.Delete[T](ctx, b, obj.Key(), ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing %s: %v", obj.Kind(), err)
	}
}

// Run runs the suite. open returns a fresh empty backend.
func Run(t *testing.T, open func(t *testing.T) store.Backend) {
	t.Run("RoundTripEveryKind", func(t *testing.T) {
		b := open(t)
		later := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		for _, o := range Samples() {
			switch o := o.(type) {
			case iam.User:
				c := o
				c.Created = later
				roundTrip(t, b, o, c)
			case iam.Group:
				c := o
				c.Created = later
				roundTrip(t, b, o, c)
			case iam.Role:
				c := o
				c.Created = later
				roundTrip(t, b, o, c)
			case iam.Policy:
				c := o
				c.Created = later
				roundTrip(t, b, o, c)
			case iam.AccessKey:
				c := o
				c.Created = later
				roundTrip(t, b, o, c)
			case iam.MfaDevice:
				c := o
				c.Created = later
				roundTrip(t, b, o, c)
			case iam.KeyIndex:
				c := o
				c.Project = "proj-b"
				roundTrip(t, b, o, c)
			case iam.Session:
				c := o
				c.Expires = later
				roundTrip(t, b, o, c)
			case iam.Operation:
				c := o
				c.Created = later
				roundTrip(t, b, o, c)
			case iam.ReplayEntry:
				c := o
				c.Expires = later
				roundTrip(t, b, o, c)
			case iam.AttemptCounter:
				c := o
				c.Failures, c.LockedUntil = 2, later
				roundTrip(t, b, o, c)
			case iam.FidoDevice:
				c := o
				c.SignCount = 8
				roundTrip(t, b, o, c)
			}
		}
	})
	t.Run("ListPageCoversEveryEntry", func(t *testing.T) {
		b := open(t)
		if _, ok := b.(store.Pager); !ok {
			t.Skip("backend has no Pager")
		}
		ctx := context.Background()
		want := map[string]bool{}
		for i := range 5 {
			h := strings.Repeat(strconv.Itoa(i), 64)
			if _, err := store.Create(ctx, b, iam.ReplayEntry{Hash: h, Expires: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
				t.Fatal(err)
			}
			want[h] = true
		}
		got, pages, cont := map[string]bool{}, 0, ""
		for {
			vs, next, err := store.ListPage[iam.ReplayEntry](ctx, b, 2, cont)
			if err != nil {
				t.Fatal(err)
			}
			// An API server may ignore limit (the fake client does) but
			// then returns everything at once.
			if len(vs) > 2 && next != "" {
				t.Fatalf("page of %d with a continue token, limit 2", len(vs))
			}
			pages++
			for _, v := range vs {
				if got[v.Object.Hash] {
					t.Fatalf("%s listed twice", v.Object.Hash)
				}
				got[v.Object.Hash] = true
			}
			if cont = next; cont == "" {
				break
			}
		}
		t.Logf("%d entries in %d pages", len(got), pages)
		if len(got) != len(want) || (pages != 3 && pages != 1) {
			t.Fatalf("got %d entries in %d pages, want 5 in 3 (or 1 if limit is ignored)", len(got), pages)
		}
	})
	t.Run("NamesAreCaseInsensitive", func(t *testing.T) {
		b := open(t)
		ctx := context.Background()
		if _, err := store.Create(ctx, b, iam.User{Name: "Bob", ID: "1"}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Create(ctx, b, iam.User{Name: "BOB", ID: "2"}); !errors.Is(err, store.ErrExists) {
			t.Fatalf("BOB after Bob: %v", err)
		}
		got, err := store.Get[iam.User](ctx, b, "bob")
		if err != nil || got.Object.Name != "Bob" {
			t.Fatalf("get bob: %v %+v", err, got.Object)
		}
	})
	t.Run("InvalidObjectIsNotStored", func(t *testing.T) {
		b := open(t)
		ctx := context.Background()
		if _, err := store.Create(ctx, b, iam.User{Name: "bad name!"}); !errors.Is(err, iam.ErrInvalid) {
			t.Fatalf("bad name: %v", err)
		}
		if _, err := store.Create(ctx, b, iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "a", Status: iam.KeyActive}); !errors.Is(err, iam.ErrInvalid) {
			t.Fatalf("unsealed key: %v", err)
		}
		if all, err := store.List[iam.User](ctx, b); err != nil || len(all) != 0 {
			t.Fatalf("stored %d invalid users", len(all))
		}
	})
	t.Run("ConcurrentMutateLosesNoWrite", func(t *testing.T) {
		b := open(t)
		ctx := context.Background()
		if _, err := store.Create(ctx, b, iam.Group{Name: "carol", ID: "1"}); err != nil {
			t.Fatal(err)
		}
		groups := []string{"u1", "u2", "u3", "u4"}
		var wg sync.WaitGroup
		for _, g := range groups {
			wg.Go(func() {
				if _, err := store.Mutate(ctx, b, "carol", func(u *iam.Group) error {
					u.Members = append(u.Members, g)
					return nil
				}); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		got, err := store.Get[iam.Group](ctx, b, "carol")
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Object.Members) != len(groups) {
			t.Fatalf("members %v, want all of %v", got.Object.Members, groups)
		}
	})
	t.Run("ConditionalWriteNeedsPrecondition", func(t *testing.T) {
		conditionalWrite(t, open(t))
	})
	t.Run("ConditionalWriteFailsAfterPreconditionMoves", func(t *testing.T) {
		conditionalWriteAfterMove(t, open(t))
	})
	t.Run("ReopenKeepsState", func(t *testing.T) {
		// A restart reads the same backend: nothing lives outside it.
		b := open(t)
		ctx := context.Background()
		if _, err := store.Create(ctx, b, iam.Group{Name: "ops", ID: "1"}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get[iam.Group](ctx, b, "OPS"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("PolicyName128RoundTrip", func(t *testing.T) {
		b := open(t)
		ctx := context.Background()
		now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
		name := strings.Repeat("P", 128)
		pol := iam.Policy{
			Name: name, ID: "ANPA1", Created: now, DefaultVersion: "v1",
			Versions: []iam.PolicyVersion{{ID: "v1", Document: `{}`, Created: now}},
		}
		if _, err := store.Create(ctx, b, pol); err != nil {
			t.Fatalf("create 128-character policy: %v", err)
		}
		got, err := store.Get[iam.Policy](ctx, b, strings.Repeat("p", 128))
		if err != nil {
			t.Fatalf("get folded name: %v", err)
		}
		if got.Object.Name != name {
			t.Fatalf("name %q", got.Object.Name)
		}
		if _, err := store.Create(ctx, b, pol); !errors.Is(err, store.ErrExists) {
			t.Fatalf("second create: %v", err)
		}
		long := pol
		long.Name = strings.Repeat("P", 129)
		if _, err := store.Create(ctx, b, long); !errors.Is(err, iam.ErrInvalid) {
			t.Fatalf("create 129-character policy: %v", err)
		}
		all, err := store.List[iam.Policy](ctx, b)
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 1 || all[0].Object.Name != name {
			t.Fatalf("list %d policies", len(all))
		}
	})
	t.Run("InlinePolicyName128RoundTrip", func(t *testing.T) {
		b := open(t)
		ctx := context.Background()
		name := strings.Repeat("P", 128)
		u := iam.User{Name: "alice", ID: "AIDA1", InlinePolicies: map[string]string{name: `{}`}}
		if _, err := store.Create(ctx, b, u); err != nil {
			t.Fatalf("create user with a 128-character inline policy: %v", err)
		}
		got, err := store.Get[iam.User](ctx, b, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if doc, ok := got.Object.InlinePolicies[name]; !ok || doc != `{}` {
			t.Fatalf("inline policies %v", got.Object.InlinePolicies)
		}
		long := iam.User{Name: "bob", ID: "AIDA2", InlinePolicies: map[string]string{strings.Repeat("P", 129): `{}`}}
		if _, err := store.Create(ctx, b, long); !errors.Is(err, iam.ErrInvalid) {
			t.Fatalf("create user with a 129-character inline policy: %v", err)
		}
	})
}

// guarded creates a user and one of its access keys, the shape of the
// conditional writes the gRPC API makes.
func guarded(t *testing.T, b store.Backend) (store.Versioned[iam.User], store.Versioned[iam.AccessKey]) {
	t.Helper()
	ctx := context.Background()
	u := iam.User{Name: "Carol", ID: "AIDA1", Path: "/allowed/"}
	uv, err := store.Create(ctx, b, u)
	if err != nil {
		t.Fatal(err)
	}
	k := iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "Carol", Status: iam.KeyActive, Secret: sealed()}
	kv, err := store.Create(ctx, b, k)
	if err != nil {
		t.Fatal(err)
	}
	return store.Versioned[iam.User]{Object: u, Version: uv}, store.Versioned[iam.AccessKey]{Object: k, Version: kv}
}

// keyIs fails unless the stored key has status st.
func keyIs(t *testing.T, b store.Backend, st iam.KeyStatus) store.Versioned[iam.AccessKey] {
	t.Helper()
	got, err := store.Get[iam.AccessKey](context.Background(), b, "AKIAABCDEFGHIJKLMNOP")
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if got.Object.Status != st {
		t.Fatalf("key status %q, want %q", got.Object.Status, st)
	}
	return got
}

// conditionalWrite: UpdateIf and DeleteIf commit while the precondition
// holds (the key folds case like every key) and refuse a missing
// precondition object, a stale key, and a delete without a version.
func conditionalWrite(t *testing.T, b store.Backend) {
	ctx := context.Background()
	u, k := guarded(t, b)
	off := k.Object
	off.Status = iam.KeyInactive

	missing := store.Pre{Kind: iam.KindUser, Key: "nobody", Version: u.Version}
	if _, err := store.UpdateIf(ctx, b, off, k.Version, missing); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("update under a missing precondition object: %v, want ErrConflict", err)
	}
	keyIs(t, b, iam.KeyActive)

	pre := store.PreOf(u)
	pre.Key = "CAROL"
	kv, err := store.UpdateIf(ctx, b, off, k.Version, pre)
	if err != nil || kv == k.Version {
		t.Fatalf("update while the precondition holds: %v (%q -> %q)", err, k.Version, kv)
	}
	keyIs(t, b, iam.KeyInactive)

	// The precondition object may have a new version now (a backend may
	// fence it), but its content is unchanged. Reading it again gives the
	// precondition for the next write.
	cur, err := store.Get[iam.User](ctx, b, "carol")
	if err != nil || cur.Object.Path != "/allowed/" {
		t.Fatalf("precondition object after the write: %v %+v", err, cur.Object)
	}
	pre = store.PreOf(cur)
	if _, err := store.UpdateIf(ctx, b, k.Object, k.Version, pre); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale key update: %v, want ErrConflict", err)
	}
	keyIs(t, b, iam.KeyInactive)
	if err := store.DeleteIf[iam.AccessKey](ctx, b, k.Object.ID, k.Version, pre); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale key delete: %v, want ErrConflict", err)
	}
	if err := store.DeleteIf[iam.AccessKey](ctx, b, k.Object.ID, "", pre); !errors.Is(err, store.ErrNoVersion) {
		t.Fatalf("delete without a version: %v, want ErrNoVersion", err)
	}
	keyIs(t, b, iam.KeyInactive)
	// A refused conditional write may also have advanced the version.
	if cur, err = store.Get[iam.User](ctx, b, "carol"); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteIf[iam.AccessKey](ctx, b, k.Object.ID, kv, store.PreOf(cur)); err != nil {
		t.Fatalf("delete while the precondition holds: %v", err)
	}
	if _, err := store.Get[iam.AccessKey](ctx, b, k.Object.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("key after the delete: %v", err)
	}
}

// conditionalWriteAfterMove: once the precondition object changes (an
// UpdateUser path move) or is deleted after it was read, neither a
// conditional update nor a conditional delete of the key commits, and the
// key keeps its state.
func conditionalWriteAfterMove(t *testing.T, b store.Backend) {
	ctx := context.Background()
	u, k := guarded(t, b)
	checked := store.PreOf(u)
	moved := u.Object
	moved.Path = "/denied/"
	if _, err := store.Update(ctx, b, moved, u.Version); err != nil {
		t.Fatal(err)
	}
	off := k.Object
	off.Status = iam.KeyInactive
	if _, err := store.UpdateIf(ctx, b, off, k.Version, checked); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("update after the precondition moved: %v, want ErrConflict", err)
	}
	if err := store.DeleteIf[iam.AccessKey](ctx, b, k.Object.ID, k.Version, checked); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete after the precondition moved: %v, want ErrConflict", err)
	}
	if got := keyIs(t, b, iam.KeyActive); got.Version != k.Version {
		t.Fatalf("key version %q, want %q: a refused write changed it", got.Version, k.Version)
	}

	cur, err := store.Get[iam.User](ctx, b, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete[iam.User](ctx, b, "carol", cur.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateIf(ctx, b, off, k.Version, store.PreOf(cur)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("update after the precondition object was deleted: %v, want ErrConflict", err)
	}
	keyIs(t, b, iam.KeyActive)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
