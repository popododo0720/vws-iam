package grpcapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const updateURL = "https://Update.Example.test/team"

func seedOIDC(t *testing.T, e *env, url string, ids, tps []string) {
	t.Helper()
	tags := []*iamv1.Tag{samlTag("team", "a")}
	if _, err := e.api.CreateOpenIDConnectProvider(t.Context(), proj, url, ids, tps, tags); err != nil {
		t.Fatal(err)
	}
}

// sameOIDCIdentity fails unless got keeps what an update never changes of
// want: UID, URL, tags and creation time.
func sameOIDCIdentity(t *testing.T, got, want iam.OIDCProvider) {
	t.Helper()
	if got.UID != want.UID || got.URL != want.URL || !got.Created.Equal(want.Created) ||
		len(got.Tags) != 1 || got.Tags["team"] != "a" {
		t.Fatalf("update changed the identity: %+v, want %+v", got, want)
	}
}

// TestUpdateOpenIDConnectProviderThumbprint: the thumbprint list is
// replaced as a whole, a repeat (in any case) kept once in order, an empty
// list clears it; an equal list writes nothing; a write moves the
// generation and keeps the UID, URL, client ids, tags and creation time,
// and a replica started later on the same store reads it. An ARN of
// another account and an unknown provider are NoSuchEntity. On both store
// backends.
func TestUpdateOpenIDConnectProviderThumbprint(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			tps := thumbprints(4)
			seedOIDC(t, e, updateURL, []string{"app", "other"}, tps[:1])
			key := iam.OIDCProviderKey(updateURL)
			first := storedOIDC(t, b, key)
			arn := oidcARN(proj, updateURL)

			if err := e.api.UpdateOpenIDConnectProviderThumbprint(t.Context(), proj, arn,
				[]string{tps[1], tps[2], strings.ToUpper(tps[1]), tps[3]}); err != nil {
				t.Fatal(err)
			}
			replica := newEnvOn(t, b, &now)
			got, err := replica.api.GetOpenIDConnectProvider(t.Context(), proj, arn)
			if err != nil {
				t.Fatal(err)
			}
			p := got.Provider
			if !slices.Equal(p.Thumbprints, []string{tps[1], tps[2], tps[3]}) ||
				!slices.Equal(p.ClientIDs, []string{"app", "other"}) || p.Generation != first.Object.Generation+1 {
				t.Fatalf("after replace: %+v", p)
			}
			sameOIDCIdentity(t, p, first.Object)

			written := storedOIDC(t, b, key)
			for _, same := range [][]string{
				{tps[1], tps[2], tps[3]}, {tps[1], tps[2], tps[3], strings.ToUpper(tps[2])},
			} {
				if err := replica.api.UpdateOpenIDConnectProviderThumbprint(t.Context(), proj, arn, same); err != nil {
					t.Fatal(err)
				}
				if again := storedOIDC(t, b, key); again.Version != written.Version {
					t.Fatalf("an equal list wrote the provider: version %s, want %s", again.Version, written.Version)
				}
			}

			for range 2 { // the second is a repeat that writes nothing
				if err := e.api.UpdateOpenIDConnectProviderThumbprint(t.Context(), proj, arn, nil); err != nil {
					t.Fatal(err)
				}
			}
			cleared := storedOIDC(t, b, key).Object
			if len(cleared.Thumbprints) != 0 || cleared.Generation != p.Generation+1 {
				t.Fatalf("after an empty list: %+v, want no thumbprint and one more write", cleared)
			}
			sameOIDCIdentity(t, cleared, first.Object)

			wantAWS(t, e.api.UpdateOpenIDConnectProviderThumbprint(t.Context(), proj,
				oidcARN("other", updateURL), tps[:1]), codes.NotFound, "NoSuchEntity")
			wantAWS(t, e.api.UpdateOpenIDConnectProviderThumbprint(t.Context(), proj,
				oidcARN(proj, "https://unknown.test"), tps[:1]), codes.NotFound, "NoSuchEntity")
			wantAWS(t, e.api.UpdateOpenIDConnectProviderThumbprint(t.Context(), proj,
				oidcARN(proj, strings.ToLower(updateURL)), tps[:1]), codes.NotFound, "NoSuchEntity")
			oidcGone(t, b, "https://unknown.test")
		})
	}
}

// TestOIDCProviderClientIDs: a client id is added after the ones the
// provider has and removed in place; an id already present (add) or absent
// (remove) writes nothing, so every call replays unchanged; removing the
// last one leaves none; the 101st id is LimitExceeded and nothing is
// written, while an id the full provider already has is still accepted.
// The UID, URL, thumbprints, tags and creation time stay. On both store
// backends.
func TestOIDCProviderClientIDs(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			seedOIDC(t, e, updateURL, []string{"app"}, thumbprints(2))
			key := iam.OIDCProviderKey(updateURL)
			arn := oidcARN(proj, updateURL)
			first := storedOIDC(t, b, key)
			replica := newEnvOn(t, b, &now)

			step := func(name string, call func() error, want []string, writes bool) {
				t.Helper()
				before := storedOIDC(t, b, key)
				if err := call(); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				after := storedOIDC(t, b, key)
				if !slices.Equal(after.Object.ClientIDs, want) || len(after.Object.ClientIDs) != len(want) {
					t.Fatalf("%s: client ids %q, want %q", name, after.Object.ClientIDs, want)
				}
				if wrote := after.Version != before.Version; wrote != writes {
					t.Fatalf("%s: wrote = %v, want %v", name, wrote, writes)
				}
				if writes && after.Object.Generation != before.Object.Generation+1 {
					t.Fatalf("%s: generation %d after %d", name, after.Object.Generation, before.Object.Generation)
				}
				sameOIDCIdentity(t, after.Object, first.Object)
				if !slices.Equal(after.Object.Thumbprints, first.Object.Thumbprints) {
					t.Fatalf("%s: thumbprints %q changed", name, after.Object.Thumbprints)
				}
			}
			add := func(id string) func() error {
				return func() error { return e.api.AddClientIDToOpenIDConnectProvider(ctx, proj, arn, id) }
			}
			remove := func(id string) func() error {
				return func() error { return replica.api.RemoveClientIDFromOpenIDConnectProvider(ctx, proj, arn, id) }
			}
			step("add", add("x"), []string{"app", "x"}, true)
			step("add again", add("x"), []string{"app", "x"}, false)
			step("add the first", add("app"), []string{"app", "x"}, false)
			step("add in another case", add("X"), []string{"app", "x", "X"}, true)
			step("remove", remove("app"), []string{"x", "X"}, true)
			step("remove again", remove("app"), []string{"x", "X"}, false)
			step("remove absent", remove("never"), []string{"x", "X"}, false)
			step("remove one", remove("X"), []string{"x"}, true)
			step("remove last", remove("x"), nil, true)
			step("remove from none", remove("x"), nil, false)

			const full = "https://full.test"
			seedOIDC(t, e, full, clientIDs(iam.MaxOIDCClientIDs), nil)
			fullKey, fullARN := iam.OIDCProviderKey(full), oidcARN(proj, full)
			held := storedOIDC(t, b, fullKey)
			wantAWS(t, e.api.AddClientIDToOpenIDConnectProvider(ctx, proj, fullARN, "one-more"),
				codes.ResourceExhausted, "LimitExceeded")
			if err := e.api.AddClientIDToOpenIDConnectProvider(ctx, proj, fullARN, "app-7"); err != nil {
				t.Fatalf("an id the full provider has: %v", err)
			}
			if again := storedOIDC(t, b, fullKey); again.Version != held.Version {
				t.Fatalf("a refused or repeated add wrote the provider: %+v", again.Object.ClientIDs)
			}
			if err := e.api.RemoveClientIDFromOpenIDConnectProvider(ctx, proj, fullARN, "app-7"); err != nil {
				t.Fatal(err)
			}
			if err := e.api.AddClientIDToOpenIDConnectProvider(ctx, proj, fullARN, "one-more"); err != nil {
				t.Fatalf("add after a remove freed a slot: %v", err)
			}
			ids := storedOIDC(t, b, fullKey).Object.ClientIDs
			if len(ids) != iam.MaxOIDCClientIDs || ids[len(ids)-1] != "one-more" {
				t.Fatalf("%d client ids ending in %q", len(ids), ids[len(ids)-1])
			}
		})
	}
}

// TestOIDCProviderUpdateConcurrent: racing adds of distinct client ids on
// two replicas all succeed and lose no id; racing adds of one id make it
// once and write it once. On both store backends.
func TestOIDCProviderUpdateConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			ctx := t.Context()
			seedOIDC(t, replicas[0], updateURL, []string{"app"}, nil)
			key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)

			race := func(id func(i int) string) {
				errs := make([]error, 8)
				var wg sync.WaitGroup
				for i := range errs {
					wg.Go(func() { errs[i] = replicas[i%2].api.AddClientIDToOpenIDConnectProvider(ctx, proj, arn, id(i)) })
				}
				wg.Wait()
				for i, err := range errs {
					if err != nil {
						t.Errorf("add %d: %v", i, err)
					}
				}
			}
			race(func(i int) string { return "racer-" + strconv.Itoa(i) })
			ids := storedOIDC(t, b, key).Object.ClientIDs
			if len(ids) != 9 || ids[0] != "app" {
				t.Fatalf("client ids %q, want app and the 8 racers", ids)
			}
			for i := range 8 {
				if !slices.Contains(ids, "racer-"+strconv.Itoa(i)) {
					t.Errorf("racer-%d lost: %q", i, ids)
				}
			}

			before := storedOIDC(t, b, key).Object.Generation
			race(func(int) string { return "same" })
			after := storedOIDC(t, b, key).Object
			n := slices.Index(after.ClientIDs, "same")
			if n != 9 || len(after.ClientIDs) != 10 || after.Generation != before+1 {
				t.Fatalf("client ids %q generation %d (was %d), want \"same\" once and one write",
					after.ClientIDs, after.Generation, before)
			}
		})
	}
}

// changingOIDCBeforeUpdate rewrites the tags of an OIDC provider before
// the first n updates of one, as a concurrent write between the read and
// the update would.
type changingOIDCBeforeUpdate struct {
	store.Backend
	mu sync.Mutex
	n  int
	t  *testing.T
}

func (c *changingOIDCBeforeUpdate) Update(
	ctx context.Context, k iam.Kind, key string, spec []byte, version string,
) (string, error) {
	if k == iam.KindOIDCProvider {
		c.mu.Lock()
		change := c.n > 0
		c.n--
		c.mu.Unlock()
		if change {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(p *iam.OIDCProvider) error {
				p.Tags = map[string]string{"team": "a", "writer": "other"}
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		}
	}
	return c.Backend.Update(ctx, k, key, spec, version)
}

// updateCalls are the three update calls, each with the value it sets and
// whether a provider holds it.
var updateCalls = []struct {
	name string
	call func(ctx context.Context, e *env, arn string) error
	has  func(p iam.OIDCProvider) bool
}{
	{
		"thumbprint",
		func(ctx context.Context, e *env, arn string) error {
			return e.api.UpdateOpenIDConnectProviderThumbprint(ctx, proj, arn, thumbprints(3)[2:])
		},
		func(p iam.OIDCProvider) bool { return slices.Equal(p.Thumbprints, thumbprints(3)[2:]) },
	},
	{
		"add",
		func(ctx context.Context, e *env, arn string) error {
			return e.api.AddClientIDToOpenIDConnectProvider(ctx, proj, arn, "added")
		},
		func(p iam.OIDCProvider) bool { return slices.Contains(p.ClientIDs, "added") },
	},
	{
		"remove",
		func(ctx context.Context, e *env, arn string) error {
			return e.api.RemoveClientIDFromOpenIDConnectProvider(ctx, proj, arn, "app")
		},
		func(p iam.OIDCProvider) bool { return !slices.Contains(p.ClientIDs, "app") },
	},
}

// TestOIDCProviderUpdateStaleRead: a provider written after it was read
// is read again and then changed, keeping the other writer's change, never
// written from a stale copy; one that keeps changing is
// ConcurrentModification and keeps its value. On both store backends.
func TestOIDCProviderUpdateStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		for _, c := range updateCalls {
			t.Run(bk.name+"/"+c.name, func(t *testing.T) {
				inner := bk.open()
				now := time.Now().UTC()
				seedOIDC(t, newEnvOn(t, inner, &now), updateURL, []string{"app"}, thumbprints(1))
				key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)

				b := &changingOIDCBeforeUpdate{Backend: inner, n: 1, t: t}
				if err := c.call(t.Context(), newEnvOn(t, b, &now), arn); err != nil {
					t.Fatalf("after one concurrent write: %v", err)
				}
				p := storedOIDC(t, inner, key).Object
				if !c.has(p) || p.Tags["writer"] != "other" {
					t.Fatalf("stored %+v, want the change and the other writer's tags", p)
				}

				// The provider no longer differs from the change, so the busy
				// writer starts from one that does.
				const busy = "https://busy.test"
				seedOIDC(t, newEnvOn(t, inner, &now), busy, []string{"app"}, thumbprints(1))
				b = &changingOIDCBeforeUpdate{Backend: inner, n: 1 << 30, t: t}
				wantAWS(t, c.call(t.Context(), newEnvOn(t, b, &now), oidcARN(proj, busy)), codes.Aborted, "ConcurrentModification")
				if c.has(storedOIDC(t, inner, iam.OIDCProviderKey(busy)).Object) {
					t.Fatal("a ConcurrentModification call stored its change")
				}
			})
		}
	}
}

// TestOIDCProviderUpdateCanceled: a canceled call writes nothing, and the
// same request afterwards changes the provider.
func TestOIDCProviderUpdateCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedOIDC(t, e, updateURL, []string{"app"}, thumbprints(1))
	key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	calls := []func(ctx context.Context) error{
		func(ctx context.Context) error {
			return e.api.UpdateOpenIDConnectProviderThumbprint(ctx, proj, arn, thumbprints(3)[2:])
		},
		func(ctx context.Context) error {
			return e.api.AddClientIDToOpenIDConnectProvider(ctx, proj, arn, "added")
		},
		func(ctx context.Context) error {
			return e.api.RemoveClientIDFromOpenIDConnectProvider(ctx, proj, arn, "app")
		},
	}
	before := storedOIDC(t, b, key)
	for i, call := range calls {
		if err := call(canceled); err == nil {
			t.Fatalf("call %d: a canceled request succeeded", i)
		}
		if v := storedOIDC(t, b, key).Version; v != before.Version {
			t.Fatalf("call %d: a canceled request wrote the provider", i)
		}
	}
	for i, call := range calls {
		if err := call(t.Context()); err != nil {
			t.Fatalf("call %d: the same request afterwards: %v", i, err)
		}
	}
	p := storedOIDC(t, b, key).Object
	if !slices.Equal(p.Thumbprints, thumbprints(3)[2:]) || !slices.Equal(p.ClientIDs, []string{"added"}) {
		t.Fatalf("stored %+v, want all three changes", p)
	}
}

// TestOIDCProviderUpdateErrors: a bad project, a bad ARN, a thumbprint of
// 39 or 41 characters or not hex, six distinct thumbprints and a client id
// of none, 256 characters or invalid UTF-8 are answered before any store
// access (the store here fails every read), never echoing the ARN; the
// boundary values are accepted; a store failure on a valid request is
// ServiceFailure (ServiceUnavailable when unavailable). None changes the
// stored provider.
// corruptOIDCGet returns an OIDC provider that does not validate (its URL
// has a port), as an operator edit of the custom resource could leave it.
type corruptOIDCGet struct{ store.Backend }

func (c corruptOIDCGet) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	if k != iam.KindOIDCProvider {
		return c.Backend.Get(ctx, k, key)
	}
	spec, err := json.Marshal(iam.OIDCProvider{URL: "https://idp.test:443", ClientIDs: []string{"app"}})
	return store.Entry{Key: key, Spec: spec, Version: "1"}, err
}

func TestOIDCProviderUpdateErrors(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	seedOIDC(t, newEnvOn(t, inner, &now), updateURL, []string{"app"}, thumbprints(1))
	key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)
	stored := storedOIDC(t, inner, key)
	down := newEnvOn(t, failingGet{Backend: inner, k: iam.KindOIDCProvider, err: store.ErrUnavailable}, &now)
	ctx := t.Context()
	const canary = "CANARY"
	tps := thumbprints(7)
	prefix := "arn:vws:iam::" + proj + ":oidc-provider/"

	for _, c := range []struct {
		name, pid, arn, aws string
		code                codes.Code
	}{
		{"bad project", "Bad_Project", arn, "ValidationError", codes.InvalidArgument},
		{"ARN of 19 characters", proj, strings.Repeat("a", 19), "ValidationError", codes.InvalidArgument},
		{
			"ARN of 2049 characters", proj, prefix + strings.Repeat("a", 2049-len(prefix)),
			"ValidationError", codes.InvalidArgument,
		},
		{
			"SAML provider ARN", proj, "arn:vws:iam::" + proj + ":saml-provider/" + canary,
			"InvalidInput", codes.InvalidArgument,
		},
		{"host with a port", proj, prefix + canary + ".test:443", "InvalidInput", codes.InvalidArgument},
		{"query", proj, prefix + "idp.test/?" + canary, "InvalidInput", codes.InvalidArgument},
		{"another account", proj, oidcARN("other", updateURL), "NoSuchEntity", codes.NotFound},
	} {
		t.Run(c.name, func(t *testing.T) {
			errs := []error{
				down.api.UpdateOpenIDConnectProviderThumbprint(ctx, c.pid, c.arn, tps[:1]),
				down.api.AddClientIDToOpenIDConnectProvider(ctx, c.pid, c.arn, "id"),
				down.api.RemoveClientIDFromOpenIDConnectProvider(ctx, c.pid, c.arn, "id"),
			}
			for i, err := range errs {
				wantAWS(t, err, c.code, c.aws)
				if strings.Contains(status.Convert(err).Message(), canary) {
					t.Fatalf("call %d: message carries the ARN: %q", i, status.Convert(err).Message())
				}
			}
		})
	}

	for _, c := range []struct {
		name string
		tps  []string
		aws  string
	}{
		{"39 characters", []string{tps[0][:39]}, "ValidationError"},
		{"41 characters", []string{tps[0] + "0"}, "ValidationError"},
		{"one bad among good", []string{tps[0], tps[1][:39]}, "ValidationError"},
		{"not hex", []string{strings.Repeat("g", iam.OIDCThumbprintLen)}, "InvalidInput"},
		{"six distinct", tps[:6], "InvalidInput"},
		{"six distinct among repeats", append(slices.Clone(tps[:6]), tps[0]), "InvalidInput"},
	} {
		t.Run("thumbprints "+c.name, func(t *testing.T) {
			wantAWS(t, down.api.UpdateOpenIDConnectProviderThumbprint(ctx, proj, arn, c.tps), codes.InvalidArgument, c.aws)
		})
	}

	for _, c := range []struct{ name, id, aws string }{
		{"none", "", "ValidationError"},
		{"256 characters", strings.Repeat("a", iam.MaxOIDCClientIDLen+1), "ValidationError"},
		{"invalid UTF-8", "bad\xff", "InvalidInput"},
	} {
		t.Run("client id "+c.name, func(t *testing.T) {
			wantAWS(t, down.api.AddClientIDToOpenIDConnectProvider(ctx, proj, arn, c.id), codes.InvalidArgument, c.aws)
			wantAWS(t, down.api.RemoveClientIDFromOpenIDConnectProvider(ctx, proj, arn, c.id), codes.InvalidArgument, c.aws)
		})
	}

	up := newEnvOn(t, inner, &now)
	for _, tp := range [][]string{append(slices.Clone(tps[:5]), strings.ToUpper(tps[0])), {strings.ToUpper(tps[0])}} {
		if err := up.api.UpdateOpenIDConnectProviderThumbprint(ctx, proj, arn, tp); err != nil {
			t.Errorf("%d thumbprints: %v", len(tp), err)
		}
	}
	for _, id := range []string{"a", strings.Repeat("é", iam.MaxOIDCClientIDLen)} {
		if err := up.api.AddClientIDToOpenIDConnectProvider(ctx, proj, arn, id); err != nil {
			t.Errorf("add %d characters: %v", len([]rune(id)), err)
		}
		if err := up.api.RemoveClientIDFromOpenIDConnectProvider(ctx, proj, arn, id); err != nil {
			t.Errorf("remove %d characters: %v", len([]rune(id)), err)
		}
	}
	// Return to the state the failures below are checked against.
	if err := up.api.UpdateOpenIDConnectProviderThumbprint(ctx, proj, arn, tps[:1]); err != nil {
		t.Fatal(err)
	}
	stored = storedOIDC(t, inner, key)

	boom := errors.New("backend down")
	for _, c := range []struct {
		name string
		b    store.Backend
		code codes.Code
		aws  string
	}{
		{"read fails", failingGet{Backend: inner, k: iam.KindOIDCProvider, err: boom}, codes.Internal, "ServiceFailure"},
		{
			"store down",
			failingGet{Backend: inner, k: iam.KindOIDCProvider, err: store.ErrUnavailable},
			codes.Unavailable, "ServiceUnavailable",
		},
		{"write fails", failingUpdate{Backend: inner, k: iam.KindOIDCProvider, err: boom}, codes.Internal, "ServiceFailure"},
		{"stored provider does not validate", corruptOIDCGet{Backend: inner}, codes.Internal, "ServiceFailure"},
		{
			"write unavailable",
			failingUpdate{Backend: inner, k: iam.KindOIDCProvider, err: store.ErrUnavailable},
			codes.Unavailable, "ServiceUnavailable",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnvOn(t, c.b, &now)
			errs := []error{
				e.api.UpdateOpenIDConnectProviderThumbprint(t.Context(), proj, arn, tps[1:2]),
				e.api.AddClientIDToOpenIDConnectProvider(t.Context(), proj, arn, "new"),
				e.api.RemoveClientIDFromOpenIDConnectProvider(t.Context(), proj, arn, "app"),
			}
			for _, err := range errs {
				wantAWS(t, err, c.code, c.aws)
			}
			if v := storedOIDC(t, inner, key).Version; v != stored.Version {
				t.Fatalf("stored provider written: version %s, want %s", v, stored.Version)
			}
		})
	}
}
