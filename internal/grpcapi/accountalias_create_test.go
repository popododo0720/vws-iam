package grpcapi_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// aliasClaimLease outlasts grpcapi.aliasClaimLease (60s).
const aliasClaimLease = 61 * time.Second

// listedAliases returns the aliases ListAccountAliases lists for pid.
func listedAliases(t *testing.T, e *env, pid string) []string {
	t.Helper()
	pg, err := e.api.ListAccountAliases(t.Context(), pid, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return pg.Aliases
}

// storedClaim returns the claim of alias, failing unless it is stored.
func storedClaim(t *testing.T, b store.Backend, alias string) store.Versioned[iam.AccountAliasClaim] {
	t.Helper()
	v, err := store.Get[iam.AccountAliasClaim](t.Context(), b, alias)
	if err != nil {
		t.Fatalf("claim of %s: %v, want stored", alias, err)
	}
	return v
}

// TestCreateAccountAlias: the alias is stored with the request time and
// claimed for the project, every replica lists it, a repeat is
// EntityAlreadyExists and changes nothing, and another project creating
// it is EntityAlreadyExists and gets no alias. On both store backends.
func TestCreateAccountAlias(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			if err := e.api.CreateAccountAlias(ctx, proj, "example-corporation"); err != nil {
				t.Fatal(err)
			}
			a := storedAlias(t, b, proj, "example-corporation")
			if a.Object.UID == "" || a.Object.Generation != 1 || !a.Object.Created.Equal(now) {
				t.Fatalf("stored %+v, want a UID, generation 1, created now", a.Object)
			}
			c := storedClaim(t, b, "example-corporation")
			if c.Object.Project != proj || !c.Object.Claimed.Equal(now) {
				t.Fatalf("claim %+v, want held by %s since now", c.Object, proj)
			}
			for _, replica := range []*env{e, other} {
				if got := listedAliases(t, replica, proj); !slices.Equal(got, []string{"example-corporation"}) {
					t.Fatalf("listed %q, want the created alias", got)
				}
			}
			err := other.api.CreateAccountAlias(ctx, proj, "example-corporation")
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			if !strings.Contains(err.Error(), "The account alias example-corporation already exists.") {
				t.Fatalf("EntityAlreadyExists message %q, want it to name the alias", err)
			}
			wantAWS(t, other.api.CreateAccountAlias(ctx, "other", "example-corporation"),
				codes.AlreadyExists, "EntityAlreadyExists")
			if got := storedAlias(t, b, proj, "example-corporation"); got.Version != a.Version {
				t.Fatalf("a refused create changed the alias: version %q, want %q", got.Version, a.Version)
			}
			if got := storedClaim(t, b, "example-corporation"); got.Version != c.Version {
				t.Fatalf("a refused create changed the claim: %+v", got.Object)
			}
			if got := listedAliases(t, e, "other"); len(got) != 0 {
				t.Fatalf("other project lists %q, want none", got)
			}
		})
	}
}

// TestCreateAccountAliasReplaces: a second alias overwrites the first,
// as in AWS, so the project lists only the new one and LimitExceeded
// never applies. The old alias stays claimed for the lease, so another
// project gets it only after the lease, while the project itself may
// take it back at once, renewing its claim. On both store backends.
func TestCreateAccountAliasReplaces(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			for i, alias := range []string{"first-corp", "second-corp", "third-corp"} {
				now = now.Add(time.Second)
				if err := e.api.CreateAccountAlias(ctx, proj, alias); err != nil {
					t.Fatalf("create %d (%s): %v", i, alias, err)
				}
				if got := listedAliases(t, e, proj); !slices.Equal(got, []string{alias}) {
					t.Fatalf("after creating %s the project lists %q, want only it", alias, got)
				}
			}
			aliasGone(t, b, proj, "first-corp")
			wantAWS(t, e.api.CreateAccountAlias(ctx, "other", "first-corp"), codes.AlreadyExists, "EntityAlreadyExists")
			now = now.Add(aliasClaimLease / 3) // past a quarter lease: the claim is renewed
			if err := e.api.CreateAccountAlias(ctx, proj, "second-corp"); err != nil {
				t.Fatalf("taking back the project's own old alias: %v", err)
			}
			if c := storedClaim(t, b, "second-corp"); c.Object.Project != proj || !c.Object.Claimed.Equal(now) {
				t.Fatalf("claim %+v, want renewed by %s now", c.Object, proj)
			}
			if got := listedAliases(t, e, proj); !slices.Equal(got, []string{"second-corp"}) {
				t.Fatalf("project lists %q, want second-corp", got)
			}
			now = now.Add(aliasClaimLease)
			if err := e.api.CreateAccountAlias(ctx, "other", "first-corp"); err != nil {
				t.Fatalf("another project after the lease: %v, want the stale claim taken over", err)
			}
			if c := storedClaim(t, b, "first-corp"); c.Object.Project != "other" {
				t.Fatalf("claim %+v, want held by other", c.Object)
			}
			if got := listedAliases(t, e, "other"); !slices.Equal(got, []string{"first-corp"}) {
				t.Fatalf("other lists %q, want first-corp", got)
			}
		})
	}
}

// TestCreateAccountAliasAfterDelete: a deleted alias stays claimed for
// the lease: another project is refused within it and takes it after.
// A claim older than the lease whose project still holds the alias is
// never taken over.
func TestCreateAccountAliasAfterDelete(t *testing.T) {
	b := memstore.New()
	now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	for _, alias := range []string{"kept-corp", "freed-corp"} {
		if err := e.api.CreateAccountAlias(ctx, "owner-"+alias, alias); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.api.DeleteAccountAlias(ctx, "owner-freed-corp", "freed-corp"); err != nil {
		t.Fatal(err)
	}
	wantAWS(t, e.api.CreateAccountAlias(ctx, proj, "freed-corp"), codes.AlreadyExists, "EntityAlreadyExists")
	now = now.Add(aliasClaimLease)
	wantAWS(t, e.api.CreateAccountAlias(ctx, proj, "kept-corp"), codes.AlreadyExists, "EntityAlreadyExists")
	if c := storedClaim(t, b, "kept-corp"); c.Object.Project != "owner-kept-corp" {
		t.Fatalf("claim of a held alias moved: %+v", c.Object)
	}
	aliasGone(t, b, proj, "kept-corp")
	if err := e.api.CreateAccountAlias(ctx, proj, "freed-corp"); err != nil {
		t.Fatalf("deleted alias after the lease: %v, want created", err)
	}
	storedAlias(t, b, proj, "freed-corp")
}

// TestCreateAccountAliasConcurrent: of creates of one alias racing on
// two replicas, from one project or from several, exactly one succeeds
// and the rest are EntityAlreadyExists, so a lost response retried is
// never a second alias, and only the winner holds it. On both store
// backends.
func TestCreateAccountAliasConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		for _, projects := range []int{1, 4} {
			t.Run(fmt.Sprintf("%s/%dprojects", bk.name, projects), func(t *testing.T) {
				b := bk.open()
				now := time.Now().UTC()
				replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
				pid := func(i int) string { return fmt.Sprintf("proj-%d", i%projects) }
				var wg sync.WaitGroup
				errs := make([]error, 16)
				for i := range errs {
					wg.Go(func() {
						errs[i] = replicas[i%2].api.CreateAccountAlias(t.Context(), pid(i), "example-corp")
					})
				}
				wg.Wait()
				winner := ""
				for i, err := range errs {
					if err == nil {
						if winner != "" {
							t.Fatalf("creates by %s and %s both succeeded, want exactly one", winner, pid(i))
						}
						winner = pid(i)
						continue
					}
					wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
				}
				if winner == "" {
					t.Fatal("no create succeeded, want exactly one")
				}
				for i := range projects {
					got := listedAliases(t, replicas[0], pid(i))
					if want := pid(i) == winner; want != slices.Equal(got, []string{"example-corp"}) || !want && len(got) != 0 {
						t.Fatalf("%s lists %q (winner %s)", pid(i), got, winner)
					}
				}
				if c := storedClaim(t, b, "example-corp"); c.Object.Project != winner {
					t.Fatalf("claim %+v, want held by %s", c.Object, winner)
				}
			})
		}
	}
}

// TestCreateAccountAliasConcurrentReplace: creates of different aliases
// racing in one project all succeed and exactly one alias stays. On both
// store backends.
func TestCreateAccountAliasConcurrentReplace(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			var wg sync.WaitGroup
			errs := make([]error, 12)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.CreateAccountAlias(t.Context(), proj, fmt.Sprintf("corp-%02d", i))
				})
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("create corp-%02d: %v, want success", i, err)
				}
			}
			if got := listedAliases(t, replicas[1], proj); len(got) != 1 {
				t.Fatalf("project lists %q, want exactly one alias", got)
			}
		})
	}
}

// TestCreateAccountAliasSkewedClock: a create on a replica whose clock is
// behind still replaces the alias an earlier create stored, as AWS
// overwrites the previous alias: the latest create wins, not the latest
// clock. On both store backends.
func TestCreateAccountAliasSkewedClock(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
			behind := now.Add(-time.Second)
			e, slow := newEnvOn(t, b, &now), newEnvOn(t, b, &behind)
			if err := e.api.CreateAccountAlias(t.Context(), proj, "zzz-corp"); err != nil {
				t.Fatal(err)
			}
			if err := slow.api.CreateAccountAlias(t.Context(), proj, "aaa-corp"); err != nil {
				t.Fatal(err)
			}
			if got := listedAliases(t, e, proj); !slices.Equal(got, []string{"aaa-corp"}) {
				t.Fatalf("project lists %q, want the later create aaa-corp", got)
			}
		})
	}
}

// TestCreateAccountAliasRepairs: a repeat of a create that stopped after
// storing its alias and before deleting the one it replaced deletes that
// one and is EntityAlreadyExists.
func TestCreateAccountAliasRepairs(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	sb := store.Scoped(b, proj)
	for i, n := range []string{"new-corp", "old-corp"} {
		a := iam.AccountAlias{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: n, Created: now, Seq: int64(2 - i)}
		if _, err := store.Create(t.Context(), sb, a); err != nil {
			t.Fatal(err)
		}
	}
	e := newEnvOn(t, b, &now)
	wantAWS(t, e.api.CreateAccountAlias(t.Context(), proj, "new-corp"), codes.AlreadyExists, "EntityAlreadyExists")
	if got := listedAliases(t, e, proj); !slices.Equal(got, []string{"new-corp"}) {
		t.Fatalf("project lists %q, want only new-corp", got)
	}
}

// TestCreateAccountAliasErrors: a bad project or AccountAlias is
// ValidationError before any store access, the AWS length and pattern
// bounds are accepted, and a store failure on any read or write is
// InternalFailure without backend detail, never success.
func TestCreateAccountAliasErrors(t *testing.T) {
	now := time.Now().UTC()
	ctx := t.Context()
	boom := errors.New("backend down")
	noAlias := failingGet{memstore.New(), iam.KindAccountAlias, boom}
	e := newEnvOn(t, failingGet{noAlias, iam.KindAccountAliasClaim, boom}, &now) // any store read fails
	bad := []string{
		"", "ab", strings.Repeat("a", iam.MaxAccountAliasLen+1),
		"ExampleCorp", "-abc", "abc-", "a--b", "a_b", "a.b", "a b", "ab\x00", "é12",
	}
	for _, n := range bad {
		wantAWS(t, e.api.CreateAccountAlias(ctx, proj, n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.CreateAccountAlias(ctx, "Bad_Project", "example-corp"), codes.InvalidArgument, "ValidationError")

	ok := newEnvOn(t, memstore.New(), &now)
	for _, n := range []string{"abc", "a-b", "0-9", "a-b-c-1", strings.Repeat("z", iam.MaxAccountAliasLen)} {
		if err := ok.api.CreateAccountAlias(ctx, "p-"+n[:3], n); err != nil {
			t.Fatalf("CreateAccountAlias(%q): %v, want created", n, err)
		}
	}

	for _, fail := range []func(store.Backend) store.Backend{
		func(m store.Backend) store.Backend { return failingGet{m, iam.KindAccountAlias, boom} },
		func(m store.Backend) store.Backend { return failingGet{m, iam.KindAccountAliasClaim, boom} },
		func(m store.Backend) store.Backend { return failingCreate{m, iam.KindAccountAliasClaim, boom} },
		func(m store.Backend) store.Backend { return failingCreate{m, iam.KindAccountAlias, boom} },
	} {
		m := memstore.New()
		err := newEnvOn(t, fail(m), &now).api.CreateAccountAlias(ctx, proj, "example-corp")
		wantAWS(t, err, codes.Internal, "InternalFailure")
		if strings.Contains(err.Error(), "backend down") {
			t.Fatalf("error %v leaks backend detail", err)
		}
		aliasGone(t, m, proj, "example-corp")
	}
}

// TestCreateAccountAliasCanceled: a request whose context is canceled
// writes neither a claim nor an alias.
func TestCreateAccountAliasCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := e.api.CreateAccountAlias(ctx, proj, "example-corp")
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
	aliasGone(t, b, proj, "example-corp")
	if _, err := store.Get[iam.AccountAliasClaim](t.Context(), b, "example-corp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claim after a canceled create: %v, want none", err)
	}
}

// conflictingClaim refuses every claim write with ErrConflict, as a
// claim that keeps changing would.
type conflictingClaim struct{ store.Backend }

func (c conflictingClaim) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	if k == iam.KindAccountAliasClaim {
		return "", store.ErrExists
	}
	return c.Backend.Create(ctx, k, key, spec)
}

// TestCreateAccountAliasContention: a claim that keeps changing is
// ConcurrentModification and no alias is written.
func TestCreateAccountAliasContention(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	err := newEnvOn(t, conflictingClaim{b}, &now).api.CreateAccountAlias(t.Context(), proj, "example-corp")
	wantAWS(t, err, codes.Aborted, "ConcurrentModification")
	aliasGone(t, b, proj, "example-corp")
}

// slowClaimRead delays every read of an account alias claim by delay and
// records the deadline of the alias write.
type slowClaimRead struct {
	store.Backend
	delay    time.Duration
	deadline time.Time
}

func (s *slowClaimRead) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	if k == iam.KindAccountAliasClaim {
		time.Sleep(s.delay)
	}
	return s.Backend.Get(ctx, k, key)
}

func (s *slowClaimRead) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	if k == iam.KindAccountAlias {
		s.deadline, _ = ctx.Deadline()
	}
	return s.Backend.Create(ctx, k, key, spec)
}

// TestCreateAccountAliasSlowClaimRead: a slow read of the project's own
// fresh claim shortens the alias write window, which still ends half a
// lease after the claim was written, measured from before the read.
func TestCreateAccountAliasSlowClaimRead(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	claimed := now.Add(-time.Second)
	if _, err := store.Create(t.Context(), b, iam.AccountAliasClaim{Name: "example-corp", Project: proj, Claimed: claimed}); err != nil {
		t.Fatal(err)
	}
	slow := &slowClaimRead{Backend: b, delay: 200 * time.Millisecond}
	e := newEnvOn(t, slow, &now)
	start := time.Now()
	if err := e.api.CreateAccountAlias(t.Context(), proj, "example-corp"); err != nil {
		t.Fatal(err)
	}
	// Half of grpcapi.aliasClaimLease (60s) after the claim, a second old,
	// with slack below the read delay.
	if latest := start.Add(29*time.Second + slow.delay/2); slow.deadline.After(latest) {
		t.Fatalf("alias write deadline %v after %v: the claim read extended it", slow.deadline, latest)
	}
}

// beforeWrite runs f once before the first create or update of kind k,
// as a replica racing the request would.
type beforeWrite struct {
	store.Backend
	k    iam.Kind
	once sync.Once
	f    func(ctx context.Context)
}

func (w *beforeWrite) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	if k == w.k {
		w.once.Do(func() { w.f(ctx) })
	}
	return w.Backend.Create(ctx, k, key, spec)
}

func (w *beforeWrite) Update(ctx context.Context, k iam.Kind, key string, spec []byte, version string) (string, error) {
	if k == w.k {
		w.once.Do(func() { w.f(ctx) })
	}
	return w.Backend.Update(ctx, k, key, spec, version)
}

// TestCreateAccountAliasClaimTakenDuringWrite: when another project
// takes the claim over while the alias is being written, the alias is
// deleted again and the create is EntityAlreadyExists, so the alias never
// stays with two projects.
func TestCreateAccountAliasClaimTakenDuringWrite(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	w := &beforeWrite{Backend: b, k: iam.KindAccountAlias, f: func(ctx context.Context) {
		if _, err := store.Mutate(ctx, b, "example-corp", func(c *iam.AccountAliasClaim) error {
			c.Project = "other"
			return nil
		}); err != nil {
			t.Error(err)
		}
	}}
	err := newEnvOn(t, w, &now).api.CreateAccountAlias(t.Context(), proj, "example-corp")
	wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
	aliasGone(t, b, proj, "example-corp")
}

// TestCreateAccountAliasTakeoverRace: when the project of a stale claim
// stores the alias while another project takes the claim over, the
// claim is handed back and the taker is EntityAlreadyExists with no
// alias.
func TestCreateAccountAliasTakeoverRace(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	stale := iam.AccountAliasClaim{Name: "example-corp", Project: proj, Claimed: now.Add(-aliasClaimLease)}
	if _, err := store.Create(t.Context(), b, stale); err != nil {
		t.Fatal(err)
	}
	w := &beforeWrite{Backend: b, k: iam.KindAccountAliasClaim, f: func(ctx context.Context) {
		a := iam.AccountAlias{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: "example-corp", Created: now, Seq: 1}
		if _, err := store.Create(ctx, store.Scoped(b, proj), a); err != nil {
			t.Error(err)
		}
	}}
	err := newEnvOn(t, w, &now).api.CreateAccountAlias(t.Context(), "other", "example-corp")
	wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
	aliasGone(t, b, "other", "example-corp")
	if c := storedClaim(t, b, "example-corp"); c.Object.Project != proj {
		t.Fatalf("claim %+v, want handed back to %s", c.Object, proj)
	}
	storedAlias(t, b, proj, "example-corp")
}
