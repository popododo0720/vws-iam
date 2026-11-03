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

const alias = "example-corp"

// listedAliases returns the aliases ListAccountAliases lists for pid.
func listedAliases(t *testing.T, e *env, pid string) []string {
	t.Helper()
	pg, err := e.api.ListAccountAliases(t.Context(), pid, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return pg.Aliases
}

// wantHolder fails unless the claim of name names pid and, of projects
// pids, exactly pid lists name.
func wantHolder(t *testing.T, e *env, b store.Backend, name, pid string, pids ...string) {
	t.Helper()
	c, err := store.Get[iam.AccountAliasClaim](t.Context(), b, name)
	if err != nil || c.Object.Project != pid {
		t.Fatalf("claim of %s: %+v, %v, want held by %s", name, c.Object, err, pid)
	}
	for _, p := range pids {
		if got := listedAliases(t, e, p); slices.Contains(got, name) != (p == pid) {
			t.Fatalf("%s lists %q; only %s should list %s", p, got, pid, name)
		}
	}
}

// stepStore calls at before every Get, List, Create, Update, Delete and
// DeleteIf, so a
// test can run another request at an exact step or fail the step.
type stepStore struct {
	store.Backend
	at func(op string, k iam.Kind, key string) error
}

func (s stepStore) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	if err := s.at("get", k, key); err != nil {
		return store.Entry{}, err
	}
	return s.Backend.Get(ctx, k, key)
}

func (s stepStore) List(ctx context.Context, k iam.Kind) ([]store.Entry, error) {
	if err := s.at("list", k, ""); err != nil {
		return nil, err
	}
	return s.Backend.List(ctx, k)
}

func (s stepStore) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if err := s.at("delete", k, key); err != nil {
		return err
	}
	return s.Backend.Delete(ctx, k, key, version)
}

func (s stepStore) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	if err := s.at("create", k, key); err != nil {
		return "", err
	}
	return s.Backend.Create(ctx, k, key, spec)
}

func (s stepStore) Update(ctx context.Context, k iam.Kind, key string, spec []byte, version string) (string, error) {
	if err := s.at("update", k, key); err != nil {
		return "", err
	}
	return s.Backend.Update(ctx, k, key, spec, version)
}

func (s stepStore) DeleteIf(ctx context.Context, k iam.Kind, key, version string, pre store.Pre) error {
	if err := s.at("deleteIf", k, key); err != nil {
		return err
	}
	return s.Backend.DeleteIf(ctx, k, key, version, pre)
}

// TestCreateAccountAlias: the alias is stored with the request time and
// claimed for the project, every replica lists it, a repeat is
// EntityAlreadyExists and keeps the alias, and another project creating
// it is EntityAlreadyExists, keeps its own alias and stores none. On both
// store backends.
func TestCreateAccountAlias(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			for pid, name := range map[string]string{proj: "example-corporation", "other": "other-corp"} {
				if err := e.api.CreateAccountAlias(ctx, pid, name); err != nil {
					t.Fatal(err)
				}
			}
			a := storedAlias(t, b, proj, "example-corporation")
			if a.Object.UID == "" || a.Object.Generation != 1 || !a.Object.Created.Equal(now) {
				t.Fatalf("stored %+v, want a UID, generation 1, created now", a.Object)
			}
			wantHolder(t, other, b, "example-corporation", proj, proj, "other")
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
			aliasGone(t, b, "other", "example-corporation")
			if got := listedAliases(t, e, "other"); !slices.Equal(got, []string{"other-corp"}) {
				t.Fatalf("other lists %q, want its own alias kept", got)
			}
		})
	}
}

// TestCreateAccountAliasReplaces: a second alias overwrites the first,
// as in AWS, so the project lists only the new one and LimitExceeded
// never applies, also from a replica whose clock is behind (the latest
// create wins, not the latest clock), and a replaced or deleted alias is
// free for any project at once, while a held one is never taken. On both
// store backends.
func TestCreateAccountAliasReplaces(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
			behind := now.Add(-time.Second)
			e, slow := newEnvOn(t, b, &now), newEnvOn(t, b, &behind)
			ctx := t.Context()
			for i, name := range []string{"zzz-corp", "second-corp", "first-corp"} {
				if err := []*env{e, e, slow}[i].api.CreateAccountAlias(ctx, proj, name); err != nil {
					t.Fatalf("create %s: %v", name, err)
				}
				if got := listedAliases(t, e, proj); !slices.Equal(got, []string{name}) {
					t.Fatalf("after creating %s the project lists %q, want only it", name, got)
				}
			}
			aliasGone(t, b, proj, "zzz-corp")
			if err := e.api.CreateAccountAlias(ctx, "other", "zzz-corp"); err != nil {
				t.Fatalf("a replaced alias for another project: %v, want created", err)
			}
			wantHolder(t, e, b, "zzz-corp", "other", proj, "other")
			wantAWS(t, e.api.CreateAccountAlias(ctx, "other", "first-corp"), codes.AlreadyExists, "EntityAlreadyExists")
			if err := e.api.CreateAccountAlias(ctx, proj, "second-corp"); err != nil {
				t.Fatalf("taking back the project's own old alias: %v", err)
			}
			if err := e.api.DeleteAccountAlias(ctx, proj, "second-corp"); err != nil {
				t.Fatal(err)
			}
			if err := e.api.CreateAccountAlias(ctx, "other", "second-corp"); err != nil {
				t.Fatalf("a deleted alias for another project: %v, want created", err)
			}
			wantHolder(t, e, b, "second-corp", "other", proj, "other")
		})
	}
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
					wg.Go(func() { errs[i] = replicas[i%2].api.CreateAccountAlias(t.Context(), pid(i), alias) })
				}
				wg.Wait()
				winner := ""
				var pids []string
				for i, err := range errs {
					pids = append(pids, pid(i))
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
				wantHolder(t, replicas[0], b, alias, winner, pids...)
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

// TestCreateAccountAliasTakeoverRace: a project re-creating its freed
// alias races another project taking the claim over, at the two orders
// that matter: the takeover swap commits before the re-create's own
// claim write, or after it. Exactly one project wins and holds the alias;
// the other is EntityAlreadyExists and stores none. On both store
// backends.
func TestCreateAccountAliasTakeoverRace(t *testing.T) {
	for _, bk := range renameBackends {
		for _, swapFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/swapFirst=%v", bk.name, swapFirst), func(t *testing.T) {
				b := bk.open()
				now := time.Now().UTC()
				ctx := t.Context()
				e := newEnvOn(t, b, &now)
				seedAlias(t, b, proj, alias)
				if err := e.api.DeleteAccountAlias(ctx, proj, alias); err != nil {
					t.Fatal(err)
				}
				// other reads the claim (proj) and finds no alias of proj,
				// then stops before its swap.
				paused, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				taker := newEnvOn(t, stepStore{b, func(op string, k iam.Kind, _ string) error {
					if op == "update" && k == iam.KindAccountAliasClaim {
						once.Do(func() { close(paused); <-release })
					}
					return nil
				}}, &now)
				done := make(chan error, 1)
				go func() { done <- taker.api.CreateAccountAlias(ctx, "other", alias) }()
				<-paused
				var otherErr error
				otherDone := false
				creator := e
				if swapFirst {
					// proj stores its alias and reads the claim; the swap
					// commits before proj's claim write.
					creator = newEnvOn(t, stepStore{b, func(op string, k iam.Kind, _ string) error {
						if op == "update" && k == iam.KindAccountAliasClaim && !otherDone {
							otherDone = true
							close(release)
							otherErr = <-done
						}
						return nil
					}}, &now)
				}
				projErr := creator.api.CreateAccountAlias(ctx, proj, alias)
				if !otherDone {
					close(release)
					otherErr = <-done
				}
				winner, loser, winErr, lostErr := proj, "other", projErr, otherErr
				if swapFirst {
					winner, loser, winErr, lostErr = loser, winner, lostErr, winErr
				}
				if winErr != nil {
					t.Fatalf("winner %s: %v, want success", winner, winErr)
				}
				wantAWS(t, lostErr, codes.AlreadyExists, "EntityAlreadyExists")
				wantHolder(t, e, b, alias, winner, proj, "other")
				aliasGone(t, b, loser, alias)
			})
		}
	}
}

// TestCreateAccountAliasRetryDuringCreate: a retry that runs while the
// first request of a new alias is between storing the alias and reading
// the claim claims it, so it succeeds and replaces the old alias; the
// first request's failing claim read then deletes nothing, so the project
// keeps exactly the new alias.
func TestCreateAccountAliasRetryDuringCreate(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	ctx := t.Context()
	e := newEnvOn(t, b, &now)
	if err := e.api.CreateAccountAlias(ctx, proj, "old-corp"); err != nil {
		t.Fatal(err)
	}
	var retryErr error
	first := newEnvOn(t, stepStore{b, func(op string, k iam.Kind, _ string) error {
		if op == "get" && k == iam.KindAccountAliasClaim {
			retryErr = e.api.CreateAccountAlias(ctx, proj, "new-corp")
			return errors.New("backend down")
		}
		return nil
	}}, &now)
	wantAWS(t, first.api.CreateAccountAlias(ctx, proj, "new-corp"), codes.Internal, "InternalFailure")
	if retryErr != nil {
		t.Fatalf("retry: %v, want success", retryErr)
	}
	if got := listedAliases(t, e, proj); !slices.Equal(got, []string{"new-corp"}) {
		t.Fatalf("project lists %q, want exactly new-corp", got)
	}
	aliasGone(t, b, proj, "old-corp")
}

// lostCreate stores every alias create, then reports ErrUnavailable, as a
// write whose response is lost.
type lostCreate struct{ store.Backend }

func (l lostCreate) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	v, err := l.Backend.Create(ctx, k, key, spec)
	if err == nil && k == iam.KindAccountAlias {
		return "", store.ErrUnavailable
	}
	return v, err
}

// TestCreateAccountAliasUnknownOutcome: an alias write whose response is
// lost is resolved by reading the alias back: retried by the store, it is
// this request's and the create succeeds; failed, the alias is stored
// but unclaimed, so no project lists it, another project may take the
// alias, and the retry is then EntityAlreadyExists and deletes the
// leftover. An alias stored under a claim another project holds is never
// listed or deletable and a create of it deletes it.
func TestCreateAccountAliasUnknownOutcome(t *testing.T) {
	now := time.Now().UTC()
	ctx := t.Context()
	b := memstore.New()
	retrying := newEnvOn(t, store.WithRetry(lostCreate{b}, 2, 0), &now)
	if err := retrying.api.CreateAccountAlias(ctx, proj, alias); err != nil {
		t.Fatalf("create retried after a lost response: %v, want success", err)
	}
	e := newEnvOn(t, b, &now)
	wantHolder(t, e, b, alias, proj, proj)

	b = memstore.New()
	e = newEnvOn(t, b, &now)
	lost := newEnvOn(t, lostCreate{b}, &now)
	if err := lost.api.CreateAccountAlias(ctx, proj, alias); status.Code(err) != codes.Unavailable {
		t.Fatalf("create with a lost response: %v, want Unavailable", err)
	}
	storedAlias(t, b, proj, alias)
	if got := listedAliases(t, e, proj); len(got) != 0 {
		t.Fatalf("an unclaimed alias is listed: %q", got)
	}
	if err := e.api.CreateAccountAlias(ctx, "other", alias); err != nil {
		t.Fatalf("an alias stored but never claimed: %v, want created for another project", err)
	}
	wantAWS(t, e.api.DeleteAccountAlias(ctx, proj, alias), codes.NotFound, "NoSuchEntity")
	wantAWS(t, e.api.CreateAccountAlias(ctx, proj, alias), codes.AlreadyExists, "EntityAlreadyExists")
	aliasGone(t, b, proj, alias)
	wantHolder(t, e, b, alias, "other", proj, "other")
}

// TestCreateAccountAliasRepairs: a repeat of a create that stored its
// alias but stopped before the claim claims it, succeeds and deletes the
// alias it replaced; a repeat of a claimed alias that stopped before
// deleting the old one deletes it and is EntityAlreadyExists.
func TestCreateAccountAliasRepairs(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedAlias(t, b, proj, "old-corp")
	a := iam.AccountAlias{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: "new-corp", Created: now, Seq: 1}
	e := newEnvOn(t, b, &now)
	if _, err := store.Create(t.Context(), store.Scoped(b, proj), a); err != nil {
		t.Fatal(err)
	}
	if err := e.api.CreateAccountAlias(t.Context(), proj, "new-corp"); err != nil {
		t.Fatalf("repeat of an unclaimed alias: %v, want success", err)
	}
	if got := listedAliases(t, e, proj); !slices.Equal(got, []string{"new-corp"}) {
		t.Fatalf("project lists %q, want only new-corp", got)
	}
	aliasGone(t, b, proj, "old-corp")
	seedAlias(t, b, proj, "zzz-corp") // Seq 0: before new-corp
	wantAWS(t, e.api.CreateAccountAlias(t.Context(), proj, "new-corp"), codes.AlreadyExists, "EntityAlreadyExists")
	aliasGone(t, b, proj, "zzz-corp")
}

// TestCreateAccountAliasErrors: a bad project or AccountAlias is
// ValidationError before any store access, the AWS length and pattern
// bounds are accepted, and a store failure on any read or write is
// InternalFailure without backend detail and lists no alias.
func TestCreateAccountAliasErrors(t *testing.T) {
	now := time.Now().UTC()
	ctx := t.Context()
	boom := errors.New("backend down")
	e := newEnvOn(t, stepStore{memstore.New(), func(string, iam.Kind, string) error { return boom }}, &now)
	bad := []string{
		"", "ab", strings.Repeat("a", iam.MaxAccountAliasLen+1),
		"ExampleCorp", "-abc", "abc-", "a--b", "a_b", "a.b", "a b", "ab\x00", "é12",
	}
	for _, n := range bad {
		wantAWS(t, e.api.CreateAccountAlias(ctx, proj, n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.CreateAccountAlias(ctx, "Bad_Project", alias), codes.InvalidArgument, "ValidationError")

	ok := newEnvOn(t, memstore.New(), &now)
	for _, n := range []string{"abc", "a-b", "0-9", "a-b-c-1", strings.Repeat("z", iam.MaxAccountAliasLen)} {
		if err := ok.api.CreateAccountAlias(ctx, "p-"+n[:3], n); err != nil {
			t.Fatalf("CreateAccountAlias(%q): %v, want created", n, err)
		}
	}

	for _, op := range []string{"get", "create", "update", "deleteIf"} {
		for _, k := range []iam.Kind{iam.KindAccountAlias, iam.KindAccountAliasClaim} {
			m := memstore.New()
			seedAlias(t, m, proj, "old-corp")
			seedAlias(t, m, "other", "taken-corp")
			fail := newEnvOn(t, stepStore{m, func(o string, kk iam.Kind, _ string) error {
				if o == op && kk == k {
					return boom
				}
				return nil
			}}, &now)
			// A new alias, one another project holds, and a repeat.
			for _, name := range []string{alias, "taken-corp", "old-corp"} {
				err := fail.api.CreateAccountAlias(ctx, proj, name)
				if err == nil || status.Code(err) == codes.AlreadyExists {
					continue // this create never reaches the failing step
				}
				wantAWS(t, err, codes.Internal, "InternalFailure")
				if strings.Contains(err.Error(), "backend down") {
					t.Fatalf("error %v leaks backend detail", err)
				}
			}
			if got := listedAliases(t, newEnvOn(t, m, &now), proj); len(got) != 1 {
				t.Fatalf("%s %s failing: project lists %q, want exactly one alias", op, k, got)
			}
		}
	}
}

// TestCreateAccountAliasDropFails: a create whose drop of the replaced
// alias fails (its List, claim read or Delete) is InternalFailure, never
// a success that leaves two aliases, and its repeat on a healthy store
// leaves exactly the new alias.
func TestCreateAccountAliasDropFails(t *testing.T) {
	now := time.Now().UTC()
	boom := errors.New("backend down")
	for _, tc := range []struct {
		op string
		k  iam.Kind
		n  int // the failing call of op on k, 1-based
	}{
		{"list", iam.KindAccountAlias, 2},
		{"get", iam.KindAccountAliasClaim, 3},
		{"delete", iam.KindAccountAlias, 1},
	} {
		t.Run(tc.op, func(t *testing.T) {
			m := memstore.New()
			seedAlias(t, m, proj, "old-corp")
			calls := 0
			fail := newEnvOn(t, stepStore{m, func(o string, k iam.Kind, _ string) error {
				if o == tc.op && k == tc.k {
					if calls++; calls == tc.n {
						return boom
					}
				}
				return nil
			}}, &now)
			wantAWS(t, fail.api.CreateAccountAlias(t.Context(), proj, "new-corp"), codes.Internal, "InternalFailure")
			e := newEnvOn(t, m, &now)
			wantAWS(t, e.api.CreateAccountAlias(t.Context(), proj, "new-corp"), codes.AlreadyExists, "EntityAlreadyExists")
			if got := listedAliases(t, e, proj); !slices.Equal(got, []string{"new-corp"}) {
				t.Fatalf("after the repeat the project lists %q, want only new-corp", got)
			}
			aliasGone(t, m, proj, "old-corp")
		})
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
	err := e.api.CreateAccountAlias(ctx, proj, alias)
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
	aliasGone(t, b, proj, alias)
	if _, err := store.Get[iam.AccountAliasClaim](t.Context(), b, alias); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("claim after a canceled create: %v, want none", err)
	}
}

// TestCreateAccountAliasContention: a claim that keeps changing is
// ConcurrentModification and no alias is listed.
func TestCreateAccountAliasContention(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	busy := stepStore{b, func(op string, k iam.Kind, _ string) error {
		if op == "create" && k == iam.KindAccountAliasClaim {
			return store.ErrExists
		}
		return nil
	}}
	err := newEnvOn(t, busy, &now).api.CreateAccountAlias(t.Context(), proj, alias)
	wantAWS(t, err, codes.Aborted, "ConcurrentModification")
	if got := listedAliases(t, newEnvOn(t, b, &now), proj); len(got) != 0 {
		t.Fatalf("project lists %q, want none", got)
	}
}
