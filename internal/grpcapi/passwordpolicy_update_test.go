package grpcapi_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func intp(v int) *int { return &v }

// wantRules fails unless got sets the same rules as want.
func wantRules(t *testing.T, got, want iam.PasswordPolicy) {
	t.Helper()
	got.Meta, want.Meta = iam.Meta{}, iam.Meta{}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stored policy %+v, want %+v", got, want)
	}
}

// fullPolicyInput is the AWS sample request of UpdateAccountPasswordPolicy.
var fullPolicyInput = grpcapi.PasswordPolicyInput{
	AllowUsersToChangePassword: true, MaxPasswordAge: intp(90), MinimumPasswordLength: intp(12),
	PasswordReusePrevention: intp(12), RequireLowercaseCharacters: true, RequireNumbers: true,
	RequireSymbols: true, RequireUppercaseCharacters: true,
}

// TestUpdateAccountPasswordPolicy: an account without a policy gets the
// requested one; a repeat from another replica succeeds and writes
// nothing; a later update without some parameters resets them to their
// AWS defaults (no partial update) and keeps the policy's UID; another
// project gets no policy. On both store backends.
func TestUpdateAccountPasswordPolicy(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			if err := e.api.UpdateAccountPasswordPolicy(ctx, proj, fullPolicyInput); err != nil {
				t.Fatal(err)
			}
			first := storedPasswordPolicy(t, b, proj)
			wantRules(t, first.Object, iam.PasswordPolicy{
				MinimumPasswordLength: 12, RequireSymbols: true, RequireNumbers: true,
				RequireUppercaseCharacters: true, RequireLowercaseCharacters: true,
				AllowUsersToChangePassword: true, MaxPasswordAge: 90, PasswordReusePrevention: 12,
			})
			if first.Object.UID == "" || first.Object.Generation != 1 || !first.Object.Updated.Equal(now) {
				t.Fatalf("created %+v, want a UID, generation 1, updated now", first.Object)
			}
			if err := other.api.UpdateAccountPasswordPolicy(ctx, proj, fullPolicyInput); err != nil {
				t.Fatalf("repeat: %v, want success", err)
			}
			if got := storedPasswordPolicy(t, b, proj); got.Version != first.Version {
				t.Fatalf("repeat wrote the policy: version %q, want %q", got.Version, first.Version)
			}

			in := grpcapi.PasswordPolicyInput{MinimumPasswordLength: intp(20), HardExpiry: true}
			if err := other.api.UpdateAccountPasswordPolicy(ctx, proj, in); err != nil {
				t.Fatal(err)
			}
			got := storedPasswordPolicy(t, b, proj)
			wantRules(t, got.Object, iam.PasswordPolicy{MinimumPasswordLength: 20, HardExpiry: true})
			if got.Object.UID != first.Object.UID || got.Object.Generation != 2 {
				t.Fatalf("updated %+v, want UID %s and generation 2", got.Object, first.Object.UID)
			}
			_, err := store.Get[iam.PasswordPolicy](ctx, store.Scoped(b, "other"), iam.PasswordPolicyKey)
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("another project's policy: %v, want none", err)
			}
		})
	}
}

// TestUpdateAccountPasswordPolicyDefaults: a request with no parameters
// stores the AWS defaults (minimum length 6, everything else off), also
// over a stricter policy.
func TestUpdateAccountPasswordPolicyDefaults(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	for range 2 {
		if err := e.api.UpdateAccountPasswordPolicy(t.Context(), proj, grpcapi.PasswordPolicyInput{}); err != nil {
			t.Fatal(err)
		}
		wantRules(t, storedPasswordPolicy(t, b, proj).Object, iam.PasswordPolicy{MinimumPasswordLength: 6})
		if err := e.api.UpdateAccountPasswordPolicy(t.Context(), proj, fullPolicyInput); err != nil {
			t.Fatal(err)
		}
	}
}

// TestUpdateAccountPasswordPolicyValidation: the AWS ranges are accepted
// at both ends; a value one past them, or an explicit 0 where AWS only
// gives the default when the parameter is omitted, is ValidationError
// naming the parameter, and so is a bad project; none of them touches the
// stored policy.
func TestUpdateAccountPasswordPolicyValidation(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	for _, in := range []grpcapi.PasswordPolicyInput{
		{MinimumPasswordLength: intp(6), MaxPasswordAge: intp(1), PasswordReusePrevention: intp(1)},
		{MinimumPasswordLength: intp(128), MaxPasswordAge: intp(1095), PasswordReusePrevention: intp(24)},
	} {
		if err := e.api.UpdateAccountPasswordPolicy(ctx, "edge", in); err != nil {
			t.Fatalf("in range %+v: %v", in, err)
		}
	}
	seedPasswordPolicy(t, b, proj)
	before := storedPasswordPolicy(t, b, proj)
	for _, tc := range []struct {
		in    grpcapi.PasswordPolicyInput
		param string
	}{
		{grpcapi.PasswordPolicyInput{MinimumPasswordLength: intp(5)}, "'minimumPasswordLength'"},
		{grpcapi.PasswordPolicyInput{MinimumPasswordLength: intp(129)}, "'minimumPasswordLength'"},
		{grpcapi.PasswordPolicyInput{MinimumPasswordLength: intp(0)}, "'minimumPasswordLength'"},
		{grpcapi.PasswordPolicyInput{MaxPasswordAge: intp(0)}, "'maxPasswordAge'"},
		{grpcapi.PasswordPolicyInput{MaxPasswordAge: intp(1096)}, "'maxPasswordAge'"},
		{grpcapi.PasswordPolicyInput{MaxPasswordAge: intp(-1)}, "'maxPasswordAge'"},
		{grpcapi.PasswordPolicyInput{PasswordReusePrevention: intp(0)}, "'passwordReusePrevention'"},
		{grpcapi.PasswordPolicyInput{PasswordReusePrevention: intp(25)}, "'passwordReusePrevention'"},
	} {
		err := e.api.UpdateAccountPasswordPolicy(ctx, proj, tc.in)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
		if !strings.Contains(err.Error(), tc.param) || !strings.Contains(err.Error(), "failed to satisfy constraint") {
			t.Fatalf("%+v: message %q, want the AWS constraint message naming %s", tc.in, err, tc.param)
		}
	}
	for _, pid := range []string{"", "Bad_Project", "a/b", "proj\x00"} {
		wantAWS(t, e.api.UpdateAccountPasswordPolicy(ctx, pid, fullPolicyInput), codes.InvalidArgument, "ValidationError")
	}
	if got := storedPasswordPolicy(t, b, proj); got.Version != before.Version {
		t.Fatalf("a refused request wrote the policy: version %q, want %q", got.Version, before.Version)
	}
}

// failingUpdate fails every Update of kind k with err.
type failingUpdate struct {
	store.Backend
	k   iam.Kind
	err error
}

func (f failingUpdate) Update(ctx context.Context, k iam.Kind, key string, spec []byte, version string) (string, error) {
	if k == f.k {
		return "", f.err
	}
	return f.Backend.Update(ctx, k, key, spec, version)
}

// TestUpdateAccountPasswordPolicyErrors: a store failure on the read,
// the create or the update is InternalFailure without backend detail,
// never success, and leaves the stored policy as it was.
func TestUpdateAccountPasswordPolicyErrors(t *testing.T) {
	now := time.Now().UTC()
	boom := errors.New("backend down")
	for _, tc := range []struct {
		name string
		fail func(store.Backend) store.Backend
		seed bool
	}{
		{"get", func(m store.Backend) store.Backend { return failingGet{m, iam.KindPasswordPolicy, boom} }, true},
		{"create", func(m store.Backend) store.Backend { return failingCreate{m, iam.KindPasswordPolicy, boom} }, false},
		{"update", func(m store.Backend) store.Backend { return failingUpdate{m, iam.KindPasswordPolicy, boom} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := memstore.New()
			if tc.seed {
				seedPasswordPolicy(t, m, proj)
			}
			err := newEnvOn(t, tc.fail(m), &now).api.UpdateAccountPasswordPolicy(t.Context(), proj, fullPolicyInput)
			wantAWS(t, err, codes.Internal, "InternalFailure")
			if strings.Contains(err.Error(), "backend down") {
				t.Fatalf("error %v leaks backend detail", err)
			}
			if !tc.seed {
				passwordPolicyGone(t, m, proj)
				return
			}
			wantRules(t, storedPasswordPolicy(t, m, proj).Object, iam.PasswordPolicy{
				MinimumPasswordLength: 12, RequireSymbols: true, MaxPasswordAge: 90,
			})
		})
	}
}

// TestUpdateAccountPasswordPolicyCanceled: a canceled request neither
// creates nor changes the policy.
func TestUpdateAccountPasswordPolicyCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.api.UpdateAccountPasswordPolicy(ctx, proj, fullPolicyInput); status.Code(err) != codes.Canceled {
		t.Fatalf("canceled create: %v, want Canceled", err)
	}
	passwordPolicyGone(t, b, proj)
	seedPasswordPolicy(t, b, proj)
	before := storedPasswordPolicy(t, b, proj)
	if err := e.api.UpdateAccountPasswordPolicy(ctx, proj, fullPolicyInput); status.Code(err) != codes.Canceled {
		t.Fatalf("canceled update: %v, want Canceled", err)
	}
	if got := storedPasswordPolicy(t, b, proj); got.Version != before.Version {
		t.Fatalf("canceled request wrote the policy: version %q, want %q", got.Version, before.Version)
	}
}

// TestUpdateAccountPasswordPolicyConcurrent: the same request racing on
// two replicas against an account without a policy always succeeds and
// is written once (a lost create is read again, not an error); different
// requests racing leave exactly one of them stored. On both store
// backends.
func TestUpdateAccountPasswordPolicyConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			var wg sync.WaitGroup
			errs := make([]error, 16)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.UpdateAccountPasswordPolicy(t.Context(), proj, fullPolicyInput)
				})
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatalf("racing identical update: %v, want success", err)
				}
			}
			if got := storedPasswordPolicy(t, b, proj); got.Object.Generation != 1 {
				t.Fatalf("identical updates wrote generation %d, want one write", got.Object.Generation)
			}

			for i := range errs {
				wg.Go(func() {
					in := grpcapi.PasswordPolicyInput{MinimumPasswordLength: intp(8 + i)}
					errs[i] = replicas[i%2].api.UpdateAccountPasswordPolicy(t.Context(), proj, in)
				})
			}
			wg.Wait()
			got := storedPasswordPolicy(t, b, proj).Object.MinimumPasswordLength
			ok := false
			for i, err := range errs {
				if err != nil {
					wantAWS(t, err, codes.Aborted, "ConcurrentModification")
					continue
				}
				ok = ok || got == 8+i
			}
			if !ok {
				t.Fatalf("stored minimum length %d is no successful request's", got)
			}
		})
	}
}

// changingPolicyBeforeWrite writes the password policy before each of
// the first n creates or updates of it, as a concurrent request between
// the read and the write would.
type changingPolicyBeforeWrite struct {
	store.Backend
	mu sync.Mutex
	n  int
	t  *testing.T
}

func (c *changingPolicyBeforeWrite) interfere(ctx context.Context, k iam.Kind) {
	if k != iam.KindPasswordPolicy {
		return
	}
	c.mu.Lock()
	change := c.n > 0
	c.n--
	c.mu.Unlock()
	if !change {
		return
	}
	b := store.Scoped(c.Backend, proj)
	_, err := store.Mutate(ctx, b, iam.PasswordPolicyKey, func(p *iam.PasswordPolicy) error {
		p.MinimumPasswordLength++
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		p := iam.PasswordPolicy{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, MinimumPasswordLength: 7}
		_, err = store.Create(ctx, b, p)
	}
	if err != nil {
		c.t.Error(err)
	}
}

func (c *changingPolicyBeforeWrite) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	c.interfere(ctx, k)
	return c.Backend.Create(ctx, k, key, spec)
}

func (c *changingPolicyBeforeWrite) Update(ctx context.Context, k iam.Kind, key string, spec []byte, version string) (string, error) {
	c.interfere(ctx, k)
	return c.Backend.Update(ctx, k, key, spec, version)
}

// TestUpdateAccountPasswordPolicyStaleRead: a policy created or changed
// after it was read is read again and then written, never overwritten
// blind at a stale version; one that keeps changing is
// ConcurrentModification and keeps the other writer's policy. On both
// store backends.
func TestUpdateAccountPasswordPolicyStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			b := &changingPolicyBeforeWrite{Backend: inner, n: 2, t: t}
			if err := newEnvOn(t, b, &now).api.UpdateAccountPasswordPolicy(t.Context(), proj, fullPolicyInput); err != nil {
				t.Fatalf("update after a concurrent create and write: %v, want success", err)
			}
			got := storedPasswordPolicy(t, inner, proj).Object
			wantRules(t, got, iam.PasswordPolicy{
				MinimumPasswordLength: 12, RequireSymbols: true, RequireNumbers: true,
				RequireUppercaseCharacters: true, RequireLowercaseCharacters: true,
				AllowUsersToChangePassword: true, MaxPasswordAge: 90, PasswordReusePrevention: 12,
			})
			if b.n > 0 || got.Generation != 2 {
				t.Fatalf("%d interferences left, generation %d; want both done and this update on the other writer's create", b.n, got.Generation)
			}

			b = &changingPolicyBeforeWrite{Backend: inner, n: 1 << 30, t: t}
			in := grpcapi.PasswordPolicyInput{MinimumPasswordLength: intp(100)}
			err := newEnvOn(t, b, &now).api.UpdateAccountPasswordPolicy(t.Context(), proj, in)
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			if got := storedPasswordPolicy(t, inner, proj).Object; got.MinimumPasswordLength == 100 {
				t.Fatalf("stored %+v, want the other writer's policy", got)
			}
		})
	}
}
