package grpcapi_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestGetAccountPasswordPolicy: an account without a custom policy is
// NoSuchEntity naming the account; after an update every field reads
// back in the AWS shape, ExpirePasswords derived from MaxPasswordAge; a
// repeat from another replica returns the same policy and writes nothing;
// unset MaxPasswordAge and PasswordReusePrevention are left out; another
// project's policy is never returned; after a delete it is NoSuchEntity
// again. On both store backends.
func TestGetAccountPasswordPolicy(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
			e, other := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
			ctx := t.Context()
			_, err := e.api.GetAccountPasswordPolicy(ctx, proj)
			wantNoPasswordPolicy(t, err, proj)

			if err := e.api.UpdateAccountPasswordPolicy(ctx, proj, fullPolicyInput); err != nil {
				t.Fatal(err)
			}
			before := storedPasswordPolicy(t, b, proj)
			want := grpcapi.AccountPasswordPolicy{
				MinimumPasswordLength: 12, RequireSymbols: true, RequireNumbers: true,
				RequireUppercaseCharacters: true, RequireLowercaseCharacters: true,
				AllowUsersToChangePassword: true, ExpirePasswords: true,
				MaxPasswordAge: intp(90), PasswordReusePrevention: intp(12),
			}
			for _, api := range []*env{e, other} {
				got, err := api.api.GetAccountPasswordPolicy(ctx, proj)
				if err != nil {
					t.Fatal(err)
				}
				wantPolicyOut(t, got, want)
			}
			if got := storedPasswordPolicy(t, b, proj); got.Version != before.Version {
				t.Fatalf("get wrote the policy: version %q, want %q", got.Version, before.Version)
			}
			_, err = e.api.GetAccountPasswordPolicy(ctx, "other")
			wantNoPasswordPolicy(t, err, "other")

			in := grpcapi.PasswordPolicyInput{MinimumPasswordLength: intp(20), HardExpiry: true}
			if err := e.api.UpdateAccountPasswordPolicy(ctx, proj, in); err != nil {
				t.Fatal(err)
			}
			got, err := other.api.GetAccountPasswordPolicy(ctx, proj)
			if err != nil {
				t.Fatal(err)
			}
			wantPolicyOut(t, got, grpcapi.AccountPasswordPolicy{MinimumPasswordLength: 20, HardExpiry: true})

			if err := e.api.DeleteAccountPasswordPolicy(ctx, proj); err != nil {
				t.Fatal(err)
			}
			_, err = other.api.GetAccountPasswordPolicy(ctx, proj)
			wantNoPasswordPolicy(t, err, proj)
		})
	}
}

// TestGetAccountPasswordPolicyExpiry: ExpirePasswords is true exactly when
// MaxPasswordAge is above 0, at both ends of the AWS range.
func TestGetAccountPasswordPolicyExpiry(t *testing.T) {
	for _, age := range []int{1, iam.MaxPasswordAgeDays} {
		b := memstore.New()
		now := time.Now().UTC()
		e := newEnvOn(t, b, &now)
		in := grpcapi.PasswordPolicyInput{MaxPasswordAge: intp(age), PasswordReusePrevention: intp(1)}
		if err := e.api.UpdateAccountPasswordPolicy(t.Context(), proj, in); err != nil {
			t.Fatal(err)
		}
		got, err := e.api.GetAccountPasswordPolicy(t.Context(), proj)
		if err != nil {
			t.Fatal(err)
		}
		wantPolicyOut(t, got, grpcapi.AccountPasswordPolicy{
			MinimumPasswordLength: iam.MinPasswordLength, ExpirePasswords: true,
			MaxPasswordAge: intp(age), PasswordReusePrevention: intp(1),
		})
	}
}

// TestGetAccountPasswordPolicyErrors: a bad project is ValidationError
// before any store access, and a store failure is InternalFailure without
// backend detail.
func TestGetAccountPasswordPolicyErrors(t *testing.T) {
	boom := errors.New("backend down")
	m := memstore.New()
	now := time.Now().UTC()
	seedPasswordPolicy(t, m, proj)
	e := newEnvOn(t, failingGet{m, iam.KindPasswordPolicy, boom}, &now)
	for _, pid := range []string{"", "Bad_Project", "a/b", "proj\x00"} {
		_, err := e.api.GetAccountPasswordPolicy(t.Context(), pid)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
		if strings.Contains(err.Error(), "backend down") {
			t.Fatalf("project %q reached the store: %v", pid, err)
		}
	}
	_, err := e.api.GetAccountPasswordPolicy(t.Context(), proj)
	wantAWS(t, err, codes.Internal, "InternalFailure")
	if strings.Contains(err.Error(), "backend down") {
		t.Fatalf("error %v leaks backend detail", err)
	}
}

// TestGetAccountPasswordPolicyCanceled: a request whose context is
// canceled is Canceled, not a policy or NoSuchEntity.
func TestGetAccountPasswordPolicyCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedPasswordPolicy(t, b, proj)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := e.api.GetAccountPasswordPolicy(ctx, proj)
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request: %v, want Canceled", err)
	}
}

// wantNoPasswordPolicy fails unless err is the AWS NoSuchEntity of an
// account pid without a custom password policy.
func wantNoPasswordPolicy(t *testing.T, err error, pid string) {
	t.Helper()
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	want := "The Password Policy with domain name " + pid + " cannot be found."
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("NoSuchEntity message %q, want %q", err, want)
	}
}

// wantPolicyOut fails unless got is want, comparing integer values.
func wantPolicyOut(t *testing.T, got, want grpcapi.AccountPasswordPolicy) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policy %s, want %s", fmtPolicyOut(got), fmtPolicyOut(want))
	}
}

// fmtPolicyOut prints p with its integer pointers dereferenced.
func fmtPolicyOut(p grpcapi.AccountPasswordPolicy) string {
	v := func(n *int) string {
		if n == nil {
			return "unset"
		}
		return strconv.Itoa(*n)
	}
	q := p
	q.MaxPasswordAge, q.PasswordReusePrevention = nil, nil
	return fmt.Sprintf("%+v MaxPasswordAge:%s PasswordReusePrevention:%s",
		q, v(p.MaxPasswordAge), v(p.PasswordReusePrevention))
}
