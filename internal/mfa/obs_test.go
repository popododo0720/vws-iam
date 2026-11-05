package mfa_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/mfa"
	"github.com/popododo0720/vws-iam/internal/store"
)

var (
	reader = sdkmetric.NewManualReader()
	spans  = tracetest.NewSpanRecorder()
)

// TestMain installs the global providers once: instruments made at package
// init delegate to the first ones set.
func TestMain(m *testing.M) {
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)))
	os.Exit(m.Run())
}

// counts sums the counter name by its attribute set.
func counts(t *testing.T, name string) map[attribute.Distinct]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[attribute.Distinct]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T, want a counter", name, m.Data)
			}
			for _, dp := range sum.DataPoints {
				for _, kv := range dp.Attributes.ToSlice() {
					if k := string(kv.Key); k != "op" && k != "result" && k != "event" {
						t.Errorf("%s carries label %q", name, k)
					}
				}
				out[dp.Attributes.Equivalent()] += dp.Value
			}
		}
	}
	return out
}

func labels(kv ...string) attribute.Distinct {
	var a []attribute.KeyValue
	for i := 0; i < len(kv); i += 2 {
		a = append(a, attribute.String(kv[i], kv[i+1]))
	}
	set := attribute.NewSet(a...)
	return set.Equivalent()
}

// delta is what each attribute set gained between before and after.
func delta(before, after map[attribute.Distinct]int64) map[attribute.Distinct]int64 {
	d := map[attribute.Distinct]int64{}
	for k, v := range after {
		if v != before[k] {
			d[k] = v - before[k]
		}
	}
	return d
}

func wantCounts(t *testing.T, what string, got, want map[attribute.Distinct]int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s counted %d label sets, want %d: %v", what, len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s %v = %d, want %d", what, k, got[k], v)
		}
	}
}

// wrongCode is a six-digit code that is not valid around at.
func wrongCode(seed []byte, at time.Time) string {
	return code(seed, at, 7)
}

func TestOperationsAreMeasuredAndTraced(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	spans.Reset()
	before := counts(t, "vws.iam.mfa.operations")

	e, err := svc.CreateVirtual(ctx, "alice-phone", "")
	if err != nil {
		t.Fatal(err)
	}
	seed := seedOf(t, e)
	c1, c2 := code(seed, clk.t, -1), code(seed, clk.t, 0)
	if err := svc.Enable(ctx, "alice", "alice-phone", c1, c2); err != nil {
		t.Fatal(err)
	}
	clk.t = clk.t.Add(time.Minute)
	good, bad := code(seed, clk.t, 0), wrongCode(seed, clk.t)
	if err := svc.Verify(ctx, "alice", "alice-phone", bad); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := svc.VerifySerial(ctx, "alice", e.SerialNumber, good); err != nil {
		t.Fatal(err)
	}
	if err := svc.Verify(ctx, "alice", "nope", good); !errors.Is(err, mfa.ErrNotAssociated) {
		t.Fatalf("unknown device: %v", err)
	}
	if ok, err := svc.Required(ctx, "alice"); err != nil || !ok {
		t.Fatalf("required: %v %v", ok, err)
	}
	if err := svc.Delete(ctx, "alice-phone"); !errors.Is(err, mfa.ErrEntityInUse) {
		t.Fatalf("delete enabled device: %v", err)
	}
	if err := svc.Deactivate(ctx, "alice", "alice-phone"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, "alice-phone"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.List(ctx, ""); err != nil {
		t.Fatal(err)
	}

	wantCounts(t, "operations", delta(before, counts(t, "vws.iam.mfa.operations")), map[attribute.Distinct]int64{
		labels("op", "CreateVirtual", "result", "ok"):      1,
		labels("op", "Enable", "result", "ok"):             1,
		labels("op", "Verify", "result", "invalid_code"):   1,
		labels("op", "VerifySerial", "result", "ok"):       1,
		labels("op", "Verify", "result", "not_associated"): 1,
		labels("op", "Required", "result", "ok"):           1,
		labels("op", "Delete", "result", "in_use"):         1,
		labels("op", "Deactivate", "result", "ok"):         1,
		labels("op", "Delete", "result", "ok"):             1,
		labels("op", "List", "result", "ok"):               1,
	})

	ended := spans.Ended()
	if len(ended) != 10 {
		t.Fatalf("%d spans, want 10", len(ended))
	}
	failed := 0
	for _, s := range ended {
		if !strings.HasPrefix(s.Name(), "mfa.") {
			t.Errorf("span %q", s.Name())
		}
		if s.Status().Code == codes.Error {
			failed++
		}
		texts := []string{s.Name(), s.Status().Description}
		for _, a := range s.Attributes() {
			texts = append(texts, a.Value.String())
		}
		for _, x := range texts {
			for _, leak := range []string{"alice", "nope", e.SerialNumber, e.Base32Seed, c1, c2, good, bad} {
				if strings.Contains(x, leak) {
					t.Errorf("span %s carries %q", s.Name(), x)
				}
			}
		}
	}
	if failed != 3 {
		t.Errorf("%d spans marked failed, want 3", failed)
	}
}

// TestLockoutsAreCounted: the wrong code that locks a device counts one
// started lockout; a renewal that extends a running lock counts one
// renewed; a renewal of an unlocked device and a refusal while locked
// count none.
func TestLockoutsAreCounted(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	seed := enroll(t, svc, clk, "alice", "d1")
	before := counts(t, "vws.iam.mfa.lockouts")
	if renewed, err := svc.RenewLock(ctx, "alice", "d1"); err != nil || renewed {
		t.Fatalf("renewal of an unlocked device: %v %v", renewed, err)
	}
	for i := 1; i <= mfa.MaxFailedAttempts; i++ {
		if err := svc.Verify(ctx, "alice", "d1", wrongCode(seed, clk.t)); err == nil {
			t.Fatalf("wrong code %d accepted", i)
		}
	}
	if err := svc.Verify(ctx, "alice", "d1", wrongCode(seed, clk.t)); !errors.Is(err, mfa.ErrLocked) {
		t.Fatalf("locked device: %v", err)
	}
	clk.t = clk.t.Add(time.Minute)
	spans.Reset()
	if renewed, err := svc.RenewLockSerial(ctx, "alice", "arn:vws:iam::"+acct+":mfa/d1"); err != nil || !renewed {
		t.Fatalf("renewal of a locked device: %v %v", renewed, err)
	}
	wantCounts(t, "lockouts", delta(before, counts(t, "vws.iam.mfa.lockouts")), map[attribute.Distinct]int64{
		labels("op", "Verify", "event", "started"):          1,
		labels("op", "RenewLockSerial", "event", "renewed"): 1,
	})
	ended := spans.Ended()
	if len(ended) != 1 || ended[0].Name() != "mfa.RenewLockSerial" {
		t.Fatalf("renewal spans %v, want one mfa.RenewLockSerial", ended)
	}
	var lockout string
	for _, a := range ended[0].Attributes() {
		if a.Key == "lockout" {
			lockout = a.Value.AsString()
		}
	}
	if lockout != "renewed" {
		t.Errorf("renewal span lockout=%q, want renewed", lockout)
	}
}

// listFails answers every MFA device List with err.
type listFails struct {
	store.Backend
	err error
}

func (l listFails) List(ctx context.Context, kind iam.Kind) ([]store.Entry, error) {
	if kind == iam.KindMfaDevice {
		return nil, l.err
	}
	return l.Backend.List(ctx, kind)
}

func TestErrorsCarryContext(t *testing.T) {
	svc, b, clk := setup(t)
	ctx := context.Background()
	seed := enroll(t, svc, clk, "alice", "alice-phone")
	clk.t = clk.t.Add(time.Minute)
	good := code(seed, clk.t, 0)

	otherErr := svc.Verify(ctx, "bob", "alice-phone", good)
	missingErr := svc.Verify(ctx, "bob", "nope", good)
	if strings.Replace(otherErr.Error(), "alice-phone", "nope", 1) != missingErr.Error() {
		t.Errorf("another user's device answers %q, a missing one %q: the message tells them apart", otherErr, missingErr)
	}
	down := mfa.New(listFails{b, store.ErrUnavailable}, nil, acct, clk.now)
	_, listErr := down.List(ctx, "alice")
	_, requiredErr := down.Required(ctx, "alice")
	for _, tc := range []struct {
		err      error
		sentinel error
		context  string
	}{
		{otherErr, mfa.ErrNotAssociated, "mfa device alice-phone"},
		{missingErr, mfa.ErrNotAssociated, "mfa device nope"},
		{svc.Verify(ctx, "alice", "alice-phone", wrongCode(seed, clk.t)), mfa.ErrInvalidCode, "mfa device alice-phone"},
		{svc.Resync(ctx, "alice", "alice-phone", good, good), mfa.ErrNotAssociated, `mfa device "alice-phone"`},
		{
			svc.Enable(ctx, "carol", "alice-phone", good, good),
			store.ErrNotFound, `enable mfa device alice-phone: user "carol"`,
		},
		{svc.Delete(ctx, "alice-phone"), mfa.ErrEntityInUse, "delete mfa device alice-phone"},
		{svc.Delete(ctx, "nope"), store.ErrNotFound, "delete mfa device nope"},
		{svc.Deactivate(ctx, "bob", "alice-phone"), mfa.ErrNotAssociated, "deactivate mfa device alice-phone"},
		{listErr, store.ErrUnavailable, "list mfa devices"},
		{requiredErr, store.ErrUnavailable, "list mfa devices"},
	} {
		if !errors.Is(tc.err, tc.sentinel) || !strings.Contains(tc.err.Error(), tc.context) {
			t.Errorf("error %v, want %v with %q", tc.err, tc.sentinel, tc.context)
		}
		if strings.Contains(tc.err.Error(), good) {
			t.Errorf("error %v carries the code", tc.err)
		}
	}
}
