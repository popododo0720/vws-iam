package sts_test

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

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
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

// points sums the operation counter and counts the duration histogram
// points by op/result. A point with any other label fails the test.
func points(t *testing.T) (opsByLabel, dursByLabel map[string]int64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	opsByLabel, dursByLabel = map[string]int64{}, map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				if m.Name == "vws.iam.sts.operations" {
					for _, dp := range data.DataPoints {
						opsByLabel[opResult(t, dp.Attributes)] += dp.Value
					}
				}
			case metricdata.Histogram[float64]:
				if m.Name == "vws.iam.sts.duration" {
					for _, dp := range data.DataPoints {
						dursByLabel[opResult(t, dp.Attributes)] += int64(dp.Count)
					}
				}
			}
		}
	}
	return opsByLabel, dursByLabel
}

func opResult(t *testing.T, set attribute.Set) string {
	t.Helper()
	for _, kv := range set.ToSlice() {
		if kv.Key != "op" && kv.Key != "result" {
			t.Errorf("metric point labelled %s=%s", kv.Key, kv.Value.String())
		}
	}
	op, _ := set.Value("op")
	r, _ := set.Value("result")
	return op.AsString() + "/" + r.AsString()
}

func changed(before, after map[string]int64) map[string]int64 {
	d := map[string]int64{}
	for k, v := range after {
		if v != before[k] {
			d[k] = v - before[k]
		}
	}
	return d
}

func sameCounts(t *testing.T, what string, got, want map[string]int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: %v, want %v", what, got, want)
		return
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %v, want %v", what, got, want)
			return
		}
	}
}

// downOn fails every read of kind with store.ErrUnavailable.
type downOn struct {
	store.Backend
	kind iam.Kind
}

func (d downOn) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	if kind == d.kind {
		return store.Entry{}, store.ErrUnavailable
	}
	return d.Backend.Get(ctx, kind, key)
}

// TestOperationsAreMeasuredAndTraced: every STS operation is one span
// sts.<op>, a child of the caller's span (so a gRPC server span carries it),
// and one counter and one latency point labelled op and result only. A
// failure marks the span failed with the result, never the message; no span
// or label carries a principal, role, session name, key id, token or
// secret. Resolve of a session token is one Resolve, not also a Validate.
func TestOperationsAreMeasuredAndTraced(t *testing.T) {
	e := setup(t)
	alice, bob := e.caller(t, "alice"), e.caller(t, "bob")
	down := sts.New(downOn{e.b, iam.KindRole}, e.keys, e.az, acct, e.clk.now)
	spans.Reset()
	ops0, durs0 := points(t)

	ctx, parent := otel.Tracer("test").Start(context.Background(), "rpc")
	assume := func(svc *sts.Service, c sts.Caller, name string) error {
		_, err := svc.AssumeRole(ctx, c, nil, adminARN, name, 0, sts.SessionPolicies{}, sts.MFA{})
		return err
	}
	creds, err := e.svc.AssumeRole(ctx, alice, nil, adminARN, "deploy-7", 0, sts.SessionPolicies{}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	if err := assume(e.svc, bob, "deploy-8"); !errors.Is(err, sts.ErrAccessDenied) {
		t.Fatalf("bob: %v", err)
	}
	if err := assume(e.svc, alice, "bad name!"); !errors.Is(err, sts.ErrInvalidRequest) {
		t.Fatalf("bad session name: %v", err)
	}
	if err := assume(down, alice, "deploy-9"); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("store down: %v", err)
	}
	if _, err := e.svc.Validate(ctx, creds.AccessKeyID, creds.SessionToken); err != nil {
		t.Fatal(err)
	}
	sessionCred := sts.Credential{AccessKeyID: creds.AccessKeyID, SessionToken: creds.SessionToken}
	if _, err := e.svc.Resolve(ctx, sessionCred); err != nil {
		t.Fatal(err)
	}
	st, err := e.svc.GetSessionToken(ctx, alice, time.Hour, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RevokeSessions(ctx, authz.Role, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Validate(ctx, creds.AccessKeyID, creds.SessionToken); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("revoked session: %v", err)
	}
	e.clk.t = e.clk.t.Add(2 * time.Hour)
	if _, err := e.svc.Validate(ctx, st.AccessKeyID, st.SessionToken); !errors.Is(err, sts.ErrExpired) {
		t.Fatalf("expired session: %v", err)
	}
	parent.End()

	ops1, durs1 := points(t)
	want := map[string]int64{
		"AssumeRole/ok":              1,
		"AssumeRole/access_denied":   1,
		"AssumeRole/invalid_request": 1,
		"AssumeRole/unavailable":     1,
		"Validate/ok":                1,
		"Resolve/ok":                 1,
		"GetSessionToken/ok":         1,
		"RevokeSessions/ok":          1,
		"Validate/invalid_token":     1,
		"Validate/expired":           1,
	}
	sameCounts(t, "operations", changed(ops0, ops1), want)
	sameCounts(t, "duration points", changed(durs0, durs1), want)

	leaks := []string{
		"alice", "bob", "admin", "deploy-", "bad name", creds.AccessKeyID, creds.SessionToken, creds.Secret,
		st.AccessKeyID, st.SessionToken, st.Secret, acct,
	}
	failed, children := 0, 0
	for _, s := range spans.Ended() {
		if !strings.HasPrefix(s.Name(), "sts.") {
			continue // the caller's span and the nested authz.authorize spans
		}
		children++
		if pc := parent.SpanContext(); s.Parent().SpanID() != pc.SpanID() || s.SpanContext().TraceID() != pc.TraceID() {
			t.Errorf("span %s is not a child of the caller's span", s.Name())
		}
		if s.Status().Code == codes.Error {
			failed++
		}
		texts := []string{s.Name(), s.Status().Description}
		for _, a := range s.Attributes() {
			texts = append(texts, a.Value.String())
		}
		for _, x := range texts {
			for _, leak := range leaks {
				if strings.Contains(x, leak) {
					t.Errorf("span %s carries %q", s.Name(), x)
				}
			}
		}
	}
	if children != 10 || failed != 5 {
		t.Errorf("%d sts spans, %d failed; want 10 and 5", children, failed)
	}
}
