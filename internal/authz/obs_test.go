package authz_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

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

// points sums the counter evaluations and counts the histogram duration
// points by attribute set.
func points(ctx context.Context, t *testing.T) (evals, durs map[string]int64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	evals, durs = map[string]int64{}, map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				if m.Name == "vws.iam.authz.evaluations" {
					for _, dp := range data.DataPoints {
						evals[key(t, dp.Attributes)] += dp.Value
					}
				}
			case metricdata.Histogram[float64]:
				if m.Name == "vws.iam.authz.duration" {
					for _, dp := range data.DataPoints {
						durs[key(t, dp.Attributes)] += int64(dp.Count)
					}
				}
			}
		}
	}
	return evals, durs
}

func labels(decision, result string) string { return decision + "/" + result }

// key is the decision/result of a metric point, which may carry no other
// label.
func key(t *testing.T, set attribute.Set) string {
	t.Helper()
	for _, kv := range set.ToSlice() {
		if kv.Key != "decision" && kv.Key != "result" {
			t.Errorf("metric point labelled %s=%s", kv.Key, kv.Value.String())
		}
	}
	d, _ := set.Value("decision")
	r, _ := set.Value("result")
	return labels(d.AsString(), r.AsString())
}

func delta(before, after map[string]int64) map[string]int64 {
	d := map[string]int64{}
	for k, v := range after {
		if v != before[k] {
			d[k] = v - before[k]
		}
	}
	return d
}

// down fails every read of kind with err, store.ErrUnavailable when nil.
type down struct {
	store.Backend
	kind iam.Kind
	err  error
}

func (d down) fail() error {
	if d.err != nil {
		return d.err
	}
	return store.ErrUnavailable
}

func (d down) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	if kind == d.kind {
		return store.Entry{}, d.fail()
	}
	return d.Backend.Get(ctx, kind, key)
}

func (d down) List(ctx context.Context, kind iam.Kind) ([]store.Entry, error) {
	if kind == d.kind {
		return nil, d.fail()
	}
	return d.Backend.List(ctx, kind)
}

func TestAuthorizeIsMeasuredAndTraced(t *testing.T) {
	ctx := context.Background()
	b := setup(t)
	noResource := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*"}}`
	put(t, b, iam.User{Name: "mallory", ID: "9", InlinePolicies: map[string]string{"bad": noResource}})
	a := authz.New(b, acct, nil)
	alice := authz.Principal{Kind: authz.User, Name: "alice"}
	spans.Reset()
	evals0, durs0 := points(ctx, t)

	calls := []struct {
		a        *authz.Authorizer
		p        authz.Principal
		action   string
		decision string
		result   string
	}{
		{a, alice, "s3:GetObject", "allow", "ok"},
		{a, alice, "iam:CreateUser", "implicit_deny", "ok"},
		{a, alice, "ec2:TerminateInstances", "explicit_deny", "ok"},
		{a, authz.Principal{Kind: authz.Root}, "iam:DeleteUser", "allow", "ok"},
		{a, authz.Principal{Kind: authz.User, Name: "nobody"}, "s3:GetObject", "none", "no_such_entity"},
		{a, authz.Principal{Kind: authz.User, Name: "mallory"}, "s3:GetObject", "none", "malformed_policy"},
		{authz.New(down{Backend: b, kind: iam.KindUser}, acct, nil), alice, "s3:GetObject", "none", "unavailable"},
	}
	want := map[string]int64{}
	for _, c := range calls {
		reqCtx := map[string][]string{"aws:SourceIp": {"192.0.2.7"}}
		_, err := c.a.Authorize(ctx, c.p, c.action, "arn:vws:s3:::secret-bucket/k", reqCtx)
		if (err == nil) != (c.result == "ok") {
			t.Fatalf("%s %s: err %v, want result %s", c.p.Name, c.action, err, c.result)
		}
		want[labels(c.decision, c.result)]++
	}
	gone := authz.New(down{Backend: b, kind: iam.KindUser, err: context.Canceled}, acct, nil)
	if _, err := gone.Authorize(ctx, alice, "s3:GetObject", "*", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	want[labels("none", "canceled")]++

	evals1, durs1 := points(ctx, t)
	for name, got := range map[string]map[string]int64{
		"vws.iam.authz.evaluations": delta(evals0, evals1),
		"vws.iam.authz.duration":    delta(durs0, durs1),
	} {
		if len(got) != len(want) {
			t.Errorf("%s: %d label sets, want %d", name, len(got), len(want))
		}
		for k, n := range want {
			if got[k] != n {
				t.Errorf("%s %s: %d, want %d", name, k, got[k], n)
			}
		}
	}

	ended := spans.Ended()
	if len(ended) != len(calls)+1 {
		t.Fatalf("%d spans, want %d", len(ended), len(calls)+1)
	}
	secrets := []string{"alice", "mallory", "nobody", "secret-bucket", "192.0.2.7", "GetObject", "TerminateInstances"}
	for i, s := range ended {
		if s.Name() != "authz.authorize" {
			t.Errorf("span %d is %q", i, s.Name())
		}
		attrs := map[string]string{}
		for _, kv := range s.Attributes() {
			attrs[string(kv.Key)] = kv.Value.String()
		}
		result := "canceled"
		if i < len(calls) {
			result = calls[i].result
			if attrs["decision"] != calls[i].decision {
				t.Errorf("span %d decision %q, want %q", i, attrs["decision"], calls[i].decision)
			}
		}
		if attrs["result"] != result {
			t.Errorf("span %d result %q, want %q", i, attrs["result"], result)
		}
		failed := s.Status().Code == codes.Error
		if failed != (result != "ok") || failed && s.Status().Description != result {
			t.Errorf("span %d status %+v, want failed=%v", i, s.Status(), result != "ok")
		}
		text := s.Status().Description
		for _, kv := range s.Attributes() {
			text += " " + string(kv.Key) + "=" + kv.Value.String()
		}
		for _, ev := range s.Events() {
			text += " " + ev.Name
		}
		for _, x := range secrets {
			if strings.Contains(text, x) {
				t.Errorf("span %d carries %q: %s", i, x, text)
			}
		}
	}
}

func TestAuthorizeErrorsCarryContext(t *testing.T) {
	ctx := context.Background()
	b := setup(t)
	alice := authz.Principal{Kind: authz.User, Name: "alice"}
	for _, c := range []struct {
		kind iam.Kind
		p    authz.Principal
		want string
	}{
		{iam.KindUser, alice, `get user "alice": `},
		{iam.KindRole, authz.Principal{Kind: authz.Role, Name: "reader"}, `get role "reader": `},
		{iam.KindGroup, alice, `list groups: `},
		{iam.KindPolicy, alice, `get policy "arn:vws:iam::` + acct + `:policy/S3Read": `},
	} {
		_, err := authz.New(down{Backend: b, kind: c.kind}, acct, nil).Authorize(ctx, c.p, "s3:GetObject", "*", nil)
		if !errors.Is(err, store.ErrUnavailable) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s down: %v, want %q wrapping ErrUnavailable", c.kind, err, c.want)
		}
	}
	_, _, err := authz.New(down{Backend: b, kind: iam.KindGroup}, acct, nil).GroupPolicies(ctx, "devs")
	if !errors.Is(err, store.ErrUnavailable) || !strings.Contains(err.Error(), `get group "devs": `) {
		t.Errorf("group down: %v", err)
	}
}
