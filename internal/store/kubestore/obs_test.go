package kubestore_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
)

type telemetryProbe struct {
	spans  *tracetest.SpanRecorder
	reader *sdkmetric.ManualReader
}

func newProbedStore(t *testing.T, c client.Client) (*kubestore.Store, telemetryProbe) {
	t.Helper()
	p := telemetryProbe{spans: tracetest.NewSpanRecorder(), reader: sdkmetric.NewManualReader()}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(p.spans))
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(p.reader))
	return kubestore.NewWithTelemetry(c, "vws-iam", tp, mp), p
}

func attr(kv []attribute.KeyValue, key string) string {
	for _, a := range kv {
		if string(a.Key) == key {
			return a.Value.AsString()
		}
	}
	return ""
}

// durations maps "op/kind/result" to the number of recorded calls.
func (p telemetryProbe) durations(t *testing.T) map[string]uint64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := p.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]uint64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "vws.iam.store.duration" {
				continue
			}
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				t.Fatalf("%s is %T, not a histogram", m.Name, m.Data)
			}
			for _, dp := range h.DataPoints {
				kv := dp.Attributes.ToSlice()
				key := attr(kv, "vws.iam.store.op") + "/" + attr(kv, "vws.iam.store.kind") + "/" + attr(kv, "vws.iam.store.result")
				out[key] += dp.Count
			}
		}
	}
	return out
}

func TestStoreCallsAreTracedAndTimed(t *testing.T) {
	b, p := newProbedStore(t, newFake())
	ctx := context.Background()
	u, err := store.Create(ctx, b, iam.User{Name: "alice", ID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, b, iam.User{Name: "alice", ID: "2"}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	if _, err := b.Get(ctx, iam.KindUser, "bob"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get bob: %v", err)
	}
	if err := b.Delete(ctx, iam.KindUser, "alice", u); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"kubestore.create": "ok",
		"kubestore.get":    "not_found",
		"kubestore.delete": "ok",
	}
	seen := map[string]bool{}
	for _, s := range p.spans.Ended() {
		kv := s.Attributes()
		if attr(kv, "vws.iam.store.kind") != string(iam.KindUser) {
			t.Errorf("%s: kind %q", s.Name(), attr(kv, "vws.iam.store.kind"))
		}
		for _, a := range kv {
			if strings.Contains(a.Value.String(), "alice") {
				t.Errorf("%s attribute %s leaks the key", s.Name(), a.Key)
			}
		}
		if s.Status().Code == codes.Error {
			t.Errorf("%s: an answer (%s) marked the span failed", s.Name(), attr(kv, "vws.iam.store.result"))
		}
		if r, ok := want[s.Name()]; ok && attr(kv, "vws.iam.store.result") == r {
			seen[s.Name()] = true
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("no %s span with result %s", name, want[name])
		}
	}

	d := p.durations(t)
	for _, k := range []string{
		"create/IamUser/ok", "create/IamUser/exists", "get/IamUser/not_found", "delete/IamUser/ok",
	} {
		if d[k] == 0 {
			t.Errorf("no duration recorded for %s (have %v)", k, d)
		}
	}
}

func TestStoreFailuresCarryContextAndFailTheSpan(t *testing.T) {
	down := apierrors.NewServiceUnavailable("etcd leader lost")
	broken := errors.New("tls: bad certificate")
	c := fake.NewClientBuilder().WithScheme(scheme()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return down
		},
		List: func(context.Context, client.WithWatch, client.ObjectList, ...client.ListOption) error {
			return broken
		},
	}).Build()
	b, p := newProbedStore(t, c)
	ctx := context.Background()

	_, err := b.Get(ctx, iam.KindRole, "r")
	if !errors.Is(err, store.ErrUnavailable) || !errors.Is(err, down) {
		t.Fatalf("get: %v does not wrap ErrUnavailable and the API error", err)
	}
	if !strings.Contains(err.Error(), "kube get IamRole") {
		t.Errorf("get error %q does not name the call and kind", err)
	}
	_, err = b.List(ctx, iam.KindPolicy)
	if !errors.Is(err, broken) || errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(err.Error(), "kube list IamPolicy") {
		t.Errorf("list error %q does not name the call and kind", err)
	}

	results := map[string]string{}
	for _, s := range p.spans.Ended() {
		results[s.Name()] = attr(s.Attributes(), "vws.iam.store.result")
		if s.Status().Code != codes.Error {
			t.Errorf("%s: a failure left the span unset", s.Name())
		}
		if len(s.Events()) == 0 {
			t.Errorf("%s: no error event", s.Name())
		}
	}
	if results["kubestore.get"] != "unavailable" || results["kubestore.list"] != "error" {
		t.Errorf("results %v", results)
	}
	d := p.durations(t)
	if d["get/IamRole/unavailable"] != 1 || d["list/IamPolicy/error"] != 1 {
		t.Errorf("durations %v", d)
	}
}

func TestSentinelErrorsStayBare(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(scheme()).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(context.Context, client.WithWatch, client.Object, ...client.UpdateOption) error {
			gr := schema.GroupResource{Group: kubestore.Group, Resource: "iamusers"}
			return apierrors.NewConflict(gr, "x", errors.New("moved"))
		},
	}).Build()
	b := kubestore.New(c, "vws-iam")
	ctx := context.Background()
	u, err := store.Create(ctx, b, iam.User{Name: "alice", ID: "1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Get(ctx, iam.KindUser, "nobody"); err == nil || err.Error() != store.ErrNotFound.Error() {
		t.Errorf("not found text %v, want %q as memstore answers", err, store.ErrNotFound)
	}
	_, err = store.Create(ctx, b, iam.User{Name: "alice", ID: "2"})
	if err == nil || err.Error() != store.ErrExists.Error() {
		t.Errorf("exists text %v", err)
	}
	_, err = store.Update(ctx, b, iam.User{Name: "alice", ID: "1"}, u)
	if err == nil || err.Error() != store.ErrConflict.Error() {
		t.Errorf("conflict text %v", err)
	}
}
