package accesskey_test

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

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
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
func counts(ctx context.Context, t *testing.T, name string) map[attribute.Distinct]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
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

func TestOperationsAreMeasuredAndTraced(t *testing.T) {
	ctx := context.Background()
	b := memstore.New()
	withUser(t, b, "carol")
	svc := accesskey.New(b, b, "proj-a", ring(t, "kek-1", map[string][]byte{"kek-1": kek(t)}), nil)
	spans.Reset()
	before := counts(ctx, t, "vws.iam.access_key.operations")

	cred, err := svc.Create(ctx, "carol")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSigningCredential(ctx, cred.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetStatus(ctx, "carol", cred.AccessKeyID, iam.KeyInactive); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetSigningCredential(ctx, cred.AccessKeyID); !errors.Is(err, accesskey.ErrInactive) {
		t.Fatalf("inactive key: %v", err)
	}
	if _, err := svc.GetSigningCredential(ctx, "AKIAUNKNOWNUNKNOWN00"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := svc.Create(ctx, "nobody"); !errors.Is(err, accesskey.ErrNoSuchUser) {
		t.Fatalf("no such user: %v", err)
	}
	if err := svc.Delete(ctx, "carol", cred.AccessKeyID); err != nil {
		t.Fatal(err)
	}

	got := delta(before, counts(ctx, t, "vws.iam.access_key.operations"))
	want := map[attribute.Distinct]int64{
		labels("op", "Create", "result", "ok"):                      1,
		labels("op", "Import", "result", "ok"):                      1,
		labels("op", "Create", "result", "no_such_user"):            1,
		labels("op", "GetSigningCredential", "result", "ok"):        1,
		labels("op", "GetSigningCredential", "result", "inactive"):  1,
		labels("op", "GetSigningCredential", "result", "not_found"): 1,
		labels("op", "SetStatus", "result", "ok"):                   1,
		labels("op", "Delete", "result", "ok"):                      1,
	}
	if len(got) != len(want) {
		t.Fatalf("operations counted %d label sets, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("operations %v = %d, want %d", k, got[k], v)
		}
	}

	ended := spans.Ended()
	if len(ended) != 8 {
		t.Fatalf("%d spans, want 8", len(ended))
	}
	failed := 0
	for _, s := range ended {
		if !strings.HasPrefix(s.Name(), "accesskey.") {
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
			for _, leak := range []string{cred.Secret, cred.AccessKeyID, "carol"} {
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

// updateFails answers every access key Update with err.
type updateFails struct {
	store.Backend
	err error
}

func (u updateFails) Update(
	ctx context.Context, kind iam.Kind, key string, spec []byte, version string,
) (string, error) {
	if kind == iam.KindAccessKey {
		return "", u.err
	}
	return u.Backend.Update(ctx, kind, key, spec, version)
}

func TestRewrapIsCounted(t *testing.T) {
	k1, k2 := kek(t), kek(t)
	for _, tc := range []struct {
		name    string
		update  error
		result  string
		wantErr error
	}{
		{"ok", nil, "ok", nil},
		{"lost race", store.ErrConflict, "conflict", nil},
		{"store down", store.ErrUnavailable, "error", store.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			b := memstore.New()
			withUser(t, b, "dave")
			cred, err := accesskey.New(b, b, "proj-a", ring(t, "kek-1", map[string][]byte{"kek-1": k1}), nil).Create(ctx, "dave")
			if err != nil {
				t.Fatal(err)
			}
			var rb store.Backend = b
			if tc.update != nil {
				rb = updateFails{b, tc.update}
			}
			rotated := accesskey.New(rb, rb, "proj-a", ring(t, "kek-2", map[string][]byte{"kek-1": k1, "kek-2": k2}), nil)
			before := counts(ctx, t, "vws.iam.access_key.rewraps")
			got, err := rotated.GetSigningCredential(ctx, cred.AccessKeyID)
			if !errors.Is(err, tc.wantErr) || (err == nil && got.Secret != cred.Secret) {
				t.Fatalf("signing credential after rotation: %v", err)
			}
			if err != nil && !strings.Contains(err.Error(), "rewrap access key "+cred.AccessKeyID) {
				t.Errorf("error %q lacks context", err)
			}
			d := delta(before, counts(ctx, t, "vws.iam.access_key.rewraps"))
			if len(d) != 1 || d[labels("result", tc.result)] != 1 {
				t.Errorf("rewraps %v, want one %q", d, tc.result)
			}
		})
	}
}

func TestErrorsCarryContext(t *testing.T) {
	ctx := context.Background()
	b := memstore.New()
	withUser(t, b, "erin")
	svc := accesskey.New(b, b, "proj-a", ring(t, "kek-1", map[string][]byte{"kek-1": kek(t)}), nil)
	cred, err := svc.Create(ctx, "erin")
	if err != nil {
		t.Fatal(err)
	}
	other := accesskey.New(b, b, "proj-a", ring(t, "kek-9", map[string][]byte{"kek-9": kek(t)}), nil)
	_, openErr := other.GetSigningCredential(ctx, cred.AccessKeyID)
	_, ownErr := svc.Get(ctx, "mallory", cred.AccessKeyID)
	_, missingErr := svc.Get(ctx, "mallory", "AKIAUNKNOWNUNKNOWN00")
	if strings.Replace(ownErr.Error(), cred.AccessKeyID, "AKIAUNKNOWNUNKNOWN00", 1) != missingErr.Error() {
		t.Errorf("another user's key answers %q, a missing key %q: the message tells them apart", ownErr, missingErr)
	}
	for _, tc := range []struct {
		err      error
		sentinel error
		context  string
	}{
		{openErr, secret.ErrUnknownKEK, "open access key " + cred.AccessKeyID},
		{ownErr, store.ErrNotFound, "access key " + cred.AccessKeyID},
		{
			svc.SetStatus(ctx, "erin", "AKIAUNKNOWNUNKNOWN00", iam.KeyInactive),
			store.ErrNotFound, "access key AKIAUNKNOWNUNKNOWN00",
		},
		{svc.Delete(ctx, "mallory", cred.AccessKeyID), store.ErrNotFound, "access key " + cred.AccessKeyID},
	} {
		if !errors.Is(tc.err, tc.sentinel) || !strings.Contains(tc.err.Error(), tc.context) {
			t.Errorf("error %v, want %v with %q", tc.err, tc.sentinel, tc.context)
		}
		if strings.Contains(tc.err.Error(), cred.Secret) {
			t.Errorf("error %v carries the secret", tc.err)
		}
	}
}
