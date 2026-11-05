package sts_test

import (
	"context"
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
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

// points sums the counter operations and counts the histogram duration
// points by op/result.
func points(ctx context.Context, t *testing.T) (opsN, durs map[string]int64) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	opsN, durs = map[string]int64{}, map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				if m.Name == "vws.iam.sts.operations" {
					for _, dp := range data.DataPoints {
						opsN[labelKey(t, dp.Attributes)] += dp.Value
					}
				}
			case metricdata.Histogram[float64]:
				if m.Name == "vws.iam.sts.duration" {
					for _, dp := range data.DataPoints {
						durs[labelKey(t, dp.Attributes)] += int64(dp.Count)
					}
				}
			}
		}
	}
	return opsN, durs
}

// labelKey is the op/result of a metric point, which may carry no other
// label.
func labelKey(t *testing.T, set attribute.Set) string {
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

func delta(before, after map[string]int64) map[string]int64 {
	d := map[string]int64{}
	for k, v := range after {
		if v != before[k] {
			d[k] = v - before[k]
		}
	}
	return d
}

// flaky fails reads of the kinds fail answers for, with the error it
// returns.
type flaky struct {
	store.Backend
	fail func(iam.Kind) error
}

func (f flaky) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	if err := f.fail(kind); err != nil {
		return store.Entry{}, err
	}
	return f.Backend.Get(ctx, kind, key)
}

func (f flaky) List(ctx context.Context, kind iam.Kind) ([]store.Entry, error) {
	if err := f.fail(kind); err != nil {
		return nil, err
	}
	return f.Backend.List(ctx, kind)
}

// downKind fails every read of kind with err.
func downKind(b store.Backend, kind iam.Kind, err error) store.Backend {
	return flaky{b, func(k iam.Kind) error {
		if k == kind {
			return err
		}
		return nil
	}}
}

// nthRead fails only the nth read of kind (1-based) with ErrUnavailable.
func nthRead(b store.Backend, kind iam.Kind, n int32) store.Backend {
	var seen atomic.Int32
	return flaky{b, func(k iam.Kind) error {
		if k == kind && seen.Add(1) == n {
			return store.ErrUnavailable
		}
		return nil
	}}
}

// obsEnv is the SAML test env plus an auditor allowed to decode messages
// and read key info, and a service over any backend.
type obsEnv struct {
	samlEnv
	provs samltest.Providers
}

func obsSetup(t *testing.T) obsEnv {
	t.Helper()
	e := samlSetup(t)
	put(t, e.b, iam.User{Name: "auditor", ID: "AIDAAUDITOR", InlinePolicies: map[string]string{
		"info": `{"Version":"2012-10-17","Statement":{"Effect":"Allow",
			"Action":["sts:GetAccessKeyInfo","sts:DecodeAuthorizationMessage"],"Resource":"*"}}`,
	}})
	return obsEnv{samlEnv: e, provs: samltest.Providers{samlIdpARN: e.idp.Provider(samlIdpARN)}}
}

// over is a service reading b for objects and index for the key index.
func (e obsEnv) over(b, index store.Backend) *sts.Service {
	return sts.New(b, e.keys, authz.New(b, acct, e.clk.now), acct, e.clk.now,
		sts.WithMFA(fakeMFA{}), sts.WithKeyIndex(index), sts.WithSAML(e.provs, samlSP))
}

func (e obsEnv) key(t *testing.T, user string) accesskey.Credential {
	t.Helper()
	cred, err := accesskey.New(e.b, e.b, acct, e.keys, e.clk.now).Create(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// indexedKey is an access key in the project's scoped view with its entry
// in the unscoped key index, the layout GetAccessKeyInfo reads.
func (e obsEnv) indexedKey(t *testing.T) accesskey.Credential {
	t.Helper()
	scoped := store.Scoped(e.b, acct)
	put(t, scoped, iam.User{Name: "keyowner", ID: "AIDAKEYOWNER"})
	cred, err := accesskey.New(scoped, e.b, acct, e.keys, e.clk.now).Create(context.Background(), "keyowner")
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

func TestSTSOperationsAreMeasuredAndTraced(t *testing.T) {
	ctx := context.Background()
	e := obsSetup(t)
	svc := e.over(e.b, e.b)
	broker, nobody, auditor := e.caller(t, "broker"), e.caller(t, "nobody"), e.caller(t, "auditor")
	nobodyKey, infoKey := e.key(t, "nobody"), e.indexedKey(t)
	unavailable := e.over(downKind(e.b, iam.KindRole, store.ErrUnavailable), e.b)
	canceled := e.over(downKind(e.b, iam.KindRole, context.Canceled), e.b)
	keyDown := e.over(downKind(e.b, iam.KindAccessKey, store.ErrUnavailable), e.b)
	enc, err := svc.EncodeAuthorizationMessage(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	badAudience := e.claims()
	badAudience.Audience = "urn:someone-else"
	goodSAML := e.response(t, e.claims(), samltest.SignAssertion)
	badSAML := e.response(t, badAudience, samltest.SignAssertion)
	serial := "arn:vws:iam::" + acct + ":mfa/broker"
	longPolicy := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}}`
	unknownKey := "AKIAZZZZZZZZZZZZZZZZ"

	var role, plain sts.Credentials
	var mfaToken sts.Credentials
	calls := []struct {
		name string
		want []string // sts spans in the order they end
		run  func() error
	}{
		{"AssumeRole", []string{"assume_role/ok"}, func() (err error) {
			role, err = svc.AssumeRole(ctx, broker, nil, adminARN, "deploy-1", 15*time.Minute, "", sts.MFA{})
			return err
		}},
		{"AssumeRole untrusted", []string{"assume_role/access_denied"}, func() error {
			_, err := svc.AssumeRole(ctx, nobody, nil, adminARN, "deploy-1", 0, "", sts.MFA{})
			return err
		}},
		{"AssumeRole bad session name", []string{"assume_role/validation"}, func() error {
			_, err := svc.AssumeRole(ctx, broker, nil, adminARN, "x", 0, "", sts.MFA{})
			return err
		}},
		{"AssumeRole bad session policy", []string{"assume_role/malformed_policy"}, func() error {
			_, err := svc.AssumeRole(ctx, broker, nil, adminARN, "deploy-1", 0, "{", sts.MFA{})
			return err
		}},
		{"AssumeRole store down", []string{"assume_role/unavailable"}, func() error {
			_, err := unavailable.AssumeRole(ctx, broker, nil, adminARN, "deploy-1", 0, "", sts.MFA{})
			return err
		}},
		{"AssumeRole canceled", []string{"assume_role/canceled"}, func() error {
			_, err := canceled.AssumeRole(ctx, broker, nil, adminARN, "deploy-1", 0, "", sts.MFA{})
			return err
		}},
		{"GetSessionToken", []string{"get_session_token/ok"}, func() (err error) {
			plain, err = svc.GetSessionToken(ctx, broker, time.Hour, sts.MFA{})
			return err
		}},
		{"GetSessionToken with MFA", []string{"get_session_token/ok"}, func() (err error) {
			mfaToken, err = svc.GetSessionToken(ctx, broker, time.Hour, sts.MFA{SerialNumber: serial, TokenCode: "123456"})
			return err
		}},
		{"GetSessionToken wrong code", []string{"get_session_token/access_denied"}, func() error {
			_, err := svc.GetSessionToken(ctx, broker, time.Hour, sts.MFA{SerialNumber: serial, TokenCode: "000000"})
			return err
		}},
		{"GetSessionToken throttled", []string{"get_session_token/throttling"}, func() error {
			_, err := svc.GetSessionToken(ctx, broker, time.Hour, sts.MFA{SerialNumber: serial, TokenCode: "999999"})
			return err
		}},
		{"GetSessionToken bad duration", []string{"get_session_token/validation"}, func() error {
			_, err := svc.GetSessionToken(ctx, broker, time.Second, sts.MFA{})
			return err
		}},
		{"GetFederationToken", []string{"get_federation_token/ok"}, func() error {
			_, err := svc.GetFederationToken(ctx, broker, nil, sts.FederationRequest{Name: "fedbob", Policy: longPolicy})
			return err
		}},
		{"GetFederationToken denied", []string{"get_federation_token/access_denied"}, func() error {
			_, err := svc.GetFederationToken(ctx, nobody, nil, sts.FederationRequest{Name: "fedbob"})
			return err
		}},
		{"GetFederationToken bad name", []string{"get_federation_token/validation"}, func() error {
			_, err := svc.GetFederationToken(ctx, broker, nil, sts.FederationRequest{Name: "x"})
			return err
		}},
		{"AssumeRoleWithSAML", []string{"assume_role_with_saml/ok"}, func() error {
			_, err := svc.AssumeRoleWithSAML(ctx, samlReq(goodSAML))
			return err
		}},
		{"AssumeRoleWithSAML wrong audience", []string{"assume_role_with_saml/invalid_identity_token"}, func() error {
			_, err := svc.AssumeRoleWithSAML(ctx, samlReq(badSAML))
			return err
		}},
		{"DecodeAuthorizationMessage", []string{"decode_authorization_message/ok"}, func() error {
			_, err := svc.DecodeAuthorizationMessage(ctx, auditor, nil, enc)
			return err
		}},
		{"DecodeAuthorizationMessage denied", []string{"decode_authorization_message/access_denied"}, func() error {
			_, err := svc.DecodeAuthorizationMessage(ctx, broker, nil, enc)
			return err
		}},
		{"DecodeAuthorizationMessage garbage", []string{
			"decode_authorization_message/invalid_authorization_message",
		}, func() error {
			_, err := svc.DecodeAuthorizationMessage(ctx, auditor, nil, "abc.def")
			return err
		}},
		{"DecodeAuthorizationMessage empty", []string{"decode_authorization_message/validation"}, func() error {
			_, err := svc.DecodeAuthorizationMessage(ctx, auditor, nil, "")
			return err
		}},
		{"GetAccessKeyInfo", []string{"get_access_key_info/ok"}, func() error {
			_, err := svc.GetAccessKeyInfo(ctx, auditor, nil, infoKey.AccessKeyID)
			return err
		}},
		{"GetAccessKeyInfo unknown key", []string{"get_access_key_info/invalid_token"}, func() error {
			_, err := svc.GetAccessKeyInfo(ctx, auditor, nil, unknownKey)
			return err
		}},
		{"GetAccessKeyInfo short id", []string{"get_access_key_info/validation"}, func() error {
			_, err := svc.GetAccessKeyInfo(ctx, auditor, nil, "short")
			return err
		}},
		{"GetAccessKeyInfo denied", []string{"get_access_key_info/access_denied"}, func() error {
			_, err := svc.GetAccessKeyInfo(ctx, broker, nil, infoKey.AccessKeyID)
			return err
		}},
		{"ConsoleCaller", []string{"console_caller/ok"}, func() error {
			_, err := svc.ConsoleCaller(ctx, "broker", false, time.Time{})
			return err
		}},
		{"ConsoleCaller unknown user", []string{"console_caller/invalid_token"}, func() error {
			_, err := svc.ConsoleCaller(ctx, "ghost", false, time.Time{})
			return err
		}},
		{"Resolve long-term key", []string{"resolve/ok"}, func() error {
			_, err := svc.Resolve(ctx, sts.Credential{AccessKeyID: nobodyKey.AccessKeyID})
			return err
		}},
		{"Resolve session", []string{"validate/ok", "resolve/ok"}, func() error {
			_, err := svc.Resolve(ctx, sts.Credential{AccessKeyID: role.AccessKeyID, SessionToken: role.SessionToken})
			return err
		}},
		{"Resolve unknown key", []string{"resolve/invalid_token"}, func() error {
			_, err := svc.Resolve(ctx, sts.Credential{AccessKeyID: unknownKey})
			return err
		}},
		{"Resolve tampered token", []string{"validate/invalid_token", "resolve/invalid_token"}, func() error {
			tampered := role.SessionToken[:len(role.SessionToken)-3] + "AAA"
			_, err := svc.Resolve(ctx, sts.Credential{AccessKeyID: role.AccessKeyID, SessionToken: tampered})
			return err
		}},
		{"Resolve store down", []string{"resolve/unavailable"}, func() error {
			_, err := keyDown.Resolve(ctx, sts.Credential{AccessKeyID: nobodyKey.AccessKeyID})
			return err
		}},
		{"Validate", []string{"validate/ok"}, func() error {
			_, err := svc.Validate(ctx, mfaToken.AccessKeyID, mfaToken.SessionToken)
			return err
		}},
		{"RevokeSessions", []string{"revoke_sessions/ok"}, func() error {
			return svc.RevokeSessions(ctx, authz.User, "nobody")
		}},
		{"RevokeSessions bad kind", []string{"revoke_sessions/validation"}, func() error {
			return svc.RevokeSessions(ctx, authz.PrincipalKind(99), "nobody")
		}},
		{"RevokeSessions unknown user", []string{"revoke_sessions/not_found"}, func() error {
			return svc.RevokeSessions(ctx, authz.User, "ghost")
		}},
		{"RevokeSessionsOnce", []string{"revoke_sessions_once/ok"}, func() error {
			return svc.RevokeSessionsOnce(ctx, authz.Role, "admin", "req-1")
		}},
		{"RevokeSessionsOnce bad kind", []string{"revoke_sessions_once/validation"}, func() error {
			return svc.RevokeSessionsOnce(ctx, authz.PrincipalKind(99), "admin", "req-2")
		}},
	}

	spans.Reset()
	ops0, durs0 := points(ctx, t)
	want := map[string]int64{}
	var wantSpans []string
	for _, c := range calls {
		err := c.run()
		last := c.want[len(c.want)-1]
		if ok := strings.HasSuffix(last, "/ok"); ok != (err == nil) {
			t.Fatalf("%s: err %v, want %s", c.name, err, last)
		}
		for _, w := range c.want {
			want[w]++
		}
		wantSpans = append(wantSpans, c.want...)
	}
	// An expired session is the only result that needs the clock moved.
	e.clk.t = e.clk.t.Add(3 * time.Hour)
	if _, err := svc.Validate(ctx, role.AccessKeyID, role.SessionToken); !errors.Is(err, sts.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	want["validate/expired"]++
	wantSpans = append(wantSpans, "validate/expired")

	ops1, durs1 := points(ctx, t)
	for name, got := range map[string]map[string]int64{
		"vws.iam.sts.operations": delta(ops0, ops1),
		"vws.iam.sts.duration":   delta(durs0, durs1),
	} {
		if !maps.Equal(got, want) {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}

	// Spans from other packages (authz.authorize, accesskey.*) are not
	// STS's; they have their own rules.
	var gotSpans []string
	for _, s := range spans.Ended() {
		if !strings.HasPrefix(s.Name(), "sts.") {
			continue
		}
		attrs := map[string]string{}
		for _, kv := range s.Attributes() {
			attrs[string(kv.Key)] = kv.Value.String()
		}
		op := strings.TrimPrefix(s.Name(), "sts.")
		if attrs["op"] != op {
			t.Errorf("span %s has op %q", s.Name(), attrs["op"])
		}
		result := attrs["result"]
		gotSpans = append(gotSpans, op+"/"+result)
		failed := s.Status().Code == codes.Error
		if failed != (result != "ok") || failed && s.Status().Description != result {
			t.Errorf("span %s/%s status %+v", op, result, s.Status())
		}
		if len(attrs) != 2 {
			t.Errorf("span %s carries %v, want op and result only", s.Name(), attrs)
		}
	}
	if !slices.Equal(gotSpans, wantSpans) {
		t.Errorf("spans\n%v\nwant\n%v", gotSpans, wantSpans)
	}

	// No recorded span of any package names a principal, ARN, session name,
	// key id, token, secret, MFA code or assertion.
	leaks := []string{
		"broker", "nobody", "auditor", "ghost", "deploy-1", "fedbob", "admin", "saml-dev", "alice@corp.test",
		"123456", "999999", "000000", adminARN, serial, goodSAML[:40], unknownKey,
		role.AccessKeyID, role.Secret, role.SessionToken, plain.Secret, plain.SessionToken,
		mfaToken.AccessKeyID, mfaToken.Secret, mfaToken.SessionToken, nobodyKey.AccessKeyID, nobodyKey.Secret,
		infoKey.AccessKeyID, infoKey.Secret, "keyowner", enc,
	}
	for i, s := range spans.Ended() {
		text := s.Name() + " " + s.Status().Description
		for _, kv := range s.Attributes() {
			text += " " + string(kv.Key) + "=" + kv.Value.String()
		}
		for _, ev := range s.Events() {
			text += " " + ev.Name
			for _, kv := range ev.Attributes {
				text += " " + string(kv.Key) + "=" + kv.Value.String()
			}
		}
		for _, x := range leaks {
			if x != "" && strings.Contains(text, x) {
				t.Errorf("span %d (%s) carries %q: %s", i, s.Name(), x, text)
			}
		}
	}
}

func TestSTSOutcomeLabelsEverySentinel(t *testing.T) {
	// The sentinel wins over the text of what it wraps: verifyMFA quotes an
	// MFA failure inside AccessDenied.
	if got := sts.Outcome(errors.Join(sts.ErrAccessDenied, store.ErrUnavailable)); got != "access_denied" {
		t.Errorf("access denied wrapping unavailable: %q", got)
	}
	for err, want := range map[error]string{
		nil:                                "ok",
		sts.ErrThrottling:                  "throttling",
		sts.ErrExpired:                     "expired",
		sts.ErrInvalidToken:                "invalid_token",
		sts.ErrNoSuchAccessKey:             "invalid_token",
		sts.ErrInvalidRequest:              "validation",
		sts.ErrAccessDenied:                "access_denied",
		sts.ErrInvalidIdentityToken:        "invalid_identity_token",
		sts.ErrIDPRejectedClaim:            "idp_rejected_claim",
		sts.ErrInvalidAuthorizationMessage: "invalid_authorization_message",
		sts.ErrPackedPolicyTooLarge:        "packed_policy_too_large",
		authz.ErrNoSuchEntity:              "no_such_entity",
		store.ErrNotFound:                  "not_found",
		store.ErrConflict:                  "conflict",
		store.ErrUnavailable:               "unavailable",
		context.Canceled:                   "canceled",
		context.DeadlineExceeded:           "deadline_exceeded",
		errors.New("anything else"):        "error",
	} {
		if got := sts.Outcome(err); got != want {
			t.Errorf("Outcome(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestSTSErrorsCarryContext(t *testing.T) {
	ctx := context.Background()
	e := obsSetup(t)
	svc := e.over(e.b, e.b)
	broker, auditor := e.caller(t, "broker"), e.caller(t, "auditor")
	enc, err := svc.EncodeAuthorizationMessage(sampleMessage())
	if err != nil {
		t.Fatal(err)
	}
	token, err := svc.GetSessionToken(ctx, broker, time.Hour, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	keyID := e.indexedKey(t).AccessKeyID
	unavailable := func(err error, want ...string) {
		t.Helper()
		if !errors.Is(err, store.ErrUnavailable) {
			t.Errorf("%v does not wrap ErrUnavailable", err)
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%q lacks %q", err, w)
			}
		}
	}
	// firstReads fails the nth read of kind for n = 1, 2, ... and returns
	// the errors, so each step that reads kind is named once.
	firstReads := func(kind iam.Kind, run func(*sts.Service) error) string {
		var all []string
		for n := int32(1); n <= 8; n++ {
			if err := run(e.over(nthRead(e.b, kind, n), e.b)); err != nil {
				unavailable(err)
				all = append(all, err.Error())
			}
		}
		return strings.Join(all, "\n")
	}
	requireAll := func(what, got string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: no error says %q:\n%s", what, w, got)
			}
		}
	}

	_, err = e.over(downKind(e.b, iam.KindRole, store.ErrUnavailable), e.b).
		AssumeRole(ctx, broker, nil, adminARN, "deploy-1", 0, "", sts.MFA{})
	unavailable(err, "get role: ")

	requireAll("AssumeRole", firstReads(iam.KindUser, func(s *sts.Service) error {
		_, err := s.AssumeRole(ctx, broker, nil, adminARN, "deploy-1", 0, "", sts.MFA{})
		return err
	}), "authorize sts:AssumeRole: ", "caller identity: ")

	requireAll("GetSessionToken", firstReads(iam.KindUser, func(s *sts.Service) error {
		_, err := s.GetSessionToken(ctx, broker, time.Hour, sts.MFA{})
		return err
	}), "caller identity: ", "revocation generation: ")

	_, err = e.over(downKind(e.b, iam.KindPolicy, store.ErrUnavailable), e.b).
		GetFederationToken(ctx, broker, nil, sts.FederationRequest{Name: "fedbob", PolicyARNs: []string{s3ReadARN}})
	unavailable(err, "check managed session policy: ")

	requireAll("GetFederationToken", firstReads(iam.KindUser, func(s *sts.Service) error {
		_, err := s.GetFederationToken(ctx, broker, nil, sts.FederationRequest{Name: "fedbob"})
		return err
	}), "authorize sts:GetFederationToken: ", "issue federation session: revocation generation: ")

	userDown := e.over(downKind(e.b, iam.KindUser, store.ErrUnavailable), e.b)
	_, err = userDown.Validate(ctx, token.AccessKeyID, token.SessionToken)
	unavailable(err, "session principal: ")

	_, err = userDown.GetAccessKeyInfo(ctx, auditor, nil, keyID)
	unavailable(err, "authorize sts:GetAccessKeyInfo: ")

	_, err = e.over(e.b, downKind(e.b, iam.KindKeyIndex, store.ErrUnavailable)).GetAccessKeyInfo(ctx, auditor, nil, keyID)
	unavailable(err, "look up access key: ")

	_, err = userDown.DecodeAuthorizationMessage(ctx, auditor, nil, enc)
	unavailable(err, "authorize sts:DecodeAuthorizationMessage: ")

	req := samlReq(e.response(t, e.claims(), samltest.SignAssertion))
	_, err = e.over(downKind(e.b, iam.KindRole, store.ErrUnavailable), e.b).AssumeRoleWithSAML(ctx, req)
	unavailable(err, "get role: ")

	req.PolicyARNs = []string{s3ReadARN}
	_, err = e.over(downKind(e.b, iam.KindPolicy, store.ErrUnavailable), e.b).AssumeRoleWithSAML(ctx, req)
	unavailable(err, "check managed session policy: ")

	svcBroken := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithSAML(failingProviders{}, samlSP))
	_, err = svcBroken.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
	unavailable(err, "get saml provider: ")

	// A client-facing message keeps its text: the sentinel and the same
	// words as before, with nothing added.
	_, err = svc.AssumeRole(ctx, broker, nil, adminARN, "x", 0, "", sts.MFA{})
	if !errors.Is(err, sts.ErrInvalidRequest) || err.Error() != `ValidationError: RoleSessionName "x"` {
		t.Errorf("validation message changed: %v", err)
	}
}

// failingProviders is a SAML provider store that is down.
type failingProviders struct{}

func (failingProviders) SAMLProvider(context.Context, string) (sts.SAMLProvider, error) {
	return sts.SAMLProvider{}, store.ErrUnavailable
}
