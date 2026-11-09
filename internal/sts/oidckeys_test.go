package sts_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // an OIDC thumbprint is a SHA-1
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"

	"github.com/popododo0720/vws-iam/internal/sts"
)

const (
	idpIssuer = "https://idp.test"
	idpJWKS   = `{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"AA","y":"AA"}]}`
)

type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial atomic.Int64

// issue makes a certificate for hosts signed by parent, or a self-signed
// one when parent is nil; ca makes it a CA.
func issue(t *testing.T, parent *pki, ca bool, hosts ...string) *pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial.Add(1)),
		Subject:               pkix.Name{CommonName: "vws test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              hosts,
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{cert: cert, key: key}
}

func thumbprint(c *x509.Certificate) string {
	sum := sha1.Sum(c.Raw) //nolint:gosec // see the import
	return hex.EncodeToString(sum[:])
}

// idp is a local TLS OpenID Connect provider for https://idp.test.
type idp struct {
	srv       *httptest.Server
	ca, leaf  *pki
	conns     atomic.Int64
	discovery atomic.Int64
	keys      atomic.Int64
	// serve, when set, answers a request instead of the defaults; it
	// returns false to fall through to them.
	serve atomic.Pointer[func(w http.ResponseWriter, r *http.Request) bool]
}

// newIdP serves the chain leaf, CA unless chain says otherwise.
func newIdP(t *testing.T, chain func(ca, leaf *pki) []*pki) *idp {
	t.Helper()
	p := &idp{}
	p.ca = issue(t, nil, true)
	p.leaf = issue(t, p.ca, false, "idp.test")
	served := []*pki{p.leaf, p.ca}
	if chain != nil {
		served = chain(p.ca, p.leaf)
	}
	tc := tls.Certificate{PrivateKey: served[0].key}
	for _, c := range served {
		tc.Certificate = append(tc.Certificate, c.cert.Raw)
	}
	p.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			p.discovery.Add(1)
		case "/keys":
			p.keys.Add(1)
		}
		if fn := p.serve.Load(); fn != nil && (*fn)(w, r) {
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			write(w, `{"issuer":"`+idpIssuer+`","jwks_uri":"`+idpIssuer+`/keys"}`)
		case "/keys":
			write(w, idpJWKS)
		default:
			http.NotFound(w, r)
		}
	}))
	p.srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			p.conns.Add(1)
		}
	}
	p.srv.TLS = &tls.Config{Certificates: []tls.Certificate{tc}, MinVersion: tls.VersionTLS12}
	p.srv.StartTLS()
	t.Cleanup(p.srv.Close)
	return p
}

// write answers body; a client that hung up is the test's business.
func write(w http.ResponseWriter, body string) {
	if _, err := io.WriteString(w, body); err != nil {
		return
	}
}

func (p *idp) handle(fn func(w http.ResponseWriter, r *http.Request) bool) { p.serve.Store(&fn) }

// lockedClock is a clock the fetch goroutine reads while the test moves it.
type lockedClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *lockedClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *lockedClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func (p *idp) fetcher(roots *x509.CertPool, clk *lockedClock, timeout time.Duration) *sts.OIDCKeyFetcher {
	if clk == nil {
		clk = &lockedClock{t: time.Now()}
	}
	return sts.NewOIDCKeyFetcherForTest(roots, p.srv.Listener.Addr().String(), clk.now, timeout)
}

func wantIDPCommunication(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, sts.ErrIDPCommunication) {
		t.Fatalf("%s: %v, want ErrIDPCommunication", what, err)
	}
}

// TestOIDCKeysThumbprint: a certificate outside the trusted roots is
// accepted only when the last certificate served matches a thumbprint
// (any case) and the leaf chains to it for the host; a trusted chain needs
// no thumbprint. A refused certificate reads nothing and is not retried.
func TestOIDCKeysThumbprint(t *testing.T) {
	ctx := context.Background()
	p := newIdP(t, nil)
	f := p.fetcher(nil, nil, time.Second)

	doc, err := f.JWKS(ctx, idpIssuer, []string{strings.Repeat("0", 40), strings.ToUpper(thumbprint(p.ca.cert))})
	if err != nil || string(doc) != idpJWKS {
		t.Fatalf("pinned CA: %q, %v", doc, err)
	}

	conns := p.conns.Load()
	_, err = p.fetcher(nil, nil, time.Second).JWKS(ctx, idpIssuer, []string{thumbprint(p.leaf.cert)})
	wantIDPCommunication(t, "thumbprint of the leaf, not the last certificate", err)
	_, err = p.fetcher(nil, nil, time.Second).JWKS(ctx, idpIssuer, nil)
	wantIDPCommunication(t, "untrusted, no thumbprint", err)
	_, err = p.fetcher(nil, nil, time.Second).JWKS(ctx, "https://other.test", []string{thumbprint(p.ca.cert)})
	wantIDPCommunication(t, "pinned CA, certificate for another host", err)
	if n := p.discovery.Load() + p.keys.Load(); n != 2 {
		t.Fatalf("%d requests, want 2 (only the pinned fetch)", n)
	}
	if n := p.conns.Load() - conns; n != 3 {
		t.Fatalf("%d connections for 3 refused fetches, want 3 (a refused certificate is not retried)", n)
	}

	roots := x509.NewCertPool()
	roots.AddCert(p.ca.cert)
	if _, err := p.fetcher(roots, nil, time.Second).JWKS(ctx, idpIssuer, nil); err != nil {
		t.Fatalf("trusted root, no thumbprint: %v", err)
	}
	if _, err := p.fetcher(roots, nil, time.Second).JWKS(ctx, idpIssuer, []string{strings.Repeat("a", 40)}); err != nil {
		t.Fatalf("trusted root, other thumbprint: %v", err)
	}
}

// TestOIDCKeysSelfSignedLeaf: a server that presents only a self-signed
// certificate is pinned by that certificate's thumbprint.
func TestOIDCKeysSelfSignedLeaf(t *testing.T) {
	var self *pki
	p := newIdP(t, func(_, _ *pki) []*pki {
		self = issue(t, nil, false, "idp.test")
		return []*pki{self}
	})
	f := p.fetcher(nil, nil, time.Second)
	if _, err := f.JWKS(context.Background(), idpIssuer, []string{thumbprint(self.cert)}); err != nil {
		t.Fatalf("self-signed leaf pinned: %v", err)
	}
}

// TestOIDCKeysOtherHosts: the JWKS may live on another host than the
// issuer when the certificate names it; a pinned last certificate does not
// vouch for a leaf it did not sign or for a host the leaf does not name; an
// IP-literal issuer is refused before any connection.
func TestOIDCKeysOtherHosts(t *testing.T) {
	ctx := context.Background()
	keysHost := func(p *idp) {
		p.handle(func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != "/.well-known/openid-configuration" {
				return false
			}
			write(w, `{"issuer":"`+idpIssuer+`","jwks_uri":"https://keys.test/keys"}`)
			return true
		})
	}

	both := newIdP(t, func(ca, _ *pki) []*pki { return []*pki{issue(t, ca, false, "idp.test", "keys.test"), ca} })
	keysHost(both)
	if _, err := both.fetcher(nil, nil, time.Second).JWKS(ctx, idpIssuer, []string{thumbprint(both.ca.cert)}); err != nil {
		t.Fatalf("jwks_uri on a host the certificate names: %v", err)
	}

	issuerOnly := newIdP(t, nil)
	keysHost(issuerOnly)
	_, err := issuerOnly.fetcher(nil, nil, time.Second).JWKS(ctx, idpIssuer, []string{thumbprint(issuerOnly.ca.cert)})
	wantIDPCommunication(t, "jwks_uri on a host the certificate does not name", err)
	if n := issuerOnly.keys.Load(); n != 0 {
		t.Fatalf("%d JWKS requests to a host the certificate does not name", n)
	}

	unrelated := newIdP(t, func(ca, _ *pki) []*pki {
		other := issue(t, nil, true)
		return []*pki{issue(t, other, false, "idp.test"), ca}
	})
	_, err = unrelated.fetcher(nil, nil, time.Second).JWKS(ctx, idpIssuer, []string{thumbprint(unrelated.ca.cert)})
	wantIDPCommunication(t, "leaf of another CA followed by the pinned certificate", err)

	p := newIdP(t, nil)
	for _, issuer := range []string{"https://127.0.0.1", "https://[::1]", "http://idp.test"} {
		_, err := p.fetcher(nil, nil, time.Second).JWKS(ctx, issuer, []string{thumbprint(p.ca.cert)})
		wantIDPCommunication(t, issuer, err)
	}
	if n := p.conns.Load(); n != 0 {
		t.Fatalf("%d connections for refused issuers", n)
	}
}

// TestOIDCKeysReturnsACopy: a caller that changes the document it got does
// not change what the next caller gets from the cache.
func TestOIDCKeysReturnsACopy(t *testing.T) {
	p := newIdP(t, nil)
	f := p.fetcher(nil, nil, time.Second)
	pin := []string{thumbprint(p.ca.cert)}
	for range 2 {
		doc, err := f.JWKS(context.Background(), idpIssuer, pin)
		if err != nil || string(doc) != idpJWKS {
			t.Fatalf("%q, %v", doc, err)
		}
		clear(doc)
	}
	if n := p.keys.Load(); n != 1 {
		t.Fatalf("%d JWKS requests, want 1", n)
	}
}

// TestOIDCKeysTimeoutCoversTheWholeFetch: the timeout is one budget for
// discovery and the JWKS together, not one per request.
func TestOIDCKeysTimeoutCoversTheWholeFetch(t *testing.T) {
	if sts.OIDCFetchTimeout != 5*time.Second {
		t.Fatalf("OIDCFetchTimeout %v, want 5s", sts.OIDCFetchTimeout)
	}
	p := newIdP(t, nil)
	p.handle(func(_ http.ResponseWriter, r *http.Request) bool {
		select {
		case <-r.Context().Done():
		case <-time.After(250 * time.Millisecond):
		}
		return false
	})
	begin := time.Now()
	f := p.fetcher(nil, nil, 400*time.Millisecond)
	_, err := f.JWKS(context.Background(), idpIssuer, []string{thumbprint(p.ca.cert)})
	wantIDPCommunication(t, "discovery and JWKS each under, together over the timeout", err)
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("gave up after %v, want about 400ms", d)
	}
	if n := p.keys.Load(); n != 1 {
		t.Fatalf("%d JWKS requests, want 1 (the budget ran out during it)", n)
	}
}

// TestOIDCKeysTimeout: an IdP that does not answer is ErrIDPCommunication
// within the fetch timeout.
func TestOIDCKeysTimeout(t *testing.T) {
	p := newIdP(t, nil)
	p.handle(func(_ http.ResponseWriter, r *http.Request) bool {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		return true
	})
	begin := time.Now()
	f := p.fetcher(nil, nil, 300*time.Millisecond)
	_, err := f.JWKS(context.Background(), idpIssuer, []string{thumbprint(p.ca.cert)})
	wantIDPCommunication(t, "silent IdP", err)
	if d := time.Since(begin); d > 2*time.Second {
		t.Fatalf("gave up after %v, want about 300ms", d)
	}
}

// TestOIDCKeysRetry: a 5xx or 429 is retried up to three attempts, any
// other status is not.
func TestOIDCKeysRetry(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		statuses []int
		ok       bool
		attempts int64
	}{
		{"503 then 200", []int{503, 503}, true, 3},
		{"429 then 200", []int{429}, true, 2},
		{"503 always", []int{503, 503, 503, 503}, false, 3},
		{"404", []int{404}, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIdP(t, nil)
			var n atomic.Int64
			p.handle(func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/.well-known/openid-configuration" {
					return false
				}
				if i := int(n.Add(1)) - 1; i < len(tc.statuses) {
					w.WriteHeader(tc.statuses[i])
					return true
				}
				return false
			})
			_, err := p.fetcher(nil, nil, 5*time.Second).JWKS(ctx, idpIssuer, []string{thumbprint(p.ca.cert)})
			if tc.ok && err != nil {
				t.Fatal(err)
			}
			if !tc.ok {
				wantIDPCommunication(t, tc.name, err)
			}
			if got := p.discovery.Load(); got != tc.attempts {
				t.Fatalf("%d attempts, want %d", got, tc.attempts)
			}
		})
	}
}

// TestOIDCKeysCache: keys are fetched once per issuer and thumbprint list
// (order and case do not matter) until OIDCKeyCacheTTL passes; a failure
// is not cached; a new fetcher (a restart) starts empty.
func TestOIDCKeysCache(t *testing.T) {
	ctx := context.Background()
	p := newIdP(t, nil)
	clk := &lockedClock{t: time.Now()}
	f := p.fetcher(nil, clk, time.Second)
	pin, other := thumbprint(p.ca.cert), strings.Repeat("b", 40)
	fetch := func(pins ...string) {
		t.Helper()
		if _, err := f.JWKS(ctx, idpIssuer, pins); err != nil {
			t.Fatal(err)
		}
	}
	want := func(n int64) {
		t.Helper()
		if d, k := p.discovery.Load(), p.keys.Load(); d != n || k != n {
			t.Fatalf("discovery %d, keys %d, want %d each", d, k, n)
		}
	}
	fetch(pin, other)
	fetch(strings.ToUpper(other), pin, pin)
	want(1)
	fetch(pin)
	want(2)
	clk.add(sts.OIDCKeyCacheTTL - time.Second)
	fetch(pin)
	want(2)
	clk.add(time.Second)
	fetch(pin)
	want(3)

	var fail atomic.Bool
	fail.Store(true)
	p.handle(func(w http.ResponseWriter, r *http.Request) bool {
		if fail.Load() && r.URL.Path == "/keys" {
			http.NotFound(w, r)
			return true
		}
		return false
	})
	clk.add(sts.OIDCKeyCacheTTL)
	_, err := f.JWKS(ctx, idpIssuer, []string{pin})
	wantIDPCommunication(t, "keys gone", err)
	fail.Store(false)
	fetch(pin)
	want(5)

	if _, err := p.fetcher(nil, clk, time.Second).JWKS(ctx, idpIssuer, []string{pin}); err != nil {
		t.Fatal(err)
	}
	want(6)
}

// TestOIDCKeysConcurrent: concurrent fetches of one provider make one
// request, and a caller that gives up does not fail the others.
func TestOIDCKeysConcurrent(t *testing.T) {
	p := newIdP(t, nil)
	release := make(chan struct{})
	p.handle(func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/keys" {
			<-release
		}
		return false
	})
	f := p.fetcher(nil, nil, 5*time.Second)
	pin := []string{thumbprint(p.ca.cert)}

	canceled, cancel := context.WithCancel(context.Background())
	gaveUp := make(chan error, 1)
	go func() {
		_, err := f.JWKS(canceled, idpIssuer, pin)
		gaveUp <- err
	}()
	for p.keys.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			doc, err := f.JWKS(context.Background(), idpIssuer, pin)
			if err == nil && string(doc) != idpJWKS {
				err = errors.New("wrong document " + string(doc))
			}
			errs <- err
		}()
	}
	cancel()
	if err := <-gaveUp; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled caller: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if d, k := p.discovery.Load(), p.keys.Load(); d != 1 || k != 1 {
		t.Fatalf("discovery %d, keys %d, want 1 each", d, k)
	}
}

// TestOIDCKeysHostileIdP: documents that are not discovery metadata or a
// key set, a redirect, an over-long body and an unreachable IdP are all
// ErrIDPCommunication, and none is cached.
func TestOIDCKeysHostileIdP(t *testing.T) {
	const disc = "/.well-known/openid-configuration"
	meta := func(issuer, jwksURI string) string {
		return `{"issuer":"` + issuer + `","jwks_uri":"` + jwksURI + `"}`
	}
	big := `{"keys":[` + strings.Repeat(" ", sts.MaxOIDCDocumentBytes) + `]}`
	for _, tc := range []struct {
		name, path, body string
		status           int
		location         string
	}{
		{name: "another issuer", path: disc, body: meta("https://evil.test", idpIssuer+"/keys")},
		{name: "issuer with a trailing slash", path: disc, body: meta(idpIssuer+"/", idpIssuer+"/keys")},
		{name: "plain http jwks_uri", path: disc, body: meta(idpIssuer, "http://idp.test/keys")},
		{name: "IPv4 jwks_uri", path: disc, body: meta(idpIssuer, "https://127.0.0.1/keys")},
		{name: "IPv6 jwks_uri", path: disc, body: meta(idpIssuer, "https://[::1]/keys")},
		{name: "jwks_uri with user info", path: disc, body: meta(idpIssuer, "https://u:p@idp.test/keys")},
		{name: "no jwks_uri", path: disc, body: `{"issuer":"https://idp.test"}`},
		{name: "discovery not JSON", path: disc, body: `<html>`},
		{name: "jwks without keys", path: "/keys", body: `{}`},
		{name: "jwks not JSON", path: "/keys", body: `keys`},
		{name: "jwks over the size limit", path: "/keys", body: big},
		{name: "redirect", path: disc, status: http.StatusFound, location: idpIssuer + "/keys"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newIdP(t, nil)
			p.handle(func(w http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != tc.path {
					return false
				}
				if tc.location != "" {
					w.Header().Set("Location", tc.location)
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				write(w, tc.body)
				return true
			})
			f := p.fetcher(nil, nil, 5*time.Second)
			pin := []string{thumbprint(p.ca.cert)}
			_, err := f.JWKS(context.Background(), idpIssuer, pin)
			wantIDPCommunication(t, tc.name, err)
			p.handle(func(http.ResponseWriter, *http.Request) bool { return false })
			if _, err := f.JWKS(context.Background(), idpIssuer, pin); err != nil {
				t.Fatalf("after the IdP recovers: %v", err)
			}
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		var lc net.ListenConfig
		l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		f := sts.NewOIDCKeyFetcherForTest(nil, addr, time.Now, time.Second)
		_, err = f.JWKS(context.Background(), idpIssuer, nil)
		wantIDPCommunication(t, "closed port", err)
	})
}

// TestOIDCKeysAreMeasuredAndTraced: a fetch is one span sts.FetchOIDCKeys
// and one counter and latency point by op and result; a failure marks the
// span failed with the result, never the issuer.
func TestOIDCKeysAreMeasuredAndTraced(t *testing.T) {
	p := newIdP(t, nil)
	f := p.fetcher(nil, nil, time.Second)
	spans.Reset()
	ops0, durs0 := points(t)
	if _, err := f.JWKS(context.Background(), idpIssuer, []string{thumbprint(p.ca.cert)}); err != nil {
		t.Fatal(err)
	}
	_, err := f.JWKS(context.Background(), idpIssuer, nil)
	wantIDPCommunication(t, "no thumbprint", err)
	ops1, durs1 := points(t)
	want := map[string]int64{"FetchOIDCKeys/ok": 1, "FetchOIDCKeys/idp_communication": 1}
	sameCounts(t, "operations", changed(ops0, ops1), want)
	sameCounts(t, "duration points", changed(durs0, durs1), want)
	failed := 0
	for _, s := range spans.Ended() {
		if s.Name() != "sts.FetchOIDCKeys" {
			continue
		}
		if s.Status().Code == codes.Error {
			failed++
			if s.Status().Description != "idp_communication" {
				t.Errorf("span status %q", s.Status().Description)
			}
		}
		for _, kv := range s.Attributes() {
			if strings.Contains(kv.Value.String(), "idp.test") {
				t.Errorf("span attribute %s carries the issuer", kv.Key)
			}
		}
	}
	if failed != 1 {
		t.Fatalf("%d failed spans, want 1", failed)
	}
}
