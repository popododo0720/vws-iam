package sts

import (
	"context"
	"crypto/sha1" //nolint:gosec // AWS defines an OIDC thumbprint as the SHA-1 of a certificate
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ErrIDPCommunication is an OIDC provider whose keys cannot be read (AWS
// IDPCommunicationError): the IdP cannot be reached, answers late or with
// an error, serves a certificate that is neither trusted nor pinned by a
// thumbprint, or serves a document that is not OpenID Connect discovery
// metadata or a JSON Web Key Set.
var ErrIDPCommunication = errors.New("IDPCommunicationError")

// errUntrustedIdP is a server certificate the fetcher refuses; a retry
// would meet the same certificate, so it is not retried.
var errUntrustedIdP = errors.New("untrusted IdP certificate")

// Bounds of an OIDC key fetch.
const (
	// OIDCFetchTimeout bounds one fetch of the discovery document and the
	// JWKS together, retries included.
	OIDCFetchTimeout = 5 * time.Second
	// OIDCKeyCacheTTL is how long fetched keys are served before they are
	// fetched again.
	OIDCKeyCacheTTL = 10 * time.Minute
	// MaxOIDCDocumentBytes bounds the discovery document and the JWKS.
	MaxOIDCDocumentBytes = 1 << 20

	oidcFetchAttempts   = 3
	oidcRetryDelay      = 100 * time.Millisecond
	oidcStepTimeout     = 3 * time.Second
	maxOIDCCacheEntries = 1024
)

// OIDCKeyFetcher reads the JSON Web Key Set of an OpenID Connect provider:
// it fetches <issuer>/.well-known/openid-configuration, then its jwks_uri,
// both over TLS 1.2 or later. A server certificate is accepted when it
// chains to a trusted root for the host, or, as AWS documents for an IdP
// outside its trusted CAs, when the SHA-1 of the last certificate the
// server presents matches one of the provider's thumbprints and the leaf
// chains to that certificate for the host. Documents are cached for
// OIDCKeyCacheTTL per issuer and thumbprint list; failures are not cached,
// and concurrent fetches of one provider share one request. It is safe
// for concurrent use; the zero value is not, use NewOIDCKeyFetcher.
type OIDCKeyFetcher struct {
	roots   *x509.CertPool // nil: the system roots
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	now     func() time.Time
	timeout time.Duration

	mu       sync.Mutex
	cache    map[string]cachedJWKS
	inflight map[string]*jwksFetch
}

type cachedJWKS struct {
	doc     []byte
	expires time.Time
}

type jwksFetch struct {
	done chan struct{}
	doc  []byte
	err  error
}

// NewOIDCKeyFetcher returns a fetcher that trusts the system roots.
func NewOIDCKeyFetcher() *OIDCKeyFetcher {
	d := &net.Dialer{Timeout: oidcStepTimeout}
	return &OIDCKeyFetcher{
		dial:     d.DialContext,
		now:      time.Now,
		timeout:  OIDCFetchTimeout,
		cache:    map[string]cachedJWKS{},
		inflight: map[string]*jwksFetch{},
	}
}

// JWKS returns the JSON Web Key Set document of the provider with issuer
// URL issuer and the given thumbprints (40 hex digits each, any case).
// Any failure to read it is
// ErrIDPCommunication; a caller whose ctx ends first gets ctx's error.
func (f *OIDCKeyFetcher) JWKS(ctx context.Context, issuer string, thumbprints []string) (doc []byte, err error) {
	ctx, end := start(ctx, "FetchOIDCKeys")
	defer end(&err)
	pins := normalizeThumbprints(thumbprints)
	key := issuer + "\x00" + strings.Join(pins, ",")

	f.mu.Lock()
	if c, ok := f.cache[key]; ok && f.now().Before(c.expires) {
		f.mu.Unlock()
		trace.SpanFromContext(ctx).SetAttributes(attribute.Bool("cache_hit", true))
		return slices.Clone(c.doc), nil
	}
	fl, running := f.inflight[key]
	if !running {
		fl = &jwksFetch{done: make(chan struct{})}
		f.inflight[key] = fl
		// The fetch outlives a caller that gives up, so one caller's
		// cancel never fails the others; f.timeout still bounds it.
		go f.run(context.WithoutCancel(ctx), key, issuer, pins, fl)
	}
	f.mu.Unlock()
	trace.SpanFromContext(ctx).SetAttributes(attribute.Bool("cache_hit", false))

	select {
	case <-fl.done:
		return slices.Clone(fl.doc), fl.err
	case <-ctx.Done():
		return nil, fmt.Errorf("fetch OIDC keys: %w", context.Cause(ctx))
	}
}

func (f *OIDCKeyFetcher) run(ctx context.Context, key, issuer string, pins []string, fl *jwksFetch) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	fl.doc, fl.err = f.fetch(ctx, issuer, pins)
	f.mu.Lock()
	delete(f.inflight, key)
	if fl.err == nil {
		f.store(key, fl.doc)
	}
	f.mu.Unlock()
	close(fl.done)
}

// store caches doc under key; f.mu is held. A full cache drops expired
// entries, then the one closest to expiry.
func (f *OIDCKeyFetcher) store(key string, doc []byte) {
	now := f.now()
	if _, ok := f.cache[key]; !ok && len(f.cache) >= maxOIDCCacheEntries {
		var oldest string
		for k, c := range f.cache {
			if !now.Before(c.expires) {
				delete(f.cache, k)
			} else if oldest == "" || c.expires.Before(f.cache[oldest].expires) {
				oldest = k
			}
		}
		if len(f.cache) >= maxOIDCCacheEntries {
			delete(f.cache, oldest)
		}
	}
	f.cache[key] = cachedJWKS{doc: doc, expires: now.Add(OIDCKeyCacheTTL)}
}

func (f *OIDCKeyFetcher) fetch(ctx context.Context, issuer string, pins []string) ([]byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:           f.dial,
			TLSClientConfig:       f.tlsConfig(pins),
			TLSHandshakeTimeout:   oidcStepTimeout,
			ResponseHeaderTimeout: oidcStepTimeout,
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   1,
		},
		// A redirect could leave the issuer's host; OpenID Connect
		// discovery does not need one.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()

	if !dnsHost(issuer) {
		return nil, fmt.Errorf("%w: issuer is not an https URL with a DNS host", ErrIDPCommunication)
	}
	disc, err := f.get(ctx, client, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("%w: openid-configuration: %w", ErrIDPCommunication, err)
	}
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(disc, &meta); err != nil {
		return nil, fmt.Errorf("%w: openid-configuration is not JSON", ErrIDPCommunication)
	}
	if meta.Issuer != issuer {
		return nil, fmt.Errorf("%w: openid-configuration names another issuer", ErrIDPCommunication)
	}
	if !dnsHost(meta.JWKSURI) {
		return nil, fmt.Errorf("%w: jwks_uri is not an https URL with a DNS host", ErrIDPCommunication)
	}
	doc, err := f.get(ctx, client, meta.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("%w: jwks: %w", ErrIDPCommunication, err)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil || set.Keys == nil {
		return nil, fmt.Errorf("%w: jwks is not a JSON Web Key Set", ErrIDPCommunication)
	}
	return doc, nil
}

// dnsHost reports whether raw is an https URL without user info whose host
// is a name, not an IP literal: TLS sends no server name for an IP, and
// the certificate check matches the leaf against that name.
func dnsHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	h := u.Hostname()
	return h != "" && net.ParseIP(h) == nil
}

// get reads target, retrying a failed connection, a 429 and a 5xx up to
// oidcFetchAttempts times with a doubling delay while ctx lives.
func (f *OIDCKeyFetcher) get(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	delay := oidcRetryDelay
	for attempt := 1; ; attempt++ {
		body, retry, err := getOnce(ctx, client, target)
		if err == nil || !retry || attempt == oidcFetchAttempts {
			return body, err
		}
		select {
		case <-time.After(delay):
			delay *= 2
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (after %w)", context.Cause(ctx), err)
		}
	}
}

func getOnce(ctx context.Context, client *http.Client, target string) (body []byte, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, false, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, ctx.Err() == nil && !errors.Is(err, errUntrustedIdP), fmt.Errorf("get: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			body, retry, err = nil, true, fmt.Errorf("close body: %w", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		transient := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return nil, transient, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, MaxOIDCDocumentBytes+1))
	if err != nil {
		return nil, ctx.Err() == nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > MaxOIDCDocumentBytes {
		return nil, false, fmt.Errorf("body over %d bytes", MaxOIDCDocumentBytes)
	}
	return body, false, nil
}

// tlsConfig checks the server certificate itself (VerifyConnection), so
// that a thumbprint can pin a CA the roots do not hold.
func (f *OIDCKeyFetcher) tlsConfig(pins []string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection checks the chain and host
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyIdPCertificate(cs, f.roots, pins)
		},
	}
}

func verifyIdPCertificate(cs tls.ConnectionState, roots *x509.CertPool, pins []string) error {
	if cs.ServerName == "" {
		// An empty DNSName would make x509 skip the host check.
		return fmt.Errorf("%w: no server name to check", errUntrustedIdP)
	}
	certs := cs.PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("%w: none presented", errUntrustedIdP)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{DNSName: cs.ServerName, Roots: roots, Intermediates: inter}
	if _, err := certs[0].Verify(opts); err == nil {
		return nil
	}
	last := certs[len(certs)-1]
	sum := sha1.Sum(last.Raw) //nolint:gosec // see the import
	if !slices.Contains(pins, hex.EncodeToString(sum[:])) {
		return fmt.Errorf("%w: not trusted and matches no thumbprint", errUntrustedIdP)
	}
	pinned := x509.NewCertPool()
	pinned.AddCert(last)
	opts.Roots = pinned
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("%w: does not chain to its thumbprint for %s: %w", errUntrustedIdP, cs.ServerName, err)
	}
	return nil
}

// normalizeThumbprints lower-cases, sorts and deduplicates, so the cache
// key does not depend on order or case.
func normalizeThumbprints(tps []string) []string {
	out := make([]string, 0, len(tps))
	for _, tp := range tps {
		out = append(out, strings.ToLower(tp))
	}
	slices.Sort(out)
	return slices.Compact(out)
}
