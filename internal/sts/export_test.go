package sts

import (
	"context"
	"crypto/x509"
	"net"
	"time"
)

// NewOIDCKeyFetcherForTest returns a fetcher that trusts roots (none when
// nil), dials addr whatever host a URL names, reads the clock now and gives
// up after timeout.
func NewOIDCKeyFetcherForTest(
	roots *x509.CertPool, addr string, now func() time.Time, timeout time.Duration,
) *OIDCKeyFetcher {
	f := NewOIDCKeyFetcher()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	f.roots = roots
	d := &net.Dialer{Timeout: oidcStepTimeout}
	f.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
	f.now = now
	f.timeout = timeout
	return f
}
