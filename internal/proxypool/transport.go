package proxypool

import (
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// RotatingTransport is an http.RoundTripper that hands each request to a
// different proxy chosen from a Pool, falling back to a direct connection
// whenever the pool has nothing healthy to offer. Wrapping this into a
// single shared *http.Client (rather than threading proxy selection through
// every caller) means every existing call site — GetSTH, GetRawEntries, the
// shard-probe HEAD checks — gets request-level proxy rotation for free,
// with no change to their own code.
type RotatingTransport struct {
	pool *Pool

	direct http.RoundTripper

	mu      sync.Mutex
	perAddr map[string]http.RoundTripper
}

// NewRotatingTransport returns a RotatingTransport drawing proxies from
// pool. If pool is nil, every request goes direct — this makes it safe to
// wire in unconditionally and only actually rotate once a harvest has
// populated the pool.
func NewRotatingTransport(pool *Pool) *RotatingTransport {
	return &RotatingTransport{
		pool:    pool,
		direct:  http.DefaultTransport,
		perAddr: make(map[string]http.RoundTripper),
	}
}

// RoundTrip implements http.RoundTripper.
func (t *RotatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.pool == nil {
		return t.direct.RoundTrip(req)
	}

	addr := t.pool.Next()
	if addr == "" {
		return t.direct.RoundTrip(req)
	}

	resp, err := t.transportFor(addr).RoundTrip(req)
	// Only a transport-level failure (dial/handshake/timeout — never
	// reached the far side at all) reflects on the PROXY. Any actual HTTP
	// response, even a 4xx/5xx from the CT log itself, means the proxy did
	// its job correctly — see Pool.Report's own doc comment for why this
	// distinction matters.
	t.pool.Report(addr, err == nil)
	return resp, err
}

// transportFor returns the cached *http.Transport for proxyAddr, creating
// one on first use so repeated selections of the same proxy (inevitable
// once the pool shrinks to whatever's still healthy) reuse its connections
// instead of paying a fresh TLS handshake every single request.
func (t *RotatingTransport) transportFor(proxyAddr string) http.RoundTripper {
	t.mu.Lock()
	defer t.mu.Unlock()
	if rt, ok := t.perAddr[proxyAddr]; ok {
		return rt
	}

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		// Malformed cached address — fall back to direct for this one
		// request rather than erroring the whole crawl over it.
		return t.direct
	}

	// TLSClientConfig is deliberately left at its default (nil = real system
	// CA verification, real hostname checking). For a CONNECT-tunneled HTTPS
	// request through an http:// proxy, this transport's TLS config governs
	// the handshake with the REAL destination (e.g. ct.googleapis.com), not
	// some separate "proxy TLS" layer — the proxy only ever sees opaque
	// tunneled bytes after the CONNECT. Skipping verification here (an
	// earlier version of this code did, copied from harvest.go's own
	// validate() without checking whether the same reasoning actually
	// applied) would mean a malicious or compromised free proxy could MITM
	// the tunnel and hand back forged CT log data with nothing to catch it —
	// roots' own CT client is constructed with an empty jsonclient.Options{}
	// in main.go, so it doesn't verify the log's STH signature either; real
	// TLS is the only integrity check left in the whole pipeline once a
	// request goes through a proxy. validate()'s own InsecureSkipVerify is
	// fine specifically because it only ever probes a fixed, known
	// connectivity-check URL to decide if a proxy is usable at all — it
	// never trusts that response's content for anything, unlike every
	// request this transport carries.
	rt := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	t.perAddr[proxyAddr] = rt
	return rt
}
