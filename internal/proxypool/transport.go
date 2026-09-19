package proxypool

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

// maxIdleConns bounds the number of idle keep-alive connections the single
// shared transport pools across ALL proxies combined. This is the other
// half of keeping roots' total connection footprint bounded: the
// LimitedRoundTripper caps ACTIVE requests, and this caps the IDLE
// connections left over between them — an idle socket still occupies a real
// NAT/conntrack entry on the router even though no request is using it right
// now. Kept small on purpose; the total live connection count is then
// roughly (active cap) + maxIdleConns, both bounded, instead of active +
// (one idle per distinct proxy) which — with a ~140-proxy pool — was the
// real cause of a network freeze the earlier per-proxy-transport design hit
// (peaked ~184 connections under a nominal 50-active cap, 2026-09-19).
const maxIdleConns = 20

// proxyCtxKey carries the per-request proxy assignment from RoundTrip to the
// shared transport's Proxy hook.
type proxyCtxKey struct{}

// RotatingTransport is an http.RoundTripper that routes each request through
// a different proxy chosen from a Pool, falling back to a direct connection
// whenever the pool has nothing healthy to offer. Wiring it into a single
// shared *http.Client (rather than threading proxy selection through every
// caller) means every existing call site — GetSTH, GetRawEntries, the
// shard-probe HEAD checks — gets request-level proxy rotation for free.
//
// Crucially it uses ONE underlying *http.Transport whose per-request Proxy
// hook consults the pool, NOT a separate transport per proxy. A separate
// transport per proxy gives each its own idle-connection pool, so the total
// idle count scales with the number of proxies (~140) and blows past any
// global connection budget — the single shared transport instead has ONE
// idle pool that MaxIdleConns bounds globally.
type RotatingTransport struct {
	pool   *Pool
	shared *http.Transport
	direct http.RoundTripper
}

// NewRotatingTransport returns a RotatingTransport drawing proxies from
// pool. If pool is nil, every request goes direct — this makes it safe to
// wire in unconditionally and only actually rotate once a harvest has
// populated the pool. limiter (may be nil) gates every dial — both the
// proxied path and the direct fallback — through one global connection cap.
func NewRotatingTransport(pool *Pool, limiter *ConnLimiter) *RotatingTransport {
	dial := limiter.Wrap(nil)
	t := &RotatingTransport{
		pool: pool,
		// Direct fallback honors the same dial cap as the proxied path, so a
		// pool that empties out mid-run doesn't quietly become an unbounded
		// direct crawl.
		direct: &http.Transport{
			DialContext:         dial,
			TLSHandshakeTimeout: 10 * time.Second,
			MaxIdleConns:        maxIdleConns,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}
	// TLSClientConfig is deliberately left at its default (nil = real system
	// CA verification, real hostname checking). For a CONNECT-tunneled HTTPS
	// request through an http:// proxy, this transport's TLS config governs
	// the handshake with the REAL destination (e.g. ct.googleapis.com), not
	// some separate "proxy TLS" layer — the proxy only ever sees opaque
	// tunneled bytes after the CONNECT. Skipping verification here would mean
	// a malicious or compromised free proxy could MITM the tunnel and hand
	// back forged CT log data with nothing to catch it — roots' own CT client
	// is constructed with an empty jsonclient.Options{} in main.go, so it
	// doesn't verify the log's STH signature either; real TLS is the only
	// integrity check left in the whole pipeline once a request goes through
	// a proxy. (validate()'s own InsecureSkipVerify is fine — it only probes
	// a fixed connectivity URL and never trusts that response's content.)
	t.shared = &http.Transport{
		Proxy:               t.proxyForRequest,
		DialContext:         dial,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return t
}

// proxyForRequest is the shared transport's Proxy hook: it returns the proxy
// this request was assigned by RoundTrip (stashed on the context), or nil
// (direct) if none. url.Parse failing on a malformed cached address returns
// (nil, err) here, which the transport surfaces as a request error —
// RoundTrip then reports that proxy as failed, exactly the right outcome.
func (t *RotatingTransport) proxyForRequest(req *http.Request) (*url.URL, error) {
	addr, _ := req.Context().Value(proxyCtxKey{}).(string)
	if addr == "" {
		return nil, nil
	}
	return url.Parse(addr)
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

	// WithContext returns a shallow copy carrying the assigned proxy — never
	// mutates the caller's request, honoring the RoundTripper contract.
	proxied := req.WithContext(context.WithValue(req.Context(), proxyCtxKey{}, addr))
	resp, err := t.shared.RoundTrip(proxied)
	// Only a transport-level failure (dial/handshake/timeout — never reached
	// the far side at all) reflects on the PROXY. Any actual HTTP response,
	// even a 4xx/5xx from the CT log itself, means the proxy did its job —
	// see Pool.Report's own doc comment for why this distinction matters.
	t.pool.Report(addr, err == nil)
	return resp, err
}
