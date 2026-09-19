package proxypool

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"
)

// ConnLimiter bounds the total number of live TCP connections roots holds
// open at once, globally, by gating every DIAL through one shared semaphore
// and holding each slot until that connection is closed.
//
// Dial-level (not request-level) limiting is what actually bounds the socket
// / NAT-entry count. An earlier request-level cap let the real connection
// count hit ~150-188 under a nominal 50 cap (2026-09-19), because it only saw
// crawl round-trips and missed three other real connection sources that every
// go through a Dial but never a crawl round-trip: idle keep-alive connections
// left pooled between requests, in-progress dials to dead proxies stuck in
// SYN-SENT for the dial timeout, and — the big one — the proxy harvest's own
// validation probes (up to validateConcurrency simultaneous dials, running at
// startup and on every refresh). One dial gate catches all of them.
type ConnLimiter struct {
	sem chan struct{}
}

// NewConnLimiter caps concurrent live connections at max (clamped to >= 1).
func NewConnLimiter(max int) *ConnLimiter {
	if max < 1 {
		max = 1
	}
	return &ConnLimiter{sem: make(chan struct{}, max)}
}

// DialFunc is the shape shared by net.Dialer.DialContext and
// http.Transport.DialContext.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Wrap returns a DialFunc that acquires a slot before dialing and releases it
// only when the returned connection is closed. base is the real dialer to
// use; if nil, a default dialer with a 10s timeout is used. A nil *ConnLimiter
// receiver returns base unchanged (no limiting) — convenient for tests and
// for a genuinely-unlimited mode.
func (c *ConnLimiter) Wrap(base DialFunc) DialFunc {
	if base == nil {
		base = (&net.Dialer{Timeout: 10 * time.Second}).DialContext
	}
	if c == nil {
		return base
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		select {
		case c.sem <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		conn, err := base(ctx, network, addr)
		if err != nil {
			<-c.sem // no socket to close — release immediately
			return nil, err
		}
		return &limitedConn{Conn: conn, release: func() { <-c.sem }}, nil
	}
}

// LimitedTransport builds an *http.Transport whose dials are gated by c, for
// the direct (no-proxy) path and the shard-prober — the same global cap the
// proxy-rotating transport uses, so total connections stay bounded in every
// mode.
func (c *ConnLimiter) LimitedTransport() *http.Transport {
	return &http.Transport{
		DialContext:         c.Wrap(nil),
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
