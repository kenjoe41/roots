package proxypool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRotatingTransport_NilPoolGoesDirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	rt := NewRotatingTransport(nil, nil)
	client := &http.Client{Transport: rt}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestRotatingTransport_EmptyPoolGoesDirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	rt := NewRotatingTransport(New(), nil) // pool with zero proxies harvested
	client := &http.Client{Transport: rt}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestRotatingTransport_MalformedProxyAddrErrorsAndReportsFailure(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	pool := New()
	pool.proxies = []string{"://not-a-valid-url"}
	rt := NewRotatingTransport(pool, nil)
	// Single-request transport (no retryablehttp wrapper) so the raw error
	// from a malformed proxy surfaces directly rather than being retried away.
	client := &http.Client{Transport: rt}

	_, err := client.Get(target.URL)
	if err == nil {
		t.Fatal("expected an error when the selected proxy address is malformed")
	}
	// The bad proxy must have been reported as failed so health scoring can
	// eventually exclude/prune it — the whole point of not silently ignoring it.
	if s := pool.health.scoreOf("://not-a-valid-url"); s >= 0.5 {
		t.Errorf("expected the malformed proxy's health to drop after a failure, got %f", s)
	}
}

func TestProxyForRequest_ReadsAssignedProxyFromContext(t *testing.T) {
	rt := NewRotatingTransport(New(), nil)

	// No assignment on the context → direct (nil URL, nil error).
	plain, _ := http.NewRequest("GET", "http://example.invalid", nil)
	if u, err := rt.proxyForRequest(plain); u != nil || err != nil {
		t.Errorf("no-assignment request: got (%v, %v), want (nil, nil)", u, err)
	}

	// With an assignment → that proxy URL.
	ctx := context.WithValue(context.Background(), proxyCtxKey{}, "http://1.2.3.4:8080")
	assigned := plain.WithContext(ctx)
	u, err := rt.proxyForRequest(assigned)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u == nil || u.Host != "1.2.3.4:8080" {
		t.Errorf("proxyForRequest = %v, want http://1.2.3.4:8080", u)
	}
}

func TestRotatingTransport_UsesOneSharedTransport(t *testing.T) {
	// Regression guard for the network-freeze fix: there must be exactly one
	// underlying transport (one global idle-connection pool), not one per
	// proxy — the per-proxy design let idle connections scale with pool size
	// and blew past the connection cap.
	rt := NewRotatingTransport(New(), nil)
	if rt.shared == nil {
		t.Fatal("expected a single shared *http.Transport")
	}
	if rt.shared.MaxIdleConns != maxIdleConns {
		t.Errorf("shared.MaxIdleConns = %d, want %d (global idle cap)", rt.shared.MaxIdleConns, maxIdleConns)
	}
}
