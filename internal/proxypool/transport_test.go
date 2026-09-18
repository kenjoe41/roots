package proxypool

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRotatingTransport_NilPoolGoesDirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	rt := NewRotatingTransport(nil)
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

	rt := NewRotatingTransport(New()) // pool with zero proxies harvested
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

func TestRotatingTransport_MalformedCachedAddrFallsBackToDirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	pool := New()
	pool.proxies = []string{"://not-a-valid-url"}
	rt := NewRotatingTransport(pool)
	client := &http.Client{Transport: rt}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
}

func TestRotatingTransport_CachesTransportPerAddr(t *testing.T) {
	rt := NewRotatingTransport(New())
	a := rt.transportFor("http://1.2.3.4:8080")
	b := rt.transportFor("http://1.2.3.4:8080")
	if a != b {
		t.Error("expected the same cached transport for the same proxy address")
	}
	c := rt.transportFor("http://5.6.7.8:8080")
	if a == c {
		t.Error("expected a different transport for a different proxy address")
	}
}
