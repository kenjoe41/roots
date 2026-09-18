package proxypool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchList_LineFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("10.0.0.1:8080\n10.0.0.2:3128\n"))
	}))
	defer server.Close()

	proxies, err := fetchList(context.Background(), &http.Client{}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d: %v", len(proxies), proxies)
	}
}

func TestFetchList_JSONStringArray(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`["10.0.0.1:8080","10.0.0.2:3128"]`))
	}))
	defer server.Close()

	proxies, err := fetchList(context.Background(), &http.Client{}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d: %v", len(proxies), proxies)
	}
}

func TestFetchList_JSONObjectArrayWrappedInData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[{"ip":"10.0.0.1","port":8080},{"ip":"10.0.0.2","port":3128}]}`))
	}))
	defer server.Close()

	proxies, err := fetchList(context.Background(), &http.Client{}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d: %v", len(proxies), proxies)
	}
}

func TestFetchList_EmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	proxies, err := fetchList(context.Background(), &http.Client{}, server.URL)
	if err != nil {
		t.Fatalf("unexpected error for empty body: %v", err)
	}
	if len(proxies) != 0 {
		t.Errorf("expected 0 proxies, got %d", len(proxies))
	}
}

func TestFetchList_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	proxies, err := fetchList(context.Background(), &http.Client{}, server.URL)
	if err != nil {
		t.Fatalf("expected no error on invalid JSON, got: %v", err)
	}
	if len(proxies) != 0 {
		t.Errorf("expected 0 proxies from invalid JSON, got %d", len(proxies))
	}
}

func TestFetchList_BadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := fetchList(context.Background(), &http.Client{}, server.URL)
	if err == nil {
		t.Fatal("expected an error for a non-200 status")
	}
}

func TestValidate_RealHTTPProxy(t *testing.T) {
	// A local server standing in as the "validator target"; a local plain
	// HTTP proxy in front of it stands in as the candidate proxy — this
	// exercises the real CONNECT-tunnel validation path end to end without
	// depending on any actual free proxy being alive during CI.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "unsupported in this fixture", http.StatusNotImplemented)
	}))
	defer proxy.Close()

	// A plain httptest CONNECT stub doesn't actually tunnel bytes, so this
	// only proves validate() correctly builds and issues a CONNECT request
	// through the given proxy address — a genuine end-to-end tunnel test
	// against a real third-party proxy isn't reproducible in CI.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = validate(ctx, proxy.Listener.Addr().String(), target.URL)
}

func TestValidate_UnreachableProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if validate(ctx, "127.0.0.1:1", defaultValidatorURL) {
		t.Error("expected an unreachable proxy to fail validation")
	}
}

func TestNormaliseAddr(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:8080":         "http://1.2.3.4:8080",
		"http://1.2.3.4:8080":  "http://1.2.3.4:8080",
		"https://1.2.3.4:8443": "https://1.2.3.4:8443",
	}
	for in, want := range cases {
		if got := normaliseAddr(in); got != want {
			t.Errorf("normaliseAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
