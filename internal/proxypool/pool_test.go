package proxypool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPool_NextEmptyReturnsEmpty(t *testing.T) {
	p := New()
	if got := p.Next(); got != "" {
		t.Errorf("Next() on empty pool = %q, want empty", got)
	}
}

func TestPool_NextRoundRobinsAcrossHealthy(t *testing.T) {
	p := New()
	p.proxies = []string{"http://a:1", "http://b:1", "http://c:1"}

	seen := map[string]int{}
	for i := 0; i < 30; i++ {
		seen[p.Next()]++
	}
	if len(seen) != 3 {
		t.Fatalf("expected all 3 proxies to be selected over 30 picks, got %d distinct: %v", len(seen), seen)
	}
	for addr, n := range seen {
		if n != 10 {
			t.Errorf("proxy %s selected %d times, want exactly 10 (even round robin)", addr, n)
		}
	}
}

func TestPool_NextExcludesUnhealthyProxies(t *testing.T) {
	p := New()
	p.proxies = []string{"http://good:1", "http://bad:1"}

	for i := 0; i < 10; i++ {
		p.health.recordFailure("http://bad:1")
	}

	for i := 0; i < 10; i++ {
		if got := p.Next(); got != "http://good:1" {
			t.Fatalf("Next() = %q, want only the healthy proxy to ever be picked", got)
		}
	}
}

func TestPool_NextReturnsEmptyWhenEveryProxyIsUnhealthy(t *testing.T) {
	p := New()
	p.proxies = []string{"http://bad1:1", "http://bad2:1"}
	for _, addr := range p.proxies {
		for i := 0; i < 10; i++ {
			p.health.recordFailure(addr)
		}
	}
	if got := p.Next(); got != "" {
		t.Errorf("Next() = %q, want empty when every proxy is unhealthy", got)
	}
}

func TestPool_ReportUpdatesHealth(t *testing.T) {
	p := New()
	p.Report("http://a:1", true)
	if s := p.health.scoreOf("http://a:1"); s <= 0.5 {
		t.Errorf("expected score to rise after a successful report, got %f", s)
	}

	p.Report("http://b:1", false)
	if s := p.health.scoreOf("http://b:1"); s >= 0.5 {
		t.Errorf("expected score to fall after a failed report, got %f", s)
	}
}

func TestPool_ReportIgnoresEmptyAddr(t *testing.T) {
	p := New()
	p.Report("", true) // must not panic or create a phantom health record
	if p.health.get("") != nil {
		t.Error("expected no health record to be created for an empty address")
	}
}

func TestPool_Len(t *testing.T) {
	p := New()
	if p.Len() != 0 {
		t.Errorf("Len() = %d, want 0 for a fresh pool", p.Len())
	}
	p.proxies = []string{"http://a:1", "http://b:1"}
	if p.Len() != 2 {
		t.Errorf("Len() = %d, want 2", p.Len())
	}
}

func TestPool_PruneRemovesOnlyDeadStreakProxies(t *testing.T) {
	p := New()
	p.proxies = []string{"http://dead:1", "http://flaky:1", "http://good:1"}

	for i := 0; i < deadStreakThreshold; i++ {
		p.Report("http://dead:1", false)
	}
	// Flaky: fails a lot, but a success resets the streak, so it must survive.
	for i := 0; i < deadStreakThreshold-1; i++ {
		p.Report("http://flaky:1", false)
	}
	p.Report("http://flaky:1", true)
	p.Report("http://good:1", true)

	removed := p.Prune()
	if removed != 1 {
		t.Fatalf("Prune() removed %d, want exactly 1 (the dead-streak proxy)", removed)
	}
	if p.Len() != 2 {
		t.Fatalf("Len() after prune = %d, want 2", p.Len())
	}
	for _, addr := range p.proxies {
		if addr == "http://dead:1" {
			t.Error("expected the dead-streak proxy to be removed by Prune")
		}
	}
}

func TestPool_PruneOnEmptyPoolIsNoop(t *testing.T) {
	p := New()
	if removed := p.Prune(); removed != 0 {
		t.Errorf("Prune() on empty pool = %d, want 0", removed)
	}
}

func TestPool_RefreshMergesNewProxiesWithoutDroppingExisting(t *testing.T) {
	// 127.0.0.1:1 refuses instantly (nothing listening on port 1), so the
	// harvested candidate fails validation fast instead of waiting out the
	// full CONNECT timeout - keeps this test sub-second while still
	// exercising the real fetch -> validate -> merge path.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("127.0.0.1:1\n"))
	}))
	defer server.Close()

	p := New()
	p.proxies = []string{"http://already-here:1"}

	added := p.Refresh(context.Background(), []string{server.URL}, "")
	// The harvested candidate won't validate (connection refused), so added
	// should be 0 - the point of this test is that Refresh never has side
	// effects on failure and never touches what was already in the pool.
	if added != 0 {
		t.Logf("added = %d (candidate happened to validate, harmless either way)", added)
	}
	if p.Len() < 1 {
		t.Fatal("expected the pre-existing proxy to survive a Refresh call")
	}
	found := false
	for _, addr := range p.proxies {
		if addr == "http://already-here:1" {
			found = true
		}
	}
	if !found {
		t.Error("Refresh must never drop a proxy that was already in the pool")
	}
}

func TestPool_RefreshDoesNotDuplicateAlreadyPresentProxy(t *testing.T) {
	// A fake proxy that answers 200 OK to any CONNECT (matching
	// TestValidate_RealHTTPProxy's own pattern) so it genuinely passes
	// validate() and reaches Refresh's real merge step — a candidate that
	// fails validation never gets there at all, which would make this test
	// pass trivially regardless of whether dedup actually works.
	fakeProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "unsupported in this fixture", http.StatusNotImplemented)
	}))
	defer fakeProxy.Close()
	addr := fakeProxy.Listener.Addr().String()

	p := New()
	p.proxies = []string{normaliseAddr(addr)}

	listSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(addr + "\n"))
	}))
	defer listSource.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	added := p.Refresh(ctx, []string{listSource.URL}, fakeProxy.URL)

	if added != 0 {
		t.Errorf("Refresh reported %d added, want 0 (the address was already present)", added)
	}
	if p.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (Refresh must not add a duplicate of an already-present proxy)", p.Len())
	}
}
