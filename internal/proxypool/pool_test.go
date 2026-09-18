package proxypool

import (
	"testing"
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
