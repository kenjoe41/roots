package proxypool

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// minHealthScore is the floor below which a proxy is excluded from
// selection — it's still tracked (a later success can bring it back above
// the floor) rather than hard-evicted, since a transient timeout under a
// heavy crawl doesn't necessarily mean a proxy is actually dead.
const minHealthScore = 0.2

// Pool distributes requests across a set of validated proxies. Unlike
// shadowweave's Rotator (its own closest analogue — see harvest.go's package
// doc for the full reasoning on what didn't carry over), Pool deliberately
// round-robins across every currently-healthy proxy rather than weighting
// toward the single best-scoring one: the goal here is spreading a
// multi-billion-entry crawl's requests across as many different source IPs
// as possible so no one of them gets rate-limited, not converging traffic
// onto a "best" proxy — which would just recreate the same single-IP
// bottleneck this whole package exists to avoid.
type Pool struct {
	mu      sync.RWMutex
	proxies []string
	health  *healthTracker
	idx     uint64
}

// New returns an empty Pool. Call Harvest to populate it.
func New() *Pool {
	return &Pool{health: newHealthTracker()}
}

// Harvest fetches and validates proxies from sources (defaultSources if
// nil/empty) against validatorURL (defaultValidatorURL if empty), replacing
// the pool's current contents, and returns how many live proxies it found.
// Safe to call again later for a fresh harvest — nothing in Pool depends on
// harvest having only run once.
func (p *Pool) Harvest(ctx context.Context, sources []string, validatorURL string) int {
	if len(sources) == 0 {
		sources = defaultSources
	}
	if validatorURL == "" {
		validatorURL = defaultValidatorURL
	}

	live := harvest(ctx, sources, validatorURL)

	p.mu.Lock()
	p.proxies = live
	p.mu.Unlock()

	return len(live)
}

// Next returns a proxy address chosen by round-robining across every proxy
// currently at or above minHealthScore, or "" if the pool is empty or every
// proxy in it has degraded below the floor — callers must treat "" as
// "proceed with a direct connection," never as an error.
func (p *Pool) Next() string {
	p.mu.RLock()
	all := p.proxies
	p.mu.RUnlock()
	if len(all) == 0 {
		return ""
	}

	healthy := make([]string, 0, len(all))
	for _, addr := range all {
		if p.health.scoreOf(addr) >= minHealthScore {
			healthy = append(healthy, addr)
		}
	}
	if len(healthy) == 0 {
		return ""
	}

	i := atomic.AddUint64(&p.idx, 1)
	return healthy[i%uint64(len(healthy))]
}

// Report records whether a request through proxyAddr reached its
// destination at all. Only transport-level outcomes belong here — a target
// server's own response (a 429 from a CT log, say) is not a proxy failure
// and must never be reported through this method, or a perfectly good
// proxy would get penalized for a log server's own rate limit.
func (p *Pool) Report(proxyAddr string, ok bool) {
	if proxyAddr == "" {
		return
	}
	if ok {
		p.health.recordSuccess(proxyAddr)
	} else {
		p.health.recordFailure(proxyAddr)
	}
}

// Len returns the number of proxies currently in the pool, healthy or not.
func (p *Pool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

// PrintStats writes a one-line health summary to stderr — operator-facing
// progress output for a long-running crawl, matching this codebase's plain
// fmt.Fprintf-to-stderr convention rather than introducing a logging
// framework for one status line.
func (p *Pool) PrintStats() {
	s := p.health.snapshot()
	fmt.Fprintf(os.Stderr, "[proxypool] %d proxies tracked (%d healthy, %d unhealthy, %d dead), mean score %.2f\n",
		s.Total, s.Healthy, s.Unhealthy, s.Dead, s.MeanScore)
}
