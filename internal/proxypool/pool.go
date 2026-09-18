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

// deadStreakThreshold is how many consecutive failures (no success since)
// mark a proxy as truly dead rather than just flaky, driving Prune's actual
// removal from the pool — distinct from minHealthScore, which only ever
// excludes a proxy from selection while keeping it around in case it
// recovers. A free proxy that has failed this many times in a row in
// practice never comes back; without ever forgetting these, a multi-day
// crawl's pool only grows, all-uphill, an ever-larger fraction of it dead
// weight Next() has to skip over on every single call.
const deadStreakThreshold = 20

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

// Refresh harvests again and merges newly-found live proxies into the
// existing pool (deduplicated against what's already there) — unlike
// Harvest, it never replaces or removes anything, so a proxy that's merely
// degraded (but hasn't hit Prune's dead-streak threshold) stays exactly
// where it was. Meant to be called periodically during a long crawl: free
// proxies churn within hours, so a pool populated once at startup of a
// run that can take days needs real top-ups, not just one harvest.
// Returns how many genuinely new proxies were added.
func (p *Pool) Refresh(ctx context.Context, sources []string, validatorURL string) int {
	if len(sources) == 0 {
		sources = defaultSources
	}
	if validatorURL == "" {
		validatorURL = defaultValidatorURL
	}
	fresh := harvest(ctx, sources, validatorURL)

	p.mu.Lock()
	defer p.mu.Unlock()
	existing := make(map[string]struct{}, len(p.proxies))
	for _, addr := range p.proxies {
		existing[addr] = struct{}{}
	}
	added := 0
	for _, addr := range fresh {
		if _, ok := existing[addr]; !ok {
			p.proxies = append(p.proxies, addr)
			existing[addr] = struct{}{}
			added++
		}
	}
	return added
}

// Prune removes every proxy at or beyond deadStreakThreshold consecutive
// failures from the pool outright — the actual forgetting Next's
// minHealthScore floor deliberately never does on its own. Returns how many
// were removed.
func (p *Pool) Prune() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := make([]string, 0, len(p.proxies))
	removed := 0
	for _, addr := range p.proxies {
		if p.health.consecutiveFailures(addr) >= deadStreakThreshold {
			removed++
			continue
		}
		kept = append(kept, addr)
	}
	p.proxies = kept
	return removed
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
