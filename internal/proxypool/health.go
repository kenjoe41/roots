package proxypool

import (
	"sync"
	"time"
)

// ewmaAlpha is the smoothing factor for the exponential weighted moving
// average used to score a proxy's reliability. 0.3 means three consecutive
// failures drop a healthy proxy (score=1.0) below 0.5, and three consecutive
// successes bring a dead proxy (score=0.0) back above 0.5 — reacts fast
// enough to route around a proxy that just died mid-crawl without being so
// twitchy that one blip evicts an otherwise-good proxy.
const ewmaAlpha = 0.3

// proxyHealth tracks one proxy's rolling success/failure record.
type proxyHealth struct {
	mu                  sync.RWMutex
	score               float64
	successCount        int64
	failureCount        int64
	consecutiveFailures int64 // reset to 0 on any success; drives Pool.Prune, distinct from score
	lastChecked         time.Time
}

func newProxyHealth() *proxyHealth {
	return &proxyHealth{score: 0.5}
}

func (h *proxyHealth) recordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.score = ewmaAlpha*1.0 + (1-ewmaAlpha)*h.score
	h.successCount++
	h.consecutiveFailures = 0
	h.lastChecked = time.Now()
}

func (h *proxyHealth) recordFailure() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.score = (1 - ewmaAlpha) * h.score
	h.failureCount++
	h.consecutiveFailures++
	h.lastChecked = time.Now()
}

func (h *proxyHealth) getScore() float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.score
}

func (h *proxyHealth) getConsecutiveFailures() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.consecutiveFailures
}

func (h *proxyHealth) counts() (success, failure int64) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.successCount, h.failureCount
}

// healthTracker holds a concurrent-safe map of proxy address to its rolling
// health record. Unlike shadowweave's original (which this is adapted
// from), there is no per-domain tracking or anonymity classification —
// roots only cares whether a proxy can reach a CT log server at all, never
// about evading detection, so that whole dimension doesn't apply here.
type healthTracker struct {
	mu     sync.RWMutex
	health map[string]*proxyHealth
}

func newHealthTracker() *healthTracker {
	return &healthTracker{health: make(map[string]*proxyHealth)}
}

func (t *healthTracker) getOrCreate(addr string) *proxyHealth {
	t.mu.Lock()
	defer t.mu.Unlock()
	if h, ok := t.health[addr]; ok {
		return h
	}
	h := newProxyHealth()
	t.health[addr] = h
	return h
}

func (t *healthTracker) get(addr string) *proxyHealth {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.health[addr]
}

func (t *healthTracker) recordSuccess(addr string) { t.getOrCreate(addr).recordSuccess() }
func (t *healthTracker) recordFailure(addr string) { t.getOrCreate(addr).recordFailure() }

// scoreOf returns addr's current score, or the neutral starting score 0.5
// if addr has no recorded observations yet.
func (t *healthTracker) scoreOf(addr string) float64 {
	if h := t.get(addr); h != nil {
		return h.getScore()
	}
	return 0.5
}

// consecutiveFailures returns how many times in a row addr has failed with
// no success in between, or 0 if addr has no recorded observations yet
// (never seen is not the same as "just failed").
func (t *healthTracker) consecutiveFailures(addr string) int64 {
	if h := t.get(addr); h != nil {
		return h.getConsecutiveFailures()
	}
	return 0
}

// poolStats summarises the health tracker for operator-facing progress
// output — "how many of the proxies we harvested are actually still
// pulling their weight partway through a multi-billion-entry crawl."
type poolStats struct {
	Total     int
	Healthy   int // score >= 0.5
	Unhealthy int // 0 < score < 0.5
	Dead      int // score == 0 (never happens exactly via EWMA, kept for symmetry)
	MeanScore float64
}

func (t *healthTracker) snapshot() poolStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var s poolStats
	var total float64
	for _, h := range t.health {
		scr := h.getScore()
		total += scr
		s.Total++
		switch {
		case scr >= 0.5:
			s.Healthy++
		case scr > 0:
			s.Unhealthy++
		default:
			s.Dead++
		}
	}
	if s.Total > 0 {
		s.MeanScore = total / float64(s.Total)
	}
	return s
}
