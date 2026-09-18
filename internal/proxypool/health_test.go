package proxypool

import "testing"

func TestHealthTracker_NewProxyStartsNeutral(t *testing.T) {
	ht := newHealthTracker()
	h := ht.getOrCreate("http://1.1.1.1:80")
	if s := h.getScore(); s != 0.5 {
		t.Errorf("expected neutral starting score 0.5, got %f", s)
	}
}

func TestHealthTracker_RecordSuccessRaisesScore(t *testing.T) {
	ht := newHealthTracker()
	ht.recordSuccess("http://1.1.1.1:80")
	got := ht.get("http://1.1.1.1:80").getScore()
	want := ewmaAlpha*1.0 + (1-ewmaAlpha)*0.5
	if got < want-1e-9 || got > want+1e-9 {
		t.Errorf("score = %f, want %f", got, want)
	}
}

func TestHealthTracker_RecordFailureLowersScore(t *testing.T) {
	ht := newHealthTracker()
	ht.recordFailure("http://1.1.1.1:80")
	got := ht.get("http://1.1.1.1:80").getScore()
	want := (1 - ewmaAlpha) * 0.5
	if got < want-1e-9 || got > want+1e-9 {
		t.Errorf("score = %f, want %f", got, want)
	}
}

func TestHealthTracker_ScoreOfUnknownProxyIsNeutral(t *testing.T) {
	ht := newHealthTracker()
	if s := ht.scoreOf("http://never-seen:80"); s != 0.5 {
		t.Errorf("scoreOf(unknown) = %f, want 0.5", s)
	}
}

func TestHealthTracker_RepeatedFailuresDriveScoreDown(t *testing.T) {
	ht := newHealthTracker()
	for i := 0; i < 10; i++ {
		ht.recordFailure("http://flaky:80")
	}
	if s := ht.scoreOf("http://flaky:80"); s >= minHealthScore {
		t.Errorf("expected score below minHealthScore after 10 failures, got %f", s)
	}
}

func TestHealthTracker_RecoverAfterSuccesses(t *testing.T) {
	ht := newHealthTracker()
	for i := 0; i < 10; i++ {
		ht.recordFailure("http://recovering:80")
	}
	for i := 0; i < 10; i++ {
		ht.recordSuccess("http://recovering:80")
	}
	if s := ht.scoreOf("http://recovering:80"); s < 0.9 {
		t.Errorf("expected score to recover close to 1.0 after 10 successes, got %f", s)
	}
}

func TestHealthTracker_Snapshot(t *testing.T) {
	ht := newHealthTracker()
	for i := 0; i < 5; i++ {
		ht.recordSuccess("http://healthy:80")
	}
	for i := 0; i < 20; i++ {
		ht.recordFailure("http://unhealthy:80")
	}

	s := ht.snapshot()
	if s.Total != 2 {
		t.Errorf("Total = %d, want 2", s.Total)
	}
	if s.Healthy != 1 {
		t.Errorf("Healthy = %d, want 1", s.Healthy)
	}
	if s.Unhealthy != 1 {
		t.Errorf("Unhealthy = %d, want 1", s.Unhealthy)
	}
}

func TestProxyHealth_CountsTrackObservations(t *testing.T) {
	h := newProxyHealth()
	h.recordSuccess()
	h.recordSuccess()
	h.recordFailure()
	success, failure := h.counts()
	if success != 2 || failure != 1 {
		t.Errorf("counts() = (%d, %d), want (2, 1)", success, failure)
	}
}
