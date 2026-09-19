package proxypool

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeConn is a no-op net.Conn whose Close is observable.
type fakeConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *fakeConn) Close() error { c.closed.Store(true); return nil }

func TestConnLimiter_CapsConcurrentDials(t *testing.T) {
	const cap = 5
	cl := NewConnLimiter(cap)

	var inFlight, peak int64
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		n := atomic.AddInt64(&inFlight, 1)
		for {
			p := atomic.LoadInt64(&peak)
			if n <= p || atomic.CompareAndSwapInt64(&peak, p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt64(&inFlight, -1)
		return &fakeConn{}, nil
	}
	dial := cl.Wrap(base)

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dial(context.Background(), "tcp", "x:1")
			if err == nil {
				conn.Close() // release the slot
			}
		}()
	}
	wg.Wait()

	if p := atomic.LoadInt64(&peak); p > cap {
		t.Errorf("peak concurrent dials = %d, want <= %d", p, cap)
	}
}

func TestConnLimiter_SlotHeldUntilConnClosed(t *testing.T) {
	cl := NewConnLimiter(1)
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &fakeConn{}, nil
	}
	dial := cl.Wrap(base)

	conn1, err := dial(context.Background(), "tcp", "a:1")
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}

	secondDone := make(chan struct{})
	go func() {
		conn2, _ := dial(context.Background(), "tcp", "b:1")
		if conn2 != nil {
			conn2.Close()
		}
		close(secondDone)
	}()

	select {
	case <-secondDone:
		t.Fatal("second dial proceeded while the first conn was still open — slot released too early")
	case <-time.After(50 * time.Millisecond):
	}

	conn1.Close() // release
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		t.Fatal("second dial never proceeded after the first conn was closed")
	}
}

func TestConnLimiter_ReleasesOnDialError(t *testing.T) {
	cl := NewConnLimiter(1)
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}
	dial := cl.Wrap(base)

	for i := 0; i < 5; i++ {
		if _, err := dial(context.Background(), "tcp", "x:1"); err == nil {
			t.Fatal("expected a dial error")
		}
	}
	// If the slot leaked on error, a 6th dial would block forever.
	done := make(chan struct{})
	go func() {
		_, _ = dial(context.Background(), "tcp", "x:1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("slot leaked on dial error — dial blocked after cap failures")
	}
}

func TestConnLimiter_RespectsContextCancel(t *testing.T) {
	cl := NewConnLimiter(1)
	block := make(chan struct{})
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		<-block
		return &fakeConn{}, nil
	}
	dial := cl.Wrap(base)

	go func() { _, _ = dial(context.Background(), "tcp", "held:1") }() // grabs the only slot
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dial(ctx, "tcp", "waiter:1"); err == nil {
		t.Error("expected a context error when the slot is full and ctx is cancelled")
	}
	close(block)
}

func TestConnLimiter_NilReceiverIsPassthrough(t *testing.T) {
	var cl *ConnLimiter // nil
	called := false
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		return &fakeConn{}, nil
	}
	dial := cl.Wrap(base)
	if _, err := dial(context.Background(), "tcp", "x:1"); err != nil {
		t.Fatalf("nil-limiter dial: %v", err)
	}
	if !called {
		t.Error("expected the base dialer to be called through a nil limiter")
	}
}

func TestConnLimiter_ClampsToAtLeastOne(t *testing.T) {
	cl := NewConnLimiter(0)
	if c := cap(cl.sem); c != 1 {
		t.Errorf("cap clamped to %d, want 1", c)
	}
}

func TestConnLimiter_LimitedTransportUsesTheLimiter(t *testing.T) {
	cl := NewConnLimiter(3)
	tr := cl.LimitedTransport()
	if tr.DialContext == nil {
		t.Fatal("LimitedTransport must set a DialContext")
	}
	if tr.MaxIdleConns != maxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d", tr.MaxIdleConns, maxIdleConns)
	}
}
