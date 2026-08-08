package striping

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// pipePair returns two slices of net.Conn: legs[i] on one side is connected
// to peers[i] on the other, via an in-memory net.Pipe (no real network, but
// exercises the exact same io.Reader/io.Writer contract a TCP conn would).
func pipePair(n int) (legs []net.Conn, peers []net.Conn) {
	for i := 0; i < n; i++ {
		a, b := net.Pipe()
		legs = append(legs, a)
		peers = append(peers, b)
	}
	return legs, peers
}

func TestStripedRoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, 4, 7} {
		n := n
		t.Run("", func(t *testing.T) {
			legs, peers := pipePair(n)
			client := New(legs, 997) // deliberately not a round chunk size
			server := New(peers, 997)
			defer client.Close()
			defer server.Close()

			payload := make([]byte, 5*1024*1024+37) // not a multiple of chunk size
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}

			var wg sync.WaitGroup
			wg.Add(1)
			var writeErr error
			go func() {
				defer wg.Done()
				_, writeErr = client.Write(payload)
			}()

			got, err := io.ReadAll(io.LimitReader(server, int64(len(payload))))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			wg.Wait()
			if writeErr != nil {
				t.Fatalf("write: %v", writeErr)
			}

			if !bytes.Equal(got, payload) {
				t.Fatalf("legs=%d: reassembled payload mismatch (got %d bytes, want %d)", n, len(got), len(payload))
			}
		})
	}
}

func TestStripedBidirectional(t *testing.T) {
	legs, peers := pipePair(3)
	a := New(legs, 4096)
	b := New(peers, 4096)
	defer a.Close()
	defer b.Close()

	aToB := make([]byte, 200000)
	bToA := make([]byte, 150000)
	rand.Read(aToB)
	rand.Read(bToA)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a.Write(aToB) }()
	go func() { defer wg.Done(); b.Write(bToA) }()

	gotAtB := make([]byte, 0, len(aToB))
	gotAtA := make([]byte, 0, len(bToA))

	var wg2 sync.WaitGroup
	wg2.Add(2)
	go func() {
		defer wg2.Done()
		buf, _ := io.ReadAll(io.LimitReader(b, int64(len(aToB))))
		gotAtB = buf
	}()
	go func() {
		defer wg2.Done()
		buf, _ := io.ReadAll(io.LimitReader(a, int64(len(bToA))))
		gotAtA = buf
	}()

	wg.Wait()
	wg2.Wait()

	if !bytes.Equal(gotAtB, aToB) {
		t.Fatalf("a->b payload mismatch")
	}
	if !bytes.Equal(gotAtA, bToA) {
		t.Fatalf("b->a payload mismatch")
	}
}

// TestStripedLegStall covers the regression that shipped in the first cut:
// a leg going silently unresponsive (peer never reads, never closes, just
// stops) must not hang Read/Write forever. It has to be detected and torn
// down within stallTimeout, propagating an error to both directions.
func TestStripedLegStall(t *testing.T) {
	const legs = 3
	clientLegs, serverLegs := pipePair(legs)

	client := New(clientLegs, 4096)
	server := New(serverLegs, 4096)
	client.stallTimeout = 200 * time.Millisecond
	server.stallTimeout = 200 * time.Millisecond
	defer client.Close()
	defer server.Close()

	// Drain legs 1 and 2 normally; leg 0's peer is never read from, so any
	// write the client's writeLeg(0) attempts blocks until its deadline -
	// simulating a leg that accepted the TCP connection but then went
	// silent (no RST, no FIN, nothing).
	go func() {
		buf := make([]byte, 4096+headerSize)
		for {
			if _, err := io.ReadFull(serverLegs[1], buf); err != nil {
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096+headerSize)
		for {
			if _, err := io.ReadFull(serverLegs[2], buf); err != nil {
				return
			}
		}
	}()

	readErrCh := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(server)
		readErrCh <- err
	}()

	// With 2 of 3 legs healthy, the work-stealing scheduler routes most
	// chunks away from the stalled leg, so this first Write can legitimately
	// succeed from the caller's point of view (same as a plain TCP Write
	// succeeding just means "accepted", not "peer got it"). What must not
	// happen is the one chunk that *did* land on leg 0 silently vanishing
	// forever - the read side has to notice and fail.
	payload := make([]byte, 64*4096)
	if _, err := client.Write(payload); err != nil {
		t.Logf("client.Write returned an error (acceptable): %v", err)
	}

	select {
	case err := <-readErrCh:
		if err == nil {
			t.Fatal("expected server read to fail once a leg stalled, got nil error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server read did not return within 3x the stall timeout - failure did not propagate to the other direction")
	}

	// Once the stall is detected, the whole Conn is torn down - a
	// subsequent Write must fail promptly instead of leaking the client
	// side as a half-alive connection nobody will ever clean up.
	select {
	case <-client.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("client was not closed after the stall was detected")
	}
	if _, err := client.Write([]byte("more data")); err == nil {
		t.Fatal("expected client.Write to fail after the connection was torn down")
	}
}

// delayedConn wraps a net.Conn and adds latency before every Read returns,
// simulating one leg of a striped connection being consistently slower than
// its siblings (e.g. a noisier path through the same CDN).
type delayedConn struct {
	net.Conn
	delay time.Duration
}

func (d *delayedConn) Read(p []byte) (int, error) {
	time.Sleep(d.delay)
	return d.Conn.Read(p)
}

// TestStripedUnevenLegSpeeds checks that data reassembles correctly (no
// corruption, no lost bytes, no hang) when legs drain at very different
// rates - the scenario the original round-robin scheduler handled by
// stalling the reorder buffer on the slow leg's fixed share of the data.
func TestStripedUnevenLegSpeeds(t *testing.T) {
	clientLegs, serverLegs := pipePair(4)

	// Slow down leg 0 from the server's (reading) side.
	serverLegs[0] = &delayedConn{Conn: serverLegs[0], delay: 20 * time.Millisecond}

	client := New(clientLegs, 2048)
	server := New(serverLegs, 2048)
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 2*1024*1024+123)
	rand.Read(payload)

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeErrCh <- err
	}()

	got, err := io.ReadAll(io.LimitReader(server, int64(len(payload))))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("write: %v", err)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload mismatch under uneven leg speeds (got %d bytes, want %d)", len(got), len(payload))
	}
}

// sharedLimiter is a token bucket shared across several wrapped conns, so
// their combined write rate - not each one individually - is capped. This
// is what actually distinguishes "N legs with independent capacity" from
// "N legs contending for one real bottleneck": with independent per-leg
// limiters every leg would just proceed at its own pace; a *shared* limiter
// is the only way to reproduce legs genuinely competing for one pipe.
type sharedLimiter struct {
	mu          sync.Mutex
	bytesPerSec float64
	tokens      float64
	last        time.Time
}

func newSharedLimiter(bytesPerSec float64) *sharedLimiter {
	return &sharedLimiter{bytesPerSec: bytesPerSec, tokens: bytesPerSec, last: time.Now()}
}

func (l *sharedLimiter) wait(n int) {
	l.mu.Lock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.bytesPerSec
	l.last = now
	if l.tokens > l.bytesPerSec {
		l.tokens = l.bytesPerSec // cap burst to ~1s worth
	}

	need := float64(n) - l.tokens
	if need <= 0 {
		l.tokens -= float64(n)
		l.mu.Unlock()
		return
	}
	wait := time.Duration(need / l.bytesPerSec * float64(time.Second))
	l.tokens = 0
	// Fast-forward the token clock to the point where this deficit will
	// have naturally been paid off. Without this, l.last stays stamped at
	// the *start* of this wait, so the next call's elapsed-time credit
	// double-counts the interval this call already spent sleeping to earn
	// it - which doubles the effective rate instead of enforcing it.
	l.last = l.last.Add(wait)
	l.mu.Unlock()
	time.Sleep(wait)
}

type limitedConn struct {
	net.Conn
	limiter *sharedLimiter
}

func (lc *limitedConn) Write(p []byte) (int, error) {
	lc.limiter.wait(len(p))
	return lc.Conn.Write(p)
}

// TestStripedSharedBottleneck exercises the actual scenario the congestion
// scheduler exists for: legs that don't have independent capacity, but all
// contend for one real shared link. It doesn't assert a throughput number
// (that's exactly the kind of thing that's flaky in CI) - it asserts what
// actually matters: the transfer still completes correctly, and it does so
// within a sane bound instead of the scheduler mismanaging itself into a
// stall under contention.
func TestStripedSharedBottleneck(t *testing.T) {
	const legCount = 4
	clientLegs, serverLegs := pipePair(legCount)

	limiter := newSharedLimiter(300 * 1024) // ~300 KB/s combined, however many legs pull from it
	for i := range clientLegs {
		clientLegs[i] = &limitedConn{Conn: clientLegs[i], limiter: limiter}
	}

	client := New(clientLegs, 8*1024)
	server := New(serverLegs, 8*1024)
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 512*1024)
	rand.Read(payload)

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeErrCh <- err
	}()

	readDone := make(chan struct{})
	var got []byte
	var readErr error
	go func() {
		got, readErr = io.ReadAll(io.LimitReader(server, int64(len(payload))))
		close(readDone)
	}()

	select {
	case <-readDone:
	case <-time.After(15 * time.Second):
		t.Fatal("transfer over a shared, rate-limited bottleneck did not complete in time")
	}

	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload mismatch over shared bottleneck (got %d bytes, want %d)", len(got), len(payload))
	}
}

// slowConn wraps a net.Conn and delays reads, simulating a receiver that
// drains slower than the sender fills - which backs data up in the reassembly
// path and widens the shutdown race window.
type slowConn struct {
	net.Conn
	delay time.Duration
}

func (s *slowConn) Read(p []byte) (int, error) {
	time.Sleep(s.delay)
	return s.Conn.Read(p)
}

// TestStripedWriteThenCloseNoLoss is the regression test for the tail-loss:
// the sender writes a payload and Closes (the real pump's sequence), the
// receiver reads to EOF. Every byte must arrive - a clean shutdown is
// lossless. Repeated many times to catch the intermittent teardown race.
func TestStripedWriteThenCloseNoLoss(t *testing.T) {
	for iter := 0; iter < 400; iter++ {
		legs, peers := pipePair(4)
		client := New(legs, 4096)
		server := New(peers, 4096)

		payload := make([]byte, 1<<20+123) // ~1MB, not a chunk multiple
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("rand: %v", err)
		}

		go func() {
			client.Write(payload)
			client.Close()
		}()

		got, err := io.ReadAll(server)
		if err != nil {
			t.Fatalf("iter %d: read to EOF failed: %v (got %d/%d bytes)", iter, err, len(got), len(payload))
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("iter %d: short/again read: got %d bytes, want %d", iter, len(got), len(payload))
		}
		server.Close()
	}
}
