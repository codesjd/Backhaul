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
