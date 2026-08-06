package striping

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
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
