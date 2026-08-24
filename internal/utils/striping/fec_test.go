package striping

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"
)

func TestFECRoundTrip(t *testing.T) {
	cases := []struct {
		data, parity int
	}{
		{2, 1},
		{4, 2},
		{6, 1},
	}
	for _, tc := range cases {
		tc := tc
		t.Run("", func(t *testing.T) {
			legs, peers := pipePair(tc.data + tc.parity)
			client, err := NewFEC(legs, 991, tc.data, tc.parity) // deliberately not a round chunk size
			if err != nil {
				t.Fatalf("NewFEC client: %v", err)
			}
			server, err := NewFEC(peers, 991, tc.data, tc.parity)
			if err != nil {
				t.Fatalf("NewFEC server: %v", err)
			}
			defer client.Close()
			defer server.Close()

			payload := make([]byte, 3*1024*1024+53) // not a multiple of row size
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}

			var wg sync.WaitGroup
			wg.Add(1)
			var writeErr error
			go func() {
				defer wg.Done()
				_, writeErr = client.Write(payload)
				writeErr2 := client.Close()
				if writeErr == nil {
					writeErr = writeErr2
				}
			}()

			got, err := io.ReadAll(io.LimitReader(server, int64(len(payload))))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			wg.Wait()

			if !bytes.Equal(got, payload) {
				t.Fatalf("data=%d parity=%d: reassembled payload mismatch (got %d bytes, want %d)", tc.data, tc.parity, len(got), len(payload))
			}
		})
	}
}

// TestFECTeleratesLegFailure kills exactly parityShards legs before the
// transfer starts (simulating them dying, e.g. a CDN resetting the
// underlying WebSocket connection) and checks the full payload still
// arrives intact - the whole point of the parity shards.
func TestFECToleratesLegFailure(t *testing.T) {
	const dataShards, parityShards = 4, 2
	legs, peers := pipePair(dataShards + parityShards)
	client, err := NewFEC(legs, 4096, dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewFEC client: %v", err)
	}
	server, err := NewFEC(peers, 4096, dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewFEC server: %v", err)
	}
	defer client.Close()
	defer server.Close()

	// Kill 2 legs (== parityShards) up front: one data leg, one parity leg.
	legs[1].Close()
	legs[dataShards].Close()

	payload := make([]byte, 2*1024*1024+11)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var writeErr error
	go func() {
		defer wg.Done()
		_, writeErr = client.Write(payload)
		writeErr2 := client.Close()
		if writeErr == nil {
			writeErr = writeErr2
		}
	}()

	got, err := io.ReadAll(io.LimitReader(server, int64(len(payload))))
	if err != nil {
		t.Fatalf("read after tolerated leg failure: %v", err)
	}
	wg.Wait()
	if writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload mismatch after tolerated leg failure (got %d bytes, want %d)", len(got), len(payload))
	}
}

// TestFECAbortWriteIsLoud mirrors TestStripedAbortWriteIsLoud for the FEC
// path: a truncated upstream write must never be reported to the peer as a
// clean end of stream.
func TestFECAbortWriteIsLoud(t *testing.T) {
	const dataShards, parityShards = 3, 1
	for iter := 0; iter < 20; iter++ {
		legs, peers := pipePair(dataShards + parityShards)
		sender, err := NewFEC(legs, 4096, dataShards, parityShards)
		if err != nil {
			t.Fatalf("NewFEC sender: %v", err)
		}
		receiver, err := NewFEC(peers, 4096, dataShards, parityShards)
		if err != nil {
			t.Fatalf("NewFEC receiver: %v", err)
		}

		payload := make([]byte, 40*dataShards*4096+17)
		if _, err := rand.Read(payload); err != nil {
			t.Fatalf("rand: %v", err)
		}

		go func() {
			sender.Write(payload)
			sender.AbortWrite()
			sender.Close()
		}()

		_, err = io.ReadAll(receiver)
		if err == nil {
			t.Fatalf("iter %d: truncated FEC stream reported a clean EOF - silent data loss", iter)
		}
		receiver.Close()
	}
}

// TestFECFailsBeyondTolerance kills more legs than parityShards can cover
// and expects a loud error - never a silent hang or, worse, corrupted data.
func TestFECFailsBeyondTolerance(t *testing.T) {
	const dataShards, parityShards = 4, 2
	legs, peers := pipePair(dataShards + parityShards)
	client, err := NewFEC(legs, 4096, dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewFEC client: %v", err)
	}
	server, err := NewFEC(peers, 4096, dataShards, parityShards)
	if err != nil {
		t.Fatalf("NewFEC server: %v", err)
	}
	defer client.Close()
	defer server.Close()

	// Kill 3 legs (> parityShards=2): the stream can no longer be guaranteed.
	legs[0].Close()
	legs[1].Close()
	legs[2].Close()

	payload := make([]byte, 512*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		client.Write(payload)
		client.Close()
	}()

	_, readErr := io.ReadAll(server)
	<-done

	if readErr == nil {
		t.Fatalf("expected an error reading past the point where alive legs dropped below dataShards, got nil")
	}
}
