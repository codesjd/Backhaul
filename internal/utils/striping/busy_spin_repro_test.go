package striping

import (
	"testing"
	"time"
)

// TestReadDoesNotBusySpinWhenEndArrivesEarly is the regression test for the
// closed-totalKnown busy-spin: once the END marker has closed totalKnown, but
// Read is still waiting for a missing sequence number, the select must not
 // keep waking on the already-closed channel (which burned a core and defeated
 // stallTimeout). It must block until a chunk arrives or stallTimeout fires.
func TestReadDoesNotBusySpinWhenEndArrivesEarly(t *testing.T) {
	// Keep both sides of the pipes open so readLeg doesn't EOF / legDone.
	legs, peers := pipePair(2)
	defer func() {
		for _, c := range legs {
			c.Close()
		}
	}()

	recv := New(peers, 1024)
	recv.stallTimeout = 150 * time.Millisecond
	defer recv.Close()

	// END marker already observed: "there are 2 data chunks total".
	// No chunks have been delivered, so nextSeq=0 and complete() is false.
	recv.setTotal(2)

	errCh := make(chan error, 1)
	start := time.Now()
	go func() {
		buf := make([]byte, 16)
		_, err := recv.Read(buf)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		elapsed := time.Since(start)
		if elapsed < 100*time.Millisecond {
			t.Fatalf("Read returned far too fast (%v, err=%v); expected to block until stallTimeout", elapsed, err)
		}
		if err == nil {
			t.Fatal("expected a stall error, got nil")
		}
		t.Logf("OK: Read unblocked after %v with %v", elapsed, err)
	case <-time.After(800 * time.Millisecond):
		t.Errorf("Read hung past 5x stallTimeout after END marker with missing chunks")
		recv.teardown()
		<-errCh
	}
}
