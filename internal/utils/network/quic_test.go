package network

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// TestUDPFragmentRoundTrip checks that payloads of many sizes (including empty,
// single-fragment, exact multiples, and multi-fragment) split and reassemble
// back to the original bytes.
func TestUDPFragmentRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 100, MaxUDPFragPayload - 1, MaxUDPFragPayload, MaxUDPFragPayload + 1, 6000, MaxUDPFragPayload * 5}
	r := NewUDPReassembler()
	for _, sz := range sizes {
		payload := make([]byte, sz)
		rand.Read(payload)
		const sessionID = uint32(42)
		frags := FragmentUDP(sessionID, NextUDPPacketID(), payload)
		if frags == nil {
			t.Fatalf("size %d: FragmentUDP returned nil", sz)
		}
		var got []byte
		var ok bool
		var sid uint32
		for _, f := range frags {
			sid, got, ok = r.Push(f)
		}
		if !ok {
			t.Fatalf("size %d: reassembly did not complete", sz)
		}
		if sid != sessionID {
			t.Fatalf("size %d: sessionID mismatch: got %d", sz, sid)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("size %d: reassembled payload mismatch (got %d bytes)", sz, len(got))
		}
	}
}

// TestUDPFragmentInterleaved checks two packets whose fragments arrive
// interleaved still reassemble correctly (keyed by packetID).
func TestUDPFragmentInterleaved(t *testing.T) {
	r := NewUDPReassembler()
	p1 := make([]byte, 5000)
	p2 := make([]byte, 5000)
	rand.Read(p1)
	rand.Read(p2)
	f1 := FragmentUDP(1, 100, p1)
	f2 := FragmentUDP(1, 200, p2)
	if len(f1) < 2 || len(f2) < 2 {
		t.Fatal("expected multi-fragment packets")
	}

	var got1, got2 []byte
	n := len(f1)
	if len(f2) > n {
		n = len(f2)
	}
	for i := 0; i < n; i++ {
		if i < len(f1) {
			if _, out, ok := r.Push(f1[i]); ok {
				got1 = out
			}
		}
		if i < len(f2) {
			if _, out, ok := r.Push(f2[i]); ok {
				got2 = out
			}
		}
	}
	if !bytes.Equal(got1, p1) || !bytes.Equal(got2, p2) {
		t.Fatal("interleaved fragment reassembly mismatch")
	}
}

// fakePacketConn is an in-memory net.PacketConn pair for testing the obfuscation
// wrapper without a real socket.
type fakePacketConn struct {
	in   chan []byte
	peer *fakePacketConn
	addr net.Addr
}

func newFakePair() (*fakePacketConn, *fakePacketConn) {
	a := &fakePacketConn{in: make(chan []byte, 16), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
	b := &fakePacketConn{in: make(chan []byte, 16), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}}
	a.peer, b.peer = b, a
	return a, b
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := <-f.in
	n := copy(p, buf)
	return n, f.peer.addr, nil
}
func (f *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	f.peer.in <- cp
	return len(p), nil
}
func (f *fakePacketConn) Close() error                       { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                { return f.addr }
func (f *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// TestObfsRoundTripAndOnWire verifies the obfuscation wrapper round-trips
// plaintext with the right password, that the bytes on the wire are not the
// plaintext (so a fingerprinter sees scrambled data), and that a wrong password
// does not recover the plaintext.
func TestObfsRoundTripAndOnWire(t *testing.T) {
	a, b := newFakePair()
	sender := NewObfsPacketConn(a, "correct-horse")
	receiver := NewObfsPacketConn(b, "correct-horse")

	plain := []byte("the quick brown fox jumps over the lazy dog, several times over")
	if _, err := sender.WriteTo(plain, b.addr); err != nil {
		t.Fatalf("obfs write: %v", err)
	}
	// Inspect the raw bytes delivered to b before deobfuscation.
	raw := <-b.in
	if bytes.Contains(raw, plain) {
		t.Fatal("plaintext appeared on the wire; obfuscation not applied")
	}
	// Put it back and read through the receiver.
	b.in <- raw
	out := make([]byte, 2048)
	n, _, err := receiver.ReadFrom(out)
	if err != nil {
		t.Fatalf("obfs read: %v", err)
	}
	if !bytes.Equal(out[:n], plain) {
		t.Fatal("obfs round trip mismatch")
	}

	// Wrong password must not recover the plaintext.
	a2, b2 := newFakePair()
	s2 := NewObfsPacketConn(a2, "correct-horse")
	r2 := NewObfsPacketConn(b2, "wrong-password")
	if _, err := s2.WriteTo(plain, b2.addr); err != nil {
		t.Fatalf("write: %v", err)
	}
	out2 := make([]byte, 2048)
	n2, _, err := r2.ReadFrom(out2)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Equal(out2[:n2], plain) {
		t.Fatal("wrong password recovered plaintext")
	}
}

// nullPacketConn discards writes; for benchmarking the obfs codec in isolation.
type nullPacketConn struct{}

func (nullPacketConn) ReadFrom(p []byte) (int, net.Addr, error)  { return 0, nil, io.EOF }
func (nullPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (nullPacketConn) Close() error                              { return nil }
func (nullPacketConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (nullPacketConn) SetDeadline(time.Time) error               { return nil }
func (nullPacketConn) SetReadDeadline(time.Time) error           { return nil }
func (nullPacketConn) SetWriteDeadline(time.Time) error          { return nil }

// BenchmarkObfsWriteTo measures the per-packet obfuscation cost on the send path
// (allocs/op should be 0 after the pooling + fast-salt changes).
func BenchmarkObfsWriteTo(b *testing.B) {
	oc := NewObfsPacketConn(nullPacketConn{}, "benchmark-password")
	p := make([]byte, 1200)
	rand.Read(p)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	b.SetBytes(1200)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := oc.WriteTo(p, addr); err != nil {
			b.Fatal(err)
		}
	}
}
