package network

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// recordingPacketConn records the destination address of every WriteTo so a test
// can observe which port a wrapper actually sent to.
type recordingPacketConn struct {
	dests []net.Addr
	local net.Addr
}

func (r *recordingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return 0, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7}, nil
}
func (r *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	r.dests = append(r.dests, addr)
	return len(p), nil
}
func (r *recordingPacketConn) Close() error                     { return nil }
func (r *recordingPacketConn) LocalAddr() net.Addr              { return r.local }
func (r *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (r *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (r *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

// bufRecordingConn records SetReadBuffer/SetWriteBuffer so a test can confirm the
// call reaches the underlying socket through the wrapper chain.
type bufRecordingConn struct {
	net.PacketConn
	rbuf, wbuf int
}

func (c *bufRecordingConn) ReadFrom(p []byte) (int, net.Addr, error)  { return 0, nil, nil }
func (c *bufRecordingConn) WriteTo(p []byte, a net.Addr) (int, error) { return len(p), nil }
func (c *bufRecordingConn) Close() error                              { return nil }
func (c *bufRecordingConn) LocalAddr() net.Addr                       { return &net.UDPAddr{} }
func (c *bufRecordingConn) SetDeadline(time.Time) error               { return nil }
func (c *bufRecordingConn) SetReadDeadline(time.Time) error           { return nil }
func (c *bufRecordingConn) SetWriteDeadline(time.Time) error          { return nil }
func (c *bufRecordingConn) SetReadBuffer(n int) error                 { c.rbuf = n; return nil }
func (c *bufRecordingConn) SetWriteBuffer(n int) error                { c.wbuf = n; return nil }

// TestPortHoppingForwardsBufferSizing guards the throughput regression: quic-go
// (and the obfs wrapper) size the kernel buffers via a SetReadBuffer/SetWriteBuffer
// type assertion; if PortHoppingPacketConn doesn't forward them, the buffers stay
// tiny and a fast link collapses. Verify the calls reach the socket both directly
// and through the obfs -> port-hopping -> socket chain the client actually builds.
func TestPortHoppingForwardsBufferSizing(t *testing.T) {
	base := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

	direct := &bufRecordingConn{}
	h := NewPortHoppingPacketConn(direct, base, 20000, 20010)
	_ = h.SetReadBuffer(1 << 20)
	_ = h.SetWriteBuffer(2 << 20)
	if direct.rbuf != 1<<20 || direct.wbuf != 2<<20 {
		t.Fatalf("port hopping did not forward buffer sizing: rbuf=%d wbuf=%d", direct.rbuf, direct.wbuf)
	}

	chained := &bufRecordingConn{}
	obfs := NewObfsPacketConn(NewPortHoppingPacketConn(chained, base, 20000, 20010), "pw")
	_ = obfs.SetReadBuffer(3 << 20)
	_ = obfs.SetWriteBuffer(4 << 20)
	if chained.rbuf != 3<<20 || chained.wbuf != 4<<20 {
		t.Fatalf("obfs->porthop->socket did not forward buffer sizing: rbuf=%d wbuf=%d", chained.rbuf, chained.wbuf)
	}
}

// TestPortHoppingRewritesDestPort verifies writes land on a single per-connection
// port inside the configured range and keep the target IP, and that the port
// stays STABLE for the connection's life (no mid-connection rotation, which
// churned NAT state). Reads report the canonical base address so quic-go never
// sees a migration.
func TestPortHoppingRewritesDestPort(t *testing.T) {
	rec := &recordingPacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}}
	base := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 443}
	const start, end = 20000, 20010
	h := NewPortHoppingPacketConn(rec, base, start, end)

	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		if _, err := h.WriteTo([]byte("x"), base); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for _, d := range rec.dests {
		ua, ok := d.(*net.UDPAddr)
		if !ok {
			t.Fatalf("dest not UDPAddr: %T", d)
		}
		if ua.Port < start || ua.Port > end {
			t.Fatalf("dest port %d outside range [%d,%d]", ua.Port, start, end)
		}
		if !ua.IP.Equal(base.IP) {
			t.Fatalf("dest IP rewritten: got %v want %v", ua.IP, base.IP)
		}
		seen[ua.Port] = true
	}
	if len(seen) != 1 {
		t.Fatalf("port must be stable for the connection; saw %d distinct ports", len(seen))
	}

	// Two separate connections should generally pick from the range independently
	// (spread across connections) - verify the picked port is always in range.
	for i := 0; i < 50; i++ {
		h2 := NewPortHoppingPacketConn(rec, base, start, end)
		if h2.dstPort < start || h2.dstPort > end {
			t.Fatalf("per-connection port %d outside range", h2.dstPort)
		}
	}

	// ReadFrom must normalize the source back to the canonical base address.
	_, addr, err := h.ReadFrom(make([]byte, 16))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := addr.(*net.UDPAddr); got.Port != base.Port || !got.IP.Equal(base.IP) {
		t.Fatalf("read addr not normalized: got %v want %v", got, base)
	}
}

// TestValidPortRange checks normalization and rejection so the client and the
// server's firewall rule always agree, and an out-of-range port can't be used.
func TestValidPortRange(t *testing.T) {
	cases := []struct {
		in           []int
		wantS, wantE int
		wantOK       bool
	}{
		{[]int{20000, 50000}, 20000, 50000, true},
		{[]int{50000, 20000}, 20000, 50000, true}, // reversed -> normalized
		{[]int{443, 443}, 443, 443, true},
		{[]int{20000, 70000}, 0, 0, false}, // > 65535
		{[]int{0, 50000}, 0, 0, false},     // < 1
		{[]int{20000}, 0, 0, false},        // wrong length
		{nil, 0, 0, false},
	}
	for _, c := range cases {
		s, e, ok := ValidPortRange(c.in)
		if ok != c.wantOK || (ok && (s != c.wantS || e != c.wantE)) {
			t.Fatalf("ValidPortRange(%v) = (%d,%d,%v), want (%d,%d,%v)", c.in, s, e, ok, c.wantS, c.wantE, c.wantOK)
		}
	}
}

// TestPortHoppingSinglePort checks a degenerate range always uses that one port.
func TestPortHoppingSinglePort(t *testing.T) {
	rec := &recordingPacketConn{local: &net.UDPAddr{}}
	base := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 443}
	h := NewPortHoppingPacketConn(rec, base, 443, 443)
	for i := 0; i < 10; i++ {
		h.WriteTo([]byte("x"), base)
	}
	for _, d := range rec.dests {
		if d.(*net.UDPAddr).Port != 443 {
			t.Fatalf("single-port range used %d", d.(*net.UDPAddr).Port)
		}
	}
}

// TestObfsSTUNRoundTrip verifies STUN-framed obfuscation round-trips and that
// the wire bytes carry the STUN magic cookie so the packet reads as STUN.
func TestObfsSTUNRoundTrip(t *testing.T) {
	a, b := newFakePair()
	sender := NewObfsPacketConn(a, "correct-horse").WithSTUN(true)
	receiver := NewObfsPacketConn(b, "correct-horse").WithSTUN(true)

	plain := make([]byte, 512)
	rand.Read(plain)
	if _, err := sender.WriteTo(plain, b.addr); err != nil {
		t.Fatalf("stun write: %v", err)
	}
	raw := <-b.in
	if len(raw) < stunHeaderLen {
		t.Fatalf("wire packet too short: %d", len(raw))
	}
	if got := binary.BigEndian.Uint32(raw[4:8]); got != stunMagicCookie {
		t.Fatalf("STUN magic cookie missing: got %#x", got)
	}
	if bytes.Contains(raw, plain) {
		t.Fatal("plaintext appeared on the wire")
	}
	b.in <- raw
	out := make([]byte, 2048)
	n, _, err := receiver.ReadFrom(out)
	if err != nil {
		t.Fatalf("stun read: %v", err)
	}
	if !bytes.Equal(out[:n], plain) {
		t.Fatal("STUN obfs round trip mismatch")
	}
}

// TestPortHoppingRuleSpec checks the NAT rule spec and human-readable command
// carry the right range and target port.
func TestPortHoppingRuleSpec(t *testing.T) {
	spec := portHoppingRuleSpec(20000, 50000, 443)
	joined := strings.Join(spec, " ")
	for _, want := range []string{"PREROUTING", "-p udp", "--dport 20000:50000", "-j REDIRECT", "--to-ports 443"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("rule spec missing %q: %s", want, joined)
		}
	}
	cmd := PortHoppingRuleCommand(20000, 50000, 443)
	if !strings.Contains(cmd, "iptables -t nat -A PREROUTING") || !strings.Contains(cmd, "--dport 20000:50000") || !strings.Contains(cmd, "--to-ports 443") {
		t.Fatalf("unexpected command string: %s", cmd)
	}
}

// TestObfsOverheadInitialPacketSize asserts QuicConfig shrinks the initial packet
// size by exactly the obfuscation overhead, so the datagram on the wire is no
// larger than a plain QUIC packet. Getting this wrong drops handshake packets on
// any path whose MTU only just fits plain QUIC (the STUN dial-timeout regression).
func TestObfsOverheadInitialPacketSize(t *testing.T) {
	if got := ObfsOverhead(false, false); got != 0 {
		t.Fatalf("ObfsOverhead(off) = %d, want 0", got)
	}
	if got := ObfsOverhead(true, false); got != obfsSaltLen {
		t.Fatalf("ObfsOverhead(obfs) = %d, want %d", got, obfsSaltLen)
	}
	if got := ObfsOverhead(true, true); got != obfsSaltLen+stunHeaderLen {
		t.Fatalf("ObfsOverhead(obfs+stun) = %d, want %d", got, obfsSaltLen+stunHeaderLen)
	}

	// No obfs -> leave InitialPacketSize at quic-go's default (0 = unset).
	if got := QuicConfig(100, 30*time.Second, 0, 0).InitialPacketSize; got != 0 {
		t.Fatalf("plain InitialPacketSize = %d, want 0 (default)", got)
	}
	// obfs+STUN -> default minus overhead, so QUIC packet + obfs == plain size.
	wantStun := uint16(quicDefaultInitialPacketSize - (obfsSaltLen + stunHeaderLen))
	if got := QuicConfig(100, 30*time.Second, 0, obfsSaltLen+stunHeaderLen).InitialPacketSize; got != wantStun {
		t.Fatalf("obfs+stun InitialPacketSize = %d, want %d", got, wantStun)
	}
}

// TestJitterKeepaliveBounds checks the jittered period stays within the expected
// window and actually varies.
func TestJitterKeepaliveBounds(t *testing.T) {
	// Default window is [4s, 8s] - kept well below the 30s idle timeout.
	seen := map[time.Duration]bool{}
	for i := 0; i < 500; i++ {
		d := JitterKeepalive(0, 0)
		if d < 4*time.Second || d > 8*time.Second {
			t.Fatalf("default jitter %v outside [4s,8s]", d)
		}
		seen[d] = true
	}
	if len(seen) < 10 {
		t.Fatalf("jitter not varying: only %d distinct values", len(seen))
	}

	// Explicit window is honored.
	for i := 0; i < 200; i++ {
		d := JitterKeepalive(5*time.Second, 9*time.Second)
		if d < 5*time.Second || d > 9*time.Second {
			t.Fatalf("explicit jitter %v outside [5s,9s]", d)
		}
	}
}
