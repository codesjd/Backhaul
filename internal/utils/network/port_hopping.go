package network

// PortHoppingPacketConn wraps a net.PacketConn to send to a randomly chosen
// destination UDP port within a configured range, so different tunnel
// connections land on different ports and a censor can't simply block the one
// well-known port. On read the source address is normalized back to the
// canonical server address so the QUIC stack never observes a "connection
// migration."
//
// The port is chosen ONCE, when the connection is established, and kept for the
// life of that connection. An earlier version rotated the port on a 30s timer
// mid-connection; that churned the server's NAT/conntrack state (every rotation
// created a new REDIRECT flow while the old one expired) and periodically broke
// the return path, tearing the tunnel down every ~30s. Rotating only per
// connection keeps the port spread across the range without destabilizing a live
// connection; a fresh port is picked naturally on every reconnect.
//
// Server-side deployment needs no application change - bind one socket and let a
// firewall rule redirect the whole range to it:
//
//	iptables -t nat -A PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 443
//
// conntrack rewrites the replies back to the port the client actually hit.
import (
	"net"

	mrand "math/rand/v2"
)

// ValidPortRange validates a [start, end] port-range config value. It returns the
// normalized (ascending) bounds and ok=true only when the slice has exactly two
// entries, both within [1, 65535]. A reversed range is swapped so the client and
// the server's firewall rule agree on the same bounds; anything else (wrong
// length, zero, or > 65535) is rejected so a misconfigured range can't silently
// send to an invalid port (EINVAL on every packet) or install a broken rule.
func ValidPortRange(r []int) (start, end int, ok bool) {
	if len(r) != 2 {
		return 0, 0, false
	}
	start, end = r[0], r[1]
	if start > end {
		start, end = end, start
	}
	if start < 1 || end > 65535 {
		return 0, 0, false
	}
	return start, end, true
}

// PortHoppingPacketConn rewrites the destination port of every outgoing packet
// to a per-connection random port within the configured range.
type PortHoppingPacketConn struct {
	net.PacketConn
	baseAddr *net.UDPAddr
	dstPort  int // chosen once at construction; stable for the connection's life
}

// NewPortHoppingPacketConn wraps inner so writes go to a random port within
// [portStart, portEnd], chosen once for this connection. baseAddr is the
// canonical server address returned to the QUIC stack on every read. If the
// range collapses to a single port, that port is used.
func NewPortHoppingPacketConn(inner net.PacketConn, baseAddr *net.UDPAddr, portStart, portEnd int) *PortHoppingPacketConn {
	if portStart > portEnd {
		portStart, portEnd = portEnd, portStart
	}
	dstPort := portStart
	if portStart < portEnd {
		dstPort = portStart + mrand.IntN(portEnd-portStart+1)
	}
	return &PortHoppingPacketConn{
		PacketConn: inner,
		baseAddr:   baseAddr,
		dstPort:    dstPort,
	}
}

// WriteTo sends p to this connection's destination port, keeping the target IP.
func (h *PortHoppingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ip := h.baseAddr.IP
	zone := h.baseAddr.Zone
	if ua, ok := addr.(*net.UDPAddr); ok {
		ip, zone = ua.IP, ua.Zone
	}
	dst := &net.UDPAddr{IP: ip, Port: h.dstPort, Zone: zone}

	n, err := h.PacketConn.WriteTo(p, dst)
	if n > len(p) {
		// Report bytes of the caller's payload, never the rewritten framing.
		n = len(p)
	}
	return n, err
}

// SetReadBuffer / SetWriteBuffer forward down to the underlying socket so quic-go
// can size the kernel buffers. Without this the type assertion quic-go (and the
// obfs wrapper) makes fails once a PortHoppingPacketConn is in the chain, the
// buffers stay at the small OS default, and packets are dropped under load -
// collapsing throughput on a fast link. net.PacketConn does not carry these, so
// they must be forwarded explicitly rather than promoted from the embedded field.
func (h *PortHoppingPacketConn) SetReadBuffer(n int) error {
	if c, ok := h.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return c.SetReadBuffer(n)
	}
	return nil
}

func (h *PortHoppingPacketConn) SetWriteBuffer(n int) error {
	if c, ok := h.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return c.SetWriteBuffer(n)
	}
	return nil
}

// ReadFrom returns the canonical baseAddr so quic-go always sees a stable peer,
// regardless of which port the reply actually arrived from.
func (h *PortHoppingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := h.PacketConn.ReadFrom(p)
	if err != nil {
		return n, nil, err
	}
	return n, h.baseAddr, nil
}
