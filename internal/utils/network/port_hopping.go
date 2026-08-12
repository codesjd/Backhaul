package network

// PortHoppingPacketConn wraps a net.PacketConn to rotate the destination UDP
// port on a timer, defeating per-flow DPI throttling that targets a stable
// 4-tuple. Every write goes to a rotating port within a configured range; on
// read the source address is normalized back to the canonical server address
// so the QUIC stack never observes a "connection migration."
//
// This is the core technique Hysteria2 uses to survive in Iran: with no stable
// flow, the censor's DPI can't build per-flow throttle state against the tunnel.
//
// Server-side deployment needs no application change - bind one socket and let a
// firewall rule redirect the whole range to it:
//
//	iptables -t nat -A PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 443
//
// conntrack rewrites the replies back to the port the client actually hit.
import (
	"net"
	"sync"
	"time"

	mrand "math/rand/v2"
)

// PortHoppingPacketConn rewrites the destination port of every outgoing packet.
type PortHoppingPacketConn struct {
	net.PacketConn
	baseAddr    *net.UDPAddr
	portStart   int
	portEnd     int
	rotationDur time.Duration

	mu          sync.Mutex
	currentPort int
	lastRotate  time.Time
}

// DefaultPortHopInterval is how often the destination port rotates when the
// caller does not specify an interval.
const DefaultPortHopInterval = 30 * time.Second

// NewPortHoppingPacketConn wraps inner so writes rotate across [portStart,
// portEnd] every rotationDur. baseAddr is the canonical server address returned
// to the QUIC stack on every read. If the range collapses to a single port, the
// wrapper simply forwards to that port with no hopping.
func NewPortHoppingPacketConn(inner net.PacketConn, baseAddr *net.UDPAddr, portStart, portEnd int, rotationDur time.Duration) *PortHoppingPacketConn {
	if portStart > portEnd {
		portStart, portEnd = portEnd, portStart
	}
	if rotationDur <= 0 {
		rotationDur = DefaultPortHopInterval
	}
	h := &PortHoppingPacketConn{
		PacketConn:  inner,
		baseAddr:    baseAddr,
		portStart:   portStart,
		portEnd:     portEnd,
		rotationDur: rotationDur,
		lastRotate:  time.Now(),
	}
	h.currentPort = h.pick()
	return h
}

// pick returns a random port within the range (or the single port if the range
// is degenerate). The top-level math/rand/v2 helpers are safe for concurrent use.
func (h *PortHoppingPacketConn) pick() int {
	if h.portStart >= h.portEnd {
		return h.portStart
	}
	return h.portStart + mrand.IntN(h.portEnd-h.portStart+1)
}

// currentDstPort returns the port to send to, rotating it if the interval elapsed.
func (h *PortHoppingPacketConn) currentDstPort() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.portStart < h.portEnd && time.Since(h.lastRotate) >= h.rotationDur {
		h.currentPort = h.pick()
		h.lastRotate = time.Now()
	}
	return h.currentPort
}

// WriteTo sends p to the current rotated destination port, keeping the target IP.
func (h *PortHoppingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	port := h.currentDstPort()

	ip := h.baseAddr.IP
	zone := h.baseAddr.Zone
	if ua, ok := addr.(*net.UDPAddr); ok {
		ip, zone = ua.IP, ua.Zone
	}
	dst := &net.UDPAddr{IP: ip, Port: port, Zone: zone}

	n, err := h.PacketConn.WriteTo(p, dst)
	if n > len(p) {
		// Report bytes of the caller's payload, never the rewritten framing.
		n = len(p)
	}
	return n, err
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
