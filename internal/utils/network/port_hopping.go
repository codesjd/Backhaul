package network

// PortHoppingPacketConn wraps a net.PacketConn to rotate the destination UDP
// port on every write, defeating per-flow DPI throttling that targets stable
// 4-tuples. The wrapper rewrites the destination port to a rotating value within
// a configured range, and normalizes the source address on read so the QUIC
// stack never sees a "connection migration."
//
// This is the core technique Hysteria2 uses to survive in Iran: no stable flow
// means no per-flow throttle state can be built by the censor's DPI.
//
// Server-side deployment: bind one socket (e.g., :443) and use iptables to
// redirect the port range:
//   iptables -t nat -A PREROUTING -p udp --dport 20000:50000 -j REDIRECT --to-ports 443
// conntrack automatically rewrites replies back to the port the client hit.

import (
	"net"
	"sync"
	"time"

	mrand "math/rand/v2"
)

// PortHoppingPacketConn wraps a PacketConn with port hopping.
type PortHoppingPacketConn struct {
	net.PacketConn
	baseAddr    *net.UDPAddr
	portStart   int
	portEnd     int
	rotationDur time.Duration
	mu          sync.RWMutex
	currentPort int
	lastRotate  time.Time
	randSrc     mrand.RandSource
}

// NewPortHoppingPacketConn creates a port-hopping wrapper. baseAddr is the
// canonical server address; the wrapper rotates the destination port within
// [portStart, portEnd] every rotationDur. If portStart == portEnd, no hopping
// occurs and packets go to the base port directly.
func NewPortHoppingPacketConn(inner net.PacketConn, baseAddr *net.UDPAddr, portStart, portEnd int, rotationDur time.Duration) *PortHoppingPacketConn {
	if portStart > portEnd {
		portStart, portEnd = portEnd, portStart
	}
	src := mrand.NewPCG(mrand.Uint64(), mrand.Uint64())
	h := &PortHoppingPacketConn{
		PacketConn:  inner,
		baseAddr:    baseAddr,
		portStart:   portStart,
		portEnd:     portEnd,
		rotationDur: rotationDur,
		randSrc:     src,
		currentPort: portStart,
		lastRotate:  time.Now(),
	}
	if portStart < portEnd {
		h.rotatePort()
	}
	return h
}

// rotatePort picks a new random port in the range. Caller must hold wlock.
func (h *PortHoppingPacketConn) rotatePort() {
	if h.portStart == h.portEnd {
		return
	}
	rangeSize := h.portEnd - h.portStart + 1
	h.currentPort = h.portStart + int(h.randSrc.Uint64()%uint64(rangeSize))
	h.lastRotate = time.Now()
}

// maybeRotateLocked checks if it's time to rotate and does so. Caller must hold lock.
func (h *PortHoppingPacketConn) maybeRotateLocked() {
	if h.portStart == h.portEnd {
		return
	}
	if time.Since(h.lastRotate) >= h.rotationDur {
		h.rotatePort()
	}
}

// WriteTo rewrites the destination port to the current rotated port.
func (h *PortHoppingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	h.mu.RLock()
	// Check rotation under read lock first (fast path)
	needRotate := false
	if h.portStart < h.portEnd && time.Since(h.lastRotate) >= h.rotationDur {
		needRotate = true
	}
	currentPort := h.currentPort
	h.mu.RUnlock()

	// Upgrade to write lock if rotation needed
	if needRotate {
		h.mu.Lock()
		h.maybeRotateLocked()
		currentPort = h.currentPort
		h.mu.Unlock()
	}

	// Build the rotated address
	var rotatedAddr *net.UDPAddr
	if ua, ok := addr.(*net.UDPAddr); ok {
		rotatedAddr = &net.UDPAddr{
			IP:   ua.IP,
			Port: currentPort,
			Zone: ua.Zone,
		}
	} else {
		// Fallback: use baseAddr with rotated port
		rotatedAddr = &net.UDPAddr{
			IP:   h.baseAddr.IP,
			Port: currentPort,
			Zone: h.baseAddr.Zone,
		}
	}

	return h.PacketConn.WriteTo(p, rotatedAddr)
}

// ReadFrom normalizes the source address back to the canonical baseAddr
// so quic-go never sees a "connection migration."
func (h *PortHoppingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, _, err := h.PacketConn.ReadFrom(p)
	if err != nil {
		return n, nil, err
	}
	// Return the canonical baseAddr so the QUIC stack sees a stable peer
	return n, h.baseAddr, nil
}

// Close closes the underlying PacketConn.
func (h *PortHoppingPacketConn) Close() error {
	return h.PacketConn.Close()
}

// LocalAddr returns the local address of the underlying connection.
func (h *PortHoppingPacketConn) LocalAddr() net.Addr {
	return h.PacketConn.LocalAddr()
}

// SetDeadline sets the read and write deadlines.
func (h *PortHoppingPacketConn) SetDeadline(t time.Time) error {
	return h.PacketConn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline.
func (h *PortHoppingPacketConn) SetReadDeadline(t time.Time) error {
	return h.PacketConn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (h *PortHoppingPacketConn) SetWriteDeadline(t time.Time) error {
	return h.PacketConn.SetWriteDeadline(t)
}
