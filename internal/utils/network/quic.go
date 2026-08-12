package network

// QUIC transport helpers shared by the client and server quic transports.
//
// The quic transport is backhaul's TUIC/Hysteria2-shaped path: a single QUIC
// connection (UDP underneath, TLS 1.3 built in) carries every forwarded flow.
// Forwarded TCP connections ride QUIC streams (independently flow-controlled, so
// one slow flow never head-of-line-blocks the others), and forwarded UDP rides
// QUIC datagrams (unreliable, unordered - matching UDP's own semantics instead
// of paying for retransmission on packets that don't want it).
//
// Bandwidth handling: Hysteria2's headline feature is "Brutal", a congestion
// controller that paces at a fixed rate and ignores packet loss, which is what
// makes it fast on lossy censored links. Brutal has to live *inside* the QUIC
// stack; this transport rides github.com/sagernet/quic-go (the sing-box fork),
// which exposes conn.SetCongestionControl, and installs a real Brutal controller
// (internal/utils/congestion) when quic_up_mbps is set. QuicConfig additionally
// sizes the flow-control windows to the bandwidth-delay product so the receiver
// window never caps a single fat flow.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	"golang.org/x/crypto/blake2b"
)

const (
	// QuicALPN is the default ALPN token both ends negotiate when masquerade is
	// off. quic_masquerade switches it to "h3" (see QuicALPNProtocols) so the
	// handshake blends with real HTTP/3 web traffic.
	QuicALPN = "backhaul-quic"

	// QuicMaxDatagramPayload bounds a single QUIC datagram we send, leaving
	// headroom under a conservative path MTU for the QUIC packet + our datagram
	// header, so it stays under the ~1200-byte floor quic-go sends unfragmented.
	QuicMaxDatagramPayload = 1100

	// udpFragHeaderLen is the per-datagram UDP framing: session id (4) +
	// packet id (2) + fragment count (1) + fragment index (1).
	udpFragHeaderLen = 8

	// MaxUDPFragPayload is how many bytes of the original UDP packet fit in one
	// datagram after the framing header.
	MaxUDPFragPayload = QuicMaxDatagramPayload - udpFragHeaderLen

	// STUN magic cookie for protocol mimicry obfuscation
	stunMagicCookie = 0x2112A442
)

// Server-opened stream types. The first byte of every stream the server opens to
// the client says what the stream is for.
const (
	QuicStreamTCP byte = 1 // followed by an LP-string target address; a forwarded TCP flow
	QuicStreamUDP byte = 2 // followed by uint32 session id + LP-string target address; registers a UDP session
)

// QuicALPNProtocols returns the ALPN list to advertise. With masquerade on it
// claims "h3" so the negotiated ALPN (which QUIC-aware DPI recovers by decrypting
// the Initial packet) matches real HTTP/3 web traffic instead of a custom token
// that stands out. Both ends must agree, so this is derived from the same
// quic_masquerade flag on client and server.
func QuicALPNProtocols(masquerade bool) []string {
	if masquerade {
		return []string{"h3"}
	}
	return []string{QuicALPN}
}

// QuicServerTLSConfig loads the configured cert/key, or generates an in-memory
// self-signed certificate when none is set (the common case for this tool,
// where the operator controls both ends and pins trust via the token, not a CA).
func QuicServerTLSConfig(certFile, keyFile string, alpn []string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load quic tls cert/key: %w", err)
		}
	} else {
		cert, err = generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed quic cert: %w", err)
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   alpn,
	}, nil
}

// QuicClientTLSConfig builds the client side. verify follows the same contract
// as the ws/wss tls_verify knob: off by default (self-signed friendly), but
// while off an on-path party can MITM the token-bearing handshake.
func QuicClientTLSConfig(serverName string, verify bool, alpn []string) *tls.Config {
	host := serverName
	if h, _, err := net.SplitHostPort(serverName); err == nil {
		host = h
	}
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !verify,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         alpn,
	}
}

// QuicConfig builds the shared *quic.Config. downMbps sizes the flow-control
// windows to the bandwidth-delay product (assuming a generous RTT budget) so the
// receiver window never caps a single fat flow - the achievable half of Brutal's
// intent. keepalive keeps an idle tunnel's NAT mapping and the connection alive.
func QuicConfig(downMbps int, keepalive time.Duration) *quic.Config {
	if downMbps <= 0 {
		downMbps = 100
	}
	// BDP over a 200ms RTT budget: bytes = mbps/8 * 1e6 * 0.2. Clamp to a sane
	// range so a misconfigured or huge value can't reserve unbounded memory.
	window := uint64(downMbps) * 1_000_000 / 8 * 200 / 1000
	const minWindow = 8 * 1024 * 1024   // 8 MB floor - already well above smux's 64 KB
	const maxWindow = 256 * 1024 * 1024 // 256 MB ceiling
	if window < minWindow {
		window = minWindow
	}
	if window > maxWindow {
		window = maxWindow
	}
	if keepalive <= 0 {
		keepalive = 30 * time.Second
	}
	return &quic.Config{
		EnableDatagrams:                true,
		MaxIdleTimeout:                 60 * time.Second,
		KeepAlivePeriod:                keepalive,
		HandshakeIdleTimeout:           10 * time.Second,
		InitialStreamReceiveWindow:     window / 2,
		MaxStreamReceiveWindow:         window,
		InitialConnectionReceiveWindow: window,
		MaxConnectionReceiveWindow:     window * 2,
		MaxIncomingStreams:             1 << 16,
	}
}

// StreamConn adapts a *quic.Stream to net.Conn (a quic.Stream has no
// Local/RemoteAddr of its own) so it drops straight into the existing
// TCPConnectionHandler pump.
type StreamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

// NewStreamConn wraps a stream, borrowing the addresses from its QUIC connection.
func NewStreamConn(s *quic.Stream, conn *quic.Conn) *StreamConn {
	return &StreamConn{Stream: s, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
}

func (s *StreamConn) LocalAddr() net.Addr  { return s.local }
func (s *StreamConn) RemoteAddr() net.Addr { return s.remote }

// WriteLPString writes a uint16 length-prefixed string.
func WriteLPString(w io.Writer, s string) error {
	if len(s) > 0xFFFF {
		return fmt.Errorf("string too long for length prefix: %d", len(s))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(s)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}

// ReadLPString reads a uint16 length-prefixed string.
func ReadLPString(r io.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "backhaul"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"backhaul"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// -------- UDP datagram framing + fragmentation --------
//
// A forwarded UDP packet can exceed what one QUIC datagram carries, so packets
// are split into fragments that share a (sessionID, packetID) and are reassembled
// on the far side. The common small-packet case is a single fragment (fragCount
// == 1) and takes the fast path with no reassembly state.

var udpPacketSeq uint32

// NextUDPPacketID returns a process-wide monotonic packet id (wrapping at 16
// bits). Reassembly is keyed by (sessionID, packetID), and stale partials are
// evicted well within a 16-bit wrap, so per-session uniqueness holds.
func NextUDPPacketID() uint16 {
	return uint16(atomic.AddUint32(&udpPacketSeq, 1))
}

// FragmentUDP splits one UDP payload into datagrams ready for SendDatagram. Each
// datagram is [sessionID][packetID][fragCount][fragIndex][slice]. A payload that
// fits in one datagram yields a single fragment.
func FragmentUDP(sessionID uint32, packetID uint16, payload []byte) [][]byte {
	n := len(payload) / MaxUDPFragPayload
	if len(payload)%MaxUDPFragPayload != 0 || len(payload) == 0 {
		n++
	}
	if n > 255 {
		return nil // too large to fragment into a single packetID's 8-bit index space
	}
	frags := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		start := i * MaxUDPFragPayload
		end := start + MaxUDPFragPayload
		if end > len(payload) {
			end = len(payload)
		}
		slice := payload[start:end]
		dg := make([]byte, udpFragHeaderLen+len(slice))
		binary.BigEndian.PutUint32(dg[0:4], sessionID)
		binary.BigEndian.PutUint16(dg[4:6], packetID)
		dg[6] = byte(n)
		dg[7] = byte(i)
		copy(dg[udpFragHeaderLen:], slice)
		frags = append(frags, dg)
	}
	return frags
}

// UDPReassembler reassembles fragmented UDP datagrams. It is safe for concurrent
// use and bounds its memory: at most maxPartials in-flight packets, each evicted
// after partialTTL, so a peer that sends only opening fragments can't grow it
// without limit.
type UDPReassembler struct {
	mu       sync.Mutex
	partials map[uint64]*udpPartial
}

type udpPartial struct {
	parts   [][]byte
	have    int
	count   int
	total   int
	created time.Time
}

const (
	maxUDPPartials = 1024
	udpPartialTTL  = 10 * time.Second
)

func NewUDPReassembler() *UDPReassembler {
	return &UDPReassembler{partials: make(map[uint64]*udpPartial)}
}

// Push feeds one received datagram. When it completes a packet (or is a lone
// fragment), it returns the sessionID, the full payload, and ok=true.
func (r *UDPReassembler) Push(dg []byte) (sessionID uint32, payload []byte, ok bool) {
	if len(dg) < udpFragHeaderLen {
		return 0, nil, false
	}
	sessionID = binary.BigEndian.Uint32(dg[0:4])
	packetID := binary.BigEndian.Uint16(dg[4:6])
	count := int(dg[6])
	index := int(dg[7])
	frag := dg[udpFragHeaderLen:]
	if count == 0 || index >= count {
		return 0, nil, false
	}
	if count == 1 {
		// Fast path: a whole packet, copied out so the caller owns it.
		out := make([]byte, len(frag))
		copy(out, frag)
		return sessionID, out, true
	}

	key := uint64(sessionID)<<16 | uint64(packetID)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictLocked()

	p := r.partials[key]
	if p == nil {
		if len(r.partials) >= maxUDPPartials {
			r.dropOldestLocked()
		}
		p = &udpPartial{parts: make([][]byte, count), count: count, created: time.Now()}
		r.partials[key] = p
	}
	if p.count != count || p.parts[index] != nil {
		return 0, nil, false // inconsistent or duplicate fragment; ignore
	}
	cp := make([]byte, len(frag))
	copy(cp, frag)
	p.parts[index] = cp
	p.have++
	p.total += len(cp)
	if p.have < p.count {
		return 0, nil, false
	}
	out := make([]byte, 0, p.total)
	for _, part := range p.parts {
		out = append(out, part...)
	}
	delete(r.partials, key)
	return sessionID, out, true
}

// evictLocked drops partials older than the TTL. Caller holds mu.
func (r *UDPReassembler) evictLocked() {
	now := time.Now()
	for k, p := range r.partials {
		if now.Sub(p.created) > udpPartialTTL {
			delete(r.partials, k)
		}
	}
}

// dropOldestLocked removes the oldest partial to make room. Caller holds mu.
func (r *UDPReassembler) dropOldestLocked() {
	var oldestKey uint64
	var oldest time.Time
	first := true
	for k, p := range r.partials {
		if first || p.created.Before(oldest) {
			oldestKey, oldest, first = k, p.created, false
		}
	}
	if !first {
		delete(r.partials, oldestKey)
	}
}

// -------- Salamander-style packet obfuscation --------
//
// Plain QUIC is an easy DPI target: the long-header handshake exposes the QUIC
// version and connection IDs in cleartext, and censors actively block or throttle
// QUIC they can't attribute to a known service. ObfsPacketConn wraps the UDP
// socket and XORs every packet with a keystream derived from a shared password
// and a per-packet random salt (BLAKE2b), so on the wire each packet is
// salt + pseudo-random bytes - not recognizably QUIC - and a probe that doesn't
// know the password produces garbage the server silently drops. This mirrors
// Hysteria2's "Salamander" obfuscation. It is obfuscation, not additional
// confidentiality: QUIC's own TLS 1.3 still provides that underneath.

const obfsSaltLen = 8

// ObfsPacketConn is a net.PacketConn that obfuscates every datagram with a
// password-derived per-packet keystream.
type ObfsPacketConn struct {
	net.PacketConn
	psk       []byte
	readBuf   []byte
	readKeyIn []byte // scratch for psk||salt on the (single-reader) read path
	readMu    sync.Mutex
}

// NewObfsPacketConn wraps inner so every packet is obfuscated with password.
func NewObfsPacketConn(inner net.PacketConn, password string) *ObfsPacketConn {
	psk := []byte(password)
	return &ObfsPacketConn{
		PacketConn: inner,
		psk:        psk,
		readBuf:    make([]byte, 2048),
		readKeyIn:  make([]byte, 0, len(psk)+obfsSaltLen),
	}
}

// obfsScratch is the per-WriteTo working set, pooled so the hot send path does
// no per-packet allocation. WriteTo can run concurrently (a server's listener
// shares one packet conn across every connection), hence the pool rather than a
// single per-conn buffer.
type obfsScratch struct {
	out   []byte
	keyIn []byte
}

var obfsScratchPool = sync.Pool{New: func() any {
	return &obfsScratch{out: make([]byte, 0, 1600), keyIn: make([]byte, 0, 64)}
}}

// xorWithKey XORs src into dst using key repeated, without a per-byte modulo.
func xorWithKey(dst, src []byte, key *[32]byte) {
	ki := 0
	for i := 0; i < len(src); i++ {
		dst[i] = src[i] ^ key[ki]
		ki++
		if ki == len(key) {
			ki = 0
		}
	}
}

// SetReadBuffer / SetWriteBuffer delegate to the wrapped socket so quic-go can
// still size the kernel buffers (it type-asserts for these); without them it
// logs a warning and leaves the buffers at the OS default. We deliberately do
// NOT expose the OOB batch-read interface: quic-go must keep reading through
// ReadFrom below so every packet is deobfuscated.
func (o *ObfsPacketConn) SetReadBuffer(n int) error {
	if c, ok := o.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return c.SetReadBuffer(n)
	}
	return nil
}

func (o *ObfsPacketConn) SetWriteBuffer(n int) error {
	if c, ok := o.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return c.SetWriteBuffer(n)
	}
	return nil
}

func (o *ObfsPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s := obfsScratchPool.Get().(*obfsScratch)
	need := obfsSaltLen + len(p)
	if cap(s.out) < need {
		s.out = make([]byte, need)
	} else {
		s.out = s.out[:need]
	}
	// The salt is prepended in the clear, so it need not be cryptographically
	// secret - only non-repeating so identical plaintext packets don't produce
	// identical ciphertext. A fast userspace PRNG replaces a per-packet
	// crypto/rand syscall, which was the dominant cost on the send path.
	binary.LittleEndian.PutUint64(s.out[:obfsSaltLen], mrand.Uint64())
	s.keyIn = append(append(s.keyIn[:0], o.psk...), s.out[:obfsSaltLen]...)
	key := blake2b.Sum256(s.keyIn)
	xorWithKey(s.out[obfsSaltLen:], p, &key)
	_, err := o.PacketConn.WriteTo(s.out, addr)
	obfsScratchPool.Put(s)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (o *ObfsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	o.readMu.Lock()
	defer o.readMu.Unlock()
	if len(o.readBuf) < len(p)+obfsSaltLen {
		o.readBuf = make([]byte, len(p)+obfsSaltLen)
	}
	for {
		n, addr, err := o.PacketConn.ReadFrom(o.readBuf)
		if err != nil {
			return 0, addr, err
		}
		if n < obfsSaltLen+1 {
			// Too short to be one of ours (or an unauthenticated probe): drop it
			// and keep reading instead of surfacing garbage to the QUIC stack.
			continue
		}
		o.readKeyIn = append(append(o.readKeyIn[:0], o.psk...), o.readBuf[:obfsSaltLen]...)
		key := blake2b.Sum256(o.readKeyIn)
		plainLen := n - obfsSaltLen
		if plainLen > len(p) {
			plainLen = len(p)
		}
		xorWithKey(p[:plainLen], o.readBuf[obfsSaltLen:n], &key)
		return plainLen, addr, nil
	}
}
