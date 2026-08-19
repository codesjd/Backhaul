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

	// STUN magic cookie (RFC 5389) prepended in protocol-mimicry obfs mode so the
	// first bytes of an obfuscated datagram read as a benign STUN packet instead
	// of full-entropy random - evading the "fully-encrypted-traffic" classifier.
	stunMagicCookie = 0x2112A442
	// stunHeaderLen is the fixed STUN message header: 2-byte type + 2-byte length
	// + 4-byte magic cookie + 12-byte transaction id.
	stunHeaderLen = 20
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
// quicDefaultInitialPacketSize mirrors quic-go's protocol.InitialPacketSize: the
// UDP payload size quic-go uses for packets before path-MTU discovery. It is not
// exported by the library, so it is duplicated here.
const quicDefaultInitialPacketSize = 1280

// ObfsOverhead is the number of bytes ObfsPacketConn prepends to every datagram:
// the 8-byte salt, plus the 20-byte STUN header when STUN mimicry is on. It must
// be subtracted from the QUIC packet size so the obfuscated datagram on the wire
// is no larger than a plain QUIC packet - otherwise, on a path whose MTU only
// just fits plain QUIC, the inflated handshake packets are silently dropped and
// the dial times out.
func ObfsOverhead(obfs, stun bool) int {
	if !obfs {
		return 0
	}
	if stun {
		return obfsSaltLen + stunHeaderLen
	}
	return obfsSaltLen
}

// DefaultQuicIdleTimeout is how long a QUIC connection tolerates receiving no
// packets before quic-go declares it dead ("timeout: no recent network
// activity"). It is deliberately generous: on a censored link the DPI regularly
// throttles UDP into short quiet spells, and QUIC is built to ride through those
// on the same connection (its connection ID survives the gap). A short timeout
// tears the tunnel down on every such spell and resets every flow through it -
// far more disruptive than the gap itself - then reconnects, adding still more
// downtime. The trade-off is that a genuinely dead/restarted server also takes
// this long to notice, but that is rare and the reconnect is automatic. Raise
// quic_idle_timeout further for links with longer blackouts.
const DefaultQuicIdleTimeout = 60 * time.Second

func QuicConfig(downMbps int, keepalive, idleTimeout time.Duration, obfsOverhead int) *quic.Config {
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
	// The idle timeout governs how long a transient quiet spell is ridden through
	// before the connection is torn down (see DefaultQuicIdleTimeout). The
	// keep-alive must stay comfortably below it, or a healthy but quiet link is
	// torn down between pings; cap it at half the idle timeout as a safety net on
	// top of the jitter window.
	if idleTimeout <= 0 {
		idleTimeout = DefaultQuicIdleTimeout
	}
	if keepalive <= 0 {
		keepalive = 6 * time.Second
	}
	if keepalive > idleTimeout/2 {
		keepalive = idleTimeout / 2
	}
	cfg := &quic.Config{
		EnableDatagrams:                true,
		MaxIdleTimeout:                 idleTimeout,
		KeepAlivePeriod:                keepalive,
		HandshakeIdleTimeout:           10 * time.Second,
		InitialStreamReceiveWindow:     window / 2,
		MaxStreamReceiveWindow:         window,
		InitialConnectionReceiveWindow: window,
		MaxConnectionReceiveWindow:     window * 2,
		MaxIncomingStreams:             1 << 16,
	}
	// Shrink the initial packet size by the obfuscation overhead so the datagram
	// that actually leaves the socket (QUIC packet + salt [+ STUN header]) is the
	// same size a plain QUIC connection would send - deliverable on any path that
	// carries plain QUIC. Path-MTU discovery is left on: its probes traverse the
	// same obfs wrapper, so it self-corrects to the true on-wire MTU from here.
	if obfsOverhead > 0 {
		cfg.InitialPacketSize = uint16(quicDefaultInitialPacketSize - obfsOverhead)
	}
	return cfg
}

// JitterKeepalive returns a randomized QUIC keep-alive period so the heartbeat
// stops being a fixed metronome a censor can lock onto. When minD/maxD are both
// unset it draws uniformly from a default [4s, 8s] window - frequent enough that
// several pings (each with quic-go's own PTO retries) fit inside the idle timeout,
// so a lossy censored link doesn't drop an otherwise-healthy connection during a
// quiet moment and force a reconnect (which also cold-starts congestion control).
// Kept well below QuicConfig's idle timeout, which also clamps as a safety net.
// When minD/maxD are set it draws from [minD, maxD]. A fresh value is picked per
// connection, so reconnects don't reveal a stable period either.
func JitterKeepalive(minD, maxD time.Duration) time.Duration {
	// Fill each bound independently so setting only one (quic_keepalive_min or
	// quic_keepalive_max) is honored instead of resetting both to the defaults.
	if minD <= 0 {
		minD = 4 * time.Second
	}
	if maxD <= 0 {
		maxD = 8 * time.Second
	}
	if minD > maxD {
		minD, maxD = maxD, minD
	}
	if minD == maxD {
		return minD
	}
	return minD + time.Duration(mrand.Int64N(int64(maxD-minD)+1))
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

// CloseWrite half-closes only the send side (a QUIC FIN), letting the peer finish
// replying. The TCP pump calls this when one copy direction ends cleanly, so the
// reverse direction is not truncated. quic.Stream.Close() closes just the send
// side, which is exactly a write half-close.
func (s *StreamConn) CloseWrite() error { return s.Stream.Close() }

// Close fully releases the stream at final teardown: it aborts the receive side
// (STOP_SENDING) in addition to FIN-ing the send side. Without the CancelRead, a
// stream whose peer never sent a FIN - an aborted/reset public connection - keeps
// its receive half open and holds a stream slot. Under heavy connection churn
// (e.g. a speed test opening many short flows) those leaked slots pile up until
// the peer's stream limit is hit and OpenStreamSync blocks, wedging the tunnel
// with a live-but-stuck connection that only a restart clears.
func (s *StreamConn) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

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
	stun      bool // prepend a mimicked STUN header so packets don't look full-entropy
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

// WithSTUN toggles STUN protocol-mimicry framing. When enabled, every datagram
// is prefixed with a fake STUN Binding-request header (magic cookie 0x2112A442)
// ahead of the salt+ciphertext body, so the packet's opening bytes match a
// benign, universally-allowed protocol instead of sitting in the full-entropy
// band the GFW "fully-encrypted-traffic" classifier flags. Both ends must agree
// (it's driven by the same shared config), and the receiver drops any datagram
// whose header lacks the cookie. Returns the receiver for call chaining.
func (o *ObfsPacketConn) WithSTUN(enabled bool) *ObfsPacketConn {
	o.stun = enabled
	return o
}

// writeSTUNHeader fills dst[:stunHeaderLen] with a plausible STUN Binding request
// whose message length advertises bodyLen. Only the magic cookie is load-bearing
// for classifier evasion; the transaction id is fresh random each packet.
func writeSTUNHeader(dst []byte, bodyLen int) {
	binary.BigEndian.PutUint16(dst[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint16(dst[2:4], uint16(bodyLen))
	binary.BigEndian.PutUint32(dst[4:8], stunMagicCookie)
	binary.LittleEndian.PutUint32(dst[8:12], uint32(mrand.Uint64()))
	binary.LittleEndian.PutUint32(dst[12:16], uint32(mrand.Uint64()))
	binary.LittleEndian.PutUint32(dst[16:20], uint32(mrand.Uint64()))
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
	hdr := 0
	if o.stun {
		hdr = stunHeaderLen
	}
	need := hdr + obfsSaltLen + len(p)
	if cap(s.out) < need {
		s.out = make([]byte, need)
	} else {
		s.out = s.out[:need]
	}
	if o.stun {
		// Advertise the salt+ciphertext length in the STUN header; the cookie is
		// what a DPI whitelist keys on.
		writeSTUNHeader(s.out[:stunHeaderLen], obfsSaltLen+len(p))
	}
	salt := s.out[hdr : hdr+obfsSaltLen]
	// The salt is prepended in the clear, so it need not be cryptographically
	// secret - only non-repeating so identical plaintext packets don't produce
	// identical ciphertext. A fast userspace PRNG replaces a per-packet
	// crypto/rand syscall, which was the dominant cost on the send path.
	binary.LittleEndian.PutUint64(salt, mrand.Uint64())
	s.keyIn = append(append(s.keyIn[:0], o.psk...), salt...)
	key := blake2b.Sum256(s.keyIn)
	xorWithKey(s.out[hdr+obfsSaltLen:], p, &key)
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
	hdr := 0
	if o.stun {
		hdr = stunHeaderLen
	}
	if len(o.readBuf) < len(p)+obfsSaltLen+hdr {
		o.readBuf = make([]byte, len(p)+obfsSaltLen+hdr)
	}
	for {
		n, addr, err := o.PacketConn.ReadFrom(o.readBuf)
		if err != nil {
			return 0, addr, err
		}
		if n < hdr+obfsSaltLen+1 {
			// Too short to be one of ours (or an unauthenticated probe): drop it
			// and keep reading instead of surfacing garbage to the QUIC stack.
			continue
		}
		if o.stun && binary.BigEndian.Uint32(o.readBuf[4:8]) != stunMagicCookie {
			// Missing STUN cookie: not one of ours - drop and keep reading.
			continue
		}
		salt := o.readBuf[hdr : hdr+obfsSaltLen]
		o.readKeyIn = append(append(o.readKeyIn[:0], o.psk...), salt...)
		key := blake2b.Sum256(o.readKeyIn)
		plainLen := n - hdr - obfsSaltLen
		if plainLen > len(p) {
			plainLen = len(p)
		}
		// XOR only the first plainLen bytes: the keystream is per-byte independent, so
		// this yields the correct leading plaintext even when the datagram is larger
		// than the caller's buffer. Slicing src to plainLen too (not the full n) keeps
		// xorWithKey - which iterates over len(src) - from writing past p[:plainLen].
		xorWithKey(p[:plainLen], o.readBuf[hdr+obfsSaltLen:hdr+obfsSaltLen+plainLen], &key)
		return plainLen, addr, nil
	}
}
