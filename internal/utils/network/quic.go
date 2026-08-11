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
// controller that sets a fixed send rate and ignores packet loss, which is what
// makes it fast on lossy censored links. A true Brutal has to live *inside* the
// QUIC stack, and neither mainline quic-go nor its tagged forks expose a public
// hook to swap the controller, so we approximate its intent with what the public
// API does allow: flow-control windows sized to the configured bandwidth-delay
// product, so a single fat flow is never throttled by the receiver's window
// (the usual ceiling on one QUIC flow). QuicConfig is the single seam where a
// real Brutal controller would be installed if a hooked quic-go is adopted.

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
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

const (
	// QuicALPN is the ALPN token both ends negotiate. It is deliberately
	// distinct from "h3" - this is not HTTP/3 - but a future masquerade mode
	// could switch it to "h3" to blend with real QUIC web traffic.
	QuicALPN = "backhaul-quic"

	// QuicMaxDatagramPayload bounds a single UDP payload carried in one QUIC
	// datagram, leaving headroom under a conservative path MTU for the QUIC
	// packet + our own datagram header. Larger UDP packets are dropped with a
	// warning (fragmentation is a documented follow-up), so this stays well
	// under the ~1200-byte floor quic-go can send unfragmented.
	QuicMaxDatagramPayload = 1100
)

// Server-opened stream types. The first byte of every stream the server opens to
// the client says what the stream is for.
const (
	QuicStreamTCP byte = 1 // followed by an LP-string target address; a forwarded TCP flow
	QuicStreamUDP byte = 2 // followed by uint32 session id + LP-string target address; registers a UDP session
)

// QuicServerTLSConfig loads the configured cert/key, or generates an in-memory
// self-signed certificate when none is set (the common case for this tool,
// where the operator controls both ends and pins trust via the token, not a CA).
func QuicServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
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
		NextProtos:   []string{QuicALPN},
	}, nil
}

// QuicClientTLSConfig builds the client side. verify follows the same contract
// as the ws/wss tls_verify knob: off by default (self-signed friendly), but
// while off an on-path party can MITM the token-bearing handshake.
func QuicClientTLSConfig(serverName string, verify bool) *tls.Config {
	host := serverName
	if h, _, err := net.SplitHostPort(serverName); err == nil {
		host = h
	}
	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !verify,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{QuicALPN},
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
