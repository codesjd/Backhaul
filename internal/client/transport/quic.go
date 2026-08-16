package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/musix/backhaul/internal/utils/congestion"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"

	quic "github.com/sagernet/quic-go"
	"github.com/sirupsen/logrus"
)

var authMagic = [4]byte{'B', 'H', 'Q', '1'}

type QuicConfig struct {
	RemoteAddr    string
	Token         string
	SnifferLog    string
	TunnelStatus  string
	Sniffer       bool
	WebPort       int
	KeepAlive     time.Duration
	DialTimeOut   time.Duration
	RetryInterval time.Duration
	TLSVerify     bool
	UpMbps        int
	DownMbps      int
	ObfsPassword  string
	Masquerade    bool
	ObfsSTUN      bool
	PortRange     []int
	KeepAliveMin  time.Duration
	KeepAliveMax  time.Duration
	IdleTimeout   time.Duration
}

type QuicTransport struct {
	config       *QuicConfig
	parentctx    context.Context
	ctx          context.Context
	cancel       context.CancelFunc
	logger       *logrus.Logger
	usageMonitor *web.Usage
	restartMutex sync.Mutex

	conn *quic.Conn

	// udpSessions maps a server-assigned session id to the local UDP socket
	// dialed to the target service.
	udpMu       sync.Mutex
	udpSessions map[uint32]*net.UDPConn
	reassembler *network.UDPReassembler
}

func NewQuicClient(parentCtx context.Context, config *QuicConfig, logger *logrus.Logger) *QuicTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	return &QuicTransport{
		config:       config,
		parentctx:    parentCtx,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		udpSessions:  make(map[uint32]*net.UDPConn),
		reassembler:  network.NewUDPReassembler(),
	}
}

func (c *QuicTransport) Start() {
	if c.config.WebPort > 0 {
		go c.usageMonitor.Monitor()
	}
	c.config.TunnelStatus = "Disconnected (QUIC)"
	go c.dialLoop()
}

func (c *QuicTransport) Restart() {
	if !c.restartMutex.TryLock() {
		c.logger.Warn("client is already restarting")
		return
	}
	defer c.restartMutex.Unlock()

	c.logger.Info("restarting client...")
	level := c.logger.Level
	c.logger.SetLevel(logrus.FatalLevel)

	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		c.conn.CloseWithError(0, "restart")
	}
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(c.parentctx)
	c.ctx = ctx
	c.cancel = cancel
	c.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", c.config.WebPort), ctx, c.config.SnifferLog, c.config.Sniffer, &c.config.TunnelStatus, c.logger)
	c.config.TunnelStatus = ""

	c.udpMu.Lock()
	for id, uc := range c.udpSessions {
		uc.Close()
		delete(c.udpSessions, id)
	}
	c.udpMu.Unlock()

	c.logger.SetLevel(level)
	go c.Start()
}

func (c *QuicTransport) dialLoop() {
	if !c.config.TLSVerify {
		c.logger.Warn("SECURITY: quic server certificate verification is OFF (tls_verify=false); the auth token can be harvested by an on-path party via TLS MITM. Set tls_verify=true once the server presents a verifiable certificate.")
	}
	if c.config.ObfsSTUN && c.config.ObfsPassword == "" {
		c.logger.Warn("quic: quic_obfs_stun is set but quic_obfs_password is empty; STUN mimicry needs the obfs layer and is therefore INACTIVE. Set quic_obfs_password (matching the server) to enable it.")
	}
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		if err := c.connectAndServe(); err != nil {
			c.logger.Errorf("quic: %v", err)
		}
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(c.config.RetryInterval):
		}
	}
}

func (c *QuicTransport) connectAndServe() error {
	tlsConf := network.QuicClientTLSConfig(c.config.RemoteAddr, c.config.TLSVerify, network.QuicALPNProtocols(c.config.Masquerade))
	serverAddr, err := net.ResolveUDPAddr("udp", c.config.RemoteAddr)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", c.config.RemoteAddr, err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return fmt.Errorf("open udp socket: %w", err)
	}
	var packetConn net.PacketConn = pc
	// Port hopping (innermost, closest to the wire): pick a random destination UDP
	// port within the range for this connection, so connections spread across the
	// range instead of all hitting one blockable port. The port is fixed for the
	// connection's life - rotating it mid-connection churned NAT/conntrack and
	// periodically broke the tunnel.
	if start, end, ok := network.ValidPortRange(c.config.PortRange); ok {
		packetConn = network.NewPortHoppingPacketConn(packetConn, serverAddr, start, end)
	} else if len(c.config.PortRange) > 0 {
		c.logger.Warnf("quic: ignoring invalid quic_port_range %v (want [start, end] within 1-65535)", c.config.PortRange)
	}
	if c.config.ObfsPassword != "" {
		packetConn = network.NewObfsPacketConn(packetConn, c.config.ObfsPassword).WithSTUN(c.config.ObfsSTUN)
	}
	// Jitter the keep-alive per connection so the heartbeat isn't a fixed metronome.
	keepalive := network.JitterKeepalive(c.config.KeepAliveMin, c.config.KeepAliveMax)
	dialCtx, cancel := context.WithTimeout(c.ctx, c.config.DialTimeOut)
	overhead := network.ObfsOverhead(c.config.ObfsPassword != "", c.config.ObfsSTUN)
	conn, err := quic.Dial(dialCtx, packetConn, serverAddr, tlsConf, network.QuicConfig(c.config.DownMbps, keepalive, c.config.IdleTimeout, overhead))
	cancel()
	if err != nil {
		packetConn.Close()
		// A dial timeout with obfuscation options on is almost always the server
		// silently dropping our packets because it isn't running the same options.
		// These must match on both ends: an obfs/STUN/masquerade mismatch looks
		// exactly like an unreachable server.
		if hint := c.mismatchHint(); hint != "" {
			return fmt.Errorf("dial %s: %w%s", c.config.RemoteAddr, err, hint)
		}
		return fmt.Errorf("dial %s: %w", c.config.RemoteAddr, err)
	}
	// Masquerade authenticates over HTTP/3 (an ordinary token-bearing request);
	// otherwise the classic magic-prefixed auth stream is used.
	if c.config.Masquerade {
		if err := c.authenticateH3(conn); err != nil {
			conn.CloseWithError(1, "auth failed")
			return fmt.Errorf("h3 auth: %w (check the token, and that the server has quic_masquerade = true on the same build)", err)
		}
	} else if err := c.authenticate(conn); err != nil {
		conn.CloseWithError(1, "auth failed")
		return fmt.Errorf("auth: %w", err)
	}
	// Enable Brutal congestion control for our send direction when a target
	// upload bandwidth is configured. Brutal paces at a fixed rate and ignores
	// loss - the Hysteria2 behaviour that keeps throughput up on lossy/censored
	// links. Left off (default quic-go CC) when quic_up_mbps is 0.
	if c.config.UpMbps > 0 {
		conn.SetCongestionControl(congestion.NewBrutalSender(uint64(c.config.UpMbps) * 1_000_000 / 8))
	}
	c.conn = conn
	c.config.TunnelStatus = "Connected (QUIC)"
	c.logger.Info("quic: control connection established successfully")

	go c.datagramLoop(conn)

	// Accept server-opened streams (one per forwarded TCP flow or UDP session)
	// until the connection dies.
	for {
		stream, err := conn.AcceptStream(c.ctx)
		if err != nil {
			c.config.TunnelStatus = "Disconnected (QUIC)"
			return fmt.Errorf("accept stream: %w", err)
		}
		go c.handleStream(conn, stream)
	}
}

// mismatchHint returns a human hint for a dial failure when obfuscation options
// are enabled, since a mismatched option on the server drops our packets and is
// indistinguishable from an unreachable server.
func (c *QuicTransport) mismatchHint() string {
	switch {
	case c.config.ObfsPassword != "" && c.config.ObfsSTUN:
		return " (server must run the same build with matching quic_obfs_password AND quic_obfs_stun)"
	case c.config.ObfsPassword != "":
		return " (server must run matching quic_obfs_password)"
	case c.config.Masquerade:
		return " (server must run the same build with quic_masquerade = true)"
	default:
		return ""
	}
}

// authenticateH3 performs the masquerade handshake: it wraps the dialed QUIC
// connection in a low-level HTTP/3 client, sends one token-bearing request, and
// requires a 2xx response. The raw client conn (rather than a full RoundTrip)
// lets us keep accepting the server's raw tunnel streams and QUIC datagrams on
// the same connection afterwards; the goroutine draining server-opened
// unidirectional streams keeps the HTTP/3 state machine (SETTINGS, QPACK) happy.
func (c *QuicTransport) authenticateH3(conn *quic.Conn) error {
	tr := network.NewH3ClientTransport()
	rc := tr.NewRawClientConn(conn)

	go func() {
		for {
			us, err := conn.AcceptUniStream(c.ctx)
			if err != nil {
				return
			}
			go rc.HandleUnidirectionalStream(us)
		}
	}()

	ctx, cancel := context.WithTimeout(c.ctx, c.config.DialTimeOut)
	defer cancel()
	rs, err := rc.OpenRequestStream(ctx)
	if err != nil {
		return fmt.Errorf("open request stream: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.config.RemoteAddr+"/", nil)
	if err != nil {
		return err
	}
	req.Header.Set(network.H3AuthHeader, network.H3AuthScheme+c.config.Token)
	if err := rs.SendRequestHeader(req); err != nil {
		return fmt.Errorf("send auth request: %w", err)
	}
	_ = rs.Close() // no request body
	resp, err := rs.ReadResponse()
	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server rejected token (status %d)", resp.StatusCode)
	}
	return nil
}

func (c *QuicTransport) authenticate(conn *quic.Conn) error {
	stream, err := conn.OpenStreamSync(c.ctx)
	if err != nil {
		return fmt.Errorf("open auth stream: %w", err)
	}
	defer stream.Close()

	var buf []byte
	buf = append(buf, authMagic[:]...)
	if err := writeAll(stream, buf); err != nil {
		return err
	}
	if err := network.WriteLPString(stream, c.config.Token); err != nil {
		return err
	}
	var bw [8]byte
	binary.BigEndian.PutUint32(bw[0:4], uint32(c.config.UpMbps))
	binary.BigEndian.PutUint32(bw[4:8], uint32(c.config.DownMbps))
	if err := writeAll(stream, bw[:]); err != nil {
		return err
	}

	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var status [1]byte
	if _, err := io.ReadFull(stream, status[:]); err != nil {
		return fmt.Errorf("read status: %w", err)
	}
	if status[0] != 1 {
		return fmt.Errorf("server rejected token")
	}
	_ = stream.SetReadDeadline(time.Time{})
	return nil
}

func (c *QuicTransport) handleStream(conn *quic.Conn, stream *quic.Stream) {
	var typ [1]byte
	if _, err := io.ReadFull(stream, typ[:]); err != nil {
		stream.CancelRead(1)
		return
	}
	switch typ[0] {
	case network.QuicStreamTCP:
		c.handleTCPStream(conn, stream)
	case network.QuicStreamUDP:
		c.handleUDPSession(conn, stream)
	default:
		c.logger.Warnf("quic: unknown stream type %d", typ[0])
		stream.CancelRead(1)
	}
}

func (c *QuicTransport) handleTCPStream(conn *quic.Conn, stream *quic.Stream) {
	target, err := network.ReadLPString(stream)
	if err != nil {
		c.logger.Debugf("quic: read tcp target: %v", err)
		stream.CancelRead(1)
		return
	}
	// A bare-port mapping (e.g. ports = ["6033"]) arrives as just "6033";
	// ResolveRemoteAddr normalizes it to 127.0.0.1:6033 and leaves host:port as-is.
	if _, target, err = network.ResolveRemoteAddr(target); err != nil {
		c.logger.Debugf("quic: invalid tcp target: %v", err)
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return
	}
	local, err := net.DialTimeout("tcp", target, c.config.DialTimeOut)
	if err != nil {
		c.logger.Debugf("quic: dial local tcp %s: %v", target, err)
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return
	}
	port := 0
	if ta, ok := local.RemoteAddr().(*net.TCPAddr); ok {
		port = ta.Port
	}
	handlers.TCPConnectionHandler(c.ctx, false, network.NewStreamConn(stream, conn), local, c.logger, c.usageMonitor, port, c.config.Sniffer)
}

func (c *QuicTransport) handleUDPSession(conn *quic.Conn, stream *quic.Stream) {
	var idBuf [4]byte
	if _, err := io.ReadFull(stream, idBuf[:]); err != nil {
		stream.CancelRead(1)
		return
	}
	id := binary.BigEndian.Uint32(idBuf[:])
	target, err := network.ReadLPString(stream)
	if err != nil {
		stream.CancelRead(1)
		return
	}
	// Normalize a bare-port target ("6033" -> "127.0.0.1:6033"); see handleTCPStream.
	if _, target, err = network.ResolveRemoteAddr(target); err != nil {
		c.logger.Debugf("quic: invalid udp target: %v", err)
		stream.CancelRead(1)
		return
	}
	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		c.logger.Debugf("quic: resolve udp %s: %v", target, err)
		stream.CancelRead(1)
		return
	}
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		c.logger.Debugf("quic: dial local udp %s: %v", target, err)
		stream.CancelRead(1)
		return
	}
	c.udpMu.Lock()
	c.udpSessions[id] = uc
	c.udpMu.Unlock()

	// Read responses from the local service and send them back as datagrams.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := uc.Read(buf)
			if err != nil {
				break
			}
			frags := network.FragmentUDP(id, network.NextUDPPacketID(), buf[:n])
			if frags == nil {
				continue // too large to fragment
			}
			for _, dgram := range frags {
				if err := conn.SendDatagram(dgram); err != nil {
					c.logger.Debugf("quic: send udp datagram: %v", err)
					break
				}
			}
		}
	}()

	// The registration stream stays open for the session's lifetime; a read that
	// returns tears the session down.
	buf := make([]byte, 1)
	_, _ = stream.Read(buf)

	c.udpMu.Lock()
	if cur, ok := c.udpSessions[id]; ok && cur == uc {
		delete(c.udpSessions, id)
	}
	c.udpMu.Unlock()
	uc.Close()
	_ = stream.Close()
}

// datagramLoop delivers inbound datagrams (public UDP packets relayed by the
// server) to the matching local UDP session.
func (c *QuicTransport) datagramLoop(conn *quic.Conn) {
	for {
		data, err := conn.ReceiveDatagram(c.ctx)
		if err != nil {
			return
		}
		id, payload, ok := c.reassembler.Push(data)
		if !ok {
			continue
		}
		c.udpMu.Lock()
		uc, ok := c.udpSessions[id]
		c.udpMu.Unlock()
		if !ok {
			continue
		}
		if _, err := uc.Write(payload); err != nil {
			c.logger.Debugf("quic: write to local udp: %v", err)
		}
	}
}

func writeAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}
