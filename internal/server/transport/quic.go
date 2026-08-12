package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/internal/utils/congestion"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/web"

	quic "github.com/sagernet/quic-go"
	"github.com/sirupsen/logrus"
)

// authMagic prefixes the client's auth stream so a stray or probing connection
// that speaks QUIC but not our protocol is rejected before the token is read.
var authMagic = [4]byte{'B', 'H', 'Q', '1'}

type QuicConfig struct {
	BindAddr     string
	Token        string
	Ports        []string
	Sniffer      bool
	WebPort      int
	SnifferLog   string
	TunnelStatus string
	Keepalive    time.Duration
	TLSCertFile  string
	TLSKeyFile   string
	UpMbps       int
	DownMbps     int
	ObfsPassword string
	Masquerade   bool
	ObfsSTUN     bool
	PortRange    []int
	KeepAliveMin time.Duration
	KeepAliveMax time.Duration
}

type QuicTransport struct {
	config       *QuicConfig
	parentctx    context.Context
	ctx          context.Context
	cancel       context.CancelFunc
	logger       *logrus.Logger
	usageMonitor *web.Usage
	restartMutex sync.Mutex
	listener     *quic.Listener

	// conn is the current authenticated client connection. Public listeners
	// open streams/datagrams on whatever is stored here; it is cleared when the
	// connection dies so a stale conn is never used.
	conn atomic.Pointer[quic.Conn]

	// udp session routing: sessionID -> session, for delivering return datagrams
	// back to the right public UDP client.
	udpMu       sync.Mutex
	udpSessions map[uint32]*quicUDPSession
	udpSeq      uint32
	reassembler *network.UDPReassembler
}

// quicUDPSession ties one public UDP client (clientAddr on pubConn) to a session
// id understood by the tunnel peer. The registration stream stays open for the
// session's lifetime; closing it tells the client to tear the session down.
type quicUDPSession struct {
	id         uint32
	clientAddr *net.UDPAddr
	pubConn    *net.UDPConn
	stream     *quic.Stream
	lastActive atomic.Int64 // unix nanos
}

func NewQuicServer(parentCtx context.Context, config *QuicConfig, logger *logrus.Logger) *QuicTransport {
	ctx, cancel := context.WithCancel(parentCtx)
	return &QuicTransport{
		config:       config,
		parentctx:    parentCtx,
		ctx:          ctx,
		cancel:       cancel,
		logger:       logger,
		usageMonitor: web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		udpSessions:  make(map[uint32]*quicUDPSession),
		reassembler:  network.NewUDPReassembler(),
	}
}

func (s *QuicTransport) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}
	s.config.TunnelStatus = "Disconnected (QUIC)"

	tlsConf, err := network.QuicServerTLSConfig(s.config.TLSCertFile, s.config.TLSKeyFile, network.QuicALPNProtocols(s.config.Masquerade))
	if err != nil {
		s.logger.Fatalf("quic: %v", err)
		return
	}
	if s.config.Masquerade {
		s.logger.Info("quic: HTTP/3 ALPN masquerade enabled")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", s.config.BindAddr)
	if err != nil {
		s.logger.Fatalf("quic: invalid bind address %s: %v", s.config.BindAddr, err)
		return
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.logger.Fatalf("quic: failed to bind %s: %v", s.config.BindAddr, err)
		return
	}
	var packetConn net.PacketConn = pc
	if s.config.ObfsPassword != "" {
		packetConn = network.NewObfsPacketConn(pc, s.config.ObfsPassword).WithSTUN(s.config.ObfsSTUN)
		s.logger.Info("quic: Salamander packet obfuscation enabled")
		if s.config.ObfsSTUN {
			s.logger.Info("quic: STUN protocol-mimicry framing enabled")
		}
	}
	// Port hopping is enforced at the network layer: the server binds one socket
	// and a firewall rule redirects the whole range to it. Surface a reminder so a
	// configured range without the matching rule isn't silently ineffective.
	if len(s.config.PortRange) == 2 && s.config.PortRange[0] > 0 && s.config.PortRange[1] > 0 {
		s.logger.Infof("quic: port hopping expected on UDP %d-%d; ensure a redirect rule targets this listener, e.g. "+
			"iptables -t nat -A PREROUTING -p udp --dport %d:%d -j REDIRECT --to-ports %d",
			s.config.PortRange[0], s.config.PortRange[1],
			s.config.PortRange[0], s.config.PortRange[1], udpAddr.Port)
	}
	keepalive := network.JitterKeepalive(s.config.Keepalive, s.config.KeepAliveMin, s.config.KeepAliveMax)
	ln, err := quic.Listen(packetConn, tlsConf, network.QuicConfig(s.config.DownMbps, keepalive))
	if err != nil {
		s.logger.Fatalf("quic: failed to listen on %s: %v", s.config.BindAddr, err)
		return
	}
	s.listener = ln
	s.logger.Infof("quic server listening on %s", s.config.BindAddr)

	go s.acceptTunnelConns()
	go s.parsePortMappings()

	<-s.ctx.Done()
}

func (s *QuicTransport) Restart() {
	if !s.restartMutex.TryLock() {
		s.logger.Warn("server restart already in progress, skipping restart attempt")
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Info("restarting server...")
	level := s.logger.Level
	s.logger.SetLevel(logrus.FatalLevel)

	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	if c := s.conn.Swap(nil); c != nil {
		c.CloseWithError(0, "restart")
	}
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.config.TunnelStatus = ""

	s.udpMu.Lock()
	s.udpSessions = make(map[uint32]*quicUDPSession)
	s.udpMu.Unlock()

	s.logger.SetLevel(level)
	go s.Start()
}

// acceptTunnelConns accepts QUIC connections from clients and authenticates each
// one before making it the active tunnel connection.
func (s *QuicTransport) acceptTunnelConns() {
	for {
		conn, err := s.listener.Accept(s.ctx)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Errorf("quic: accept failed: %v", err)
				continue
			}
		}
		go s.handleTunnelConn(conn)
	}
}

func (s *QuicTransport) handleTunnelConn(conn *quic.Conn) {
	// The client's very first stream is the auth stream.
	authCtx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	stream, err := conn.AcceptStream(authCtx)
	cancel()
	if err != nil {
		conn.CloseWithError(1, "auth timeout")
		return
	}
	if err := s.authenticate(stream); err != nil {
		s.logger.Warnf("quic: auth from %s failed: %v", conn.RemoteAddr(), err)
		_ = stream.Close()
		conn.CloseWithError(1, "auth failed")
		return
	}
	_ = stream.Close()

	// Enable Brutal congestion control for the server's send direction (the
	// download path to public clients) when a target bandwidth is configured.
	if s.config.UpMbps > 0 {
		conn.SetCongestionControl(congestion.NewBrutalSender(uint64(s.config.UpMbps) * 1_000_000 / 8))
	}

	s.logger.Infof("quic: client authenticated from %s", conn.RemoteAddr())
	s.config.TunnelStatus = "Connected (QUIC)"

	// Retire any previous connection - one client, one active tunnel.
	if prev := s.conn.Swap(conn); prev != nil && prev != conn {
		prev.CloseWithError(0, "superseded")
	}

	go s.datagramReturnLoop(conn)

	<-conn.Context().Done()
	// Only clear if this connection is still the active one.
	s.conn.CompareAndSwap(conn, nil)
	s.config.TunnelStatus = "Disconnected (QUIC)"
	s.logger.Infof("quic: client connection from %s closed", conn.RemoteAddr())
}

func (s *QuicTransport) authenticate(stream *quic.Stream) error {
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var magic [4]byte
	if _, err := io.ReadFull(stream, magic[:]); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}
	if magic != authMagic {
		return fmt.Errorf("bad magic")
	}
	token, err := network.ReadLPString(stream)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	var bw [8]byte
	if _, err := io.ReadFull(stream, bw[:]); err != nil {
		return fmt.Errorf("read bandwidth: %w", err)
	}
	if token != s.config.Token {
		_, _ = stream.Write([]byte{0})
		return fmt.Errorf("invalid token")
	}
	_ = stream.SetReadDeadline(time.Time{})
	_, err = stream.Write([]byte{1})
	return err
}

// currentConn returns the active tunnel connection, waiting briefly for a client
// to (re)connect rather than failing a just-arrived public connection outright.
func (s *QuicTransport) currentConn() *quic.Conn {
	if c := s.conn.Load(); c != nil {
		return c
	}
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return nil
		case <-timeout:
			return s.conn.Load()
		case <-ticker.C:
			if c := s.conn.Load(); c != nil {
				return c
			}
		}
	}
}

func (s *QuicTransport) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
		local, remote, ranged, start, end, ok := parseMapping(portMapping)
		if !ok {
			s.logger.Fatalf("invalid port mapping format: %s", portMapping)
			return
		}
		if ranged {
			for port := start; port <= end; port++ {
				la := fmt.Sprintf(":%d", port)
				ra := remote
				if ra == "" {
					ra = strconv.Itoa(port)
				}
				go s.startListeners(la, ra)
				time.Sleep(time.Millisecond)
			}
			continue
		}
		go s.startListeners(local, remote)
	}
}

func (s *QuicTransport) startListeners(localAddr, remoteAddr string) {
	go s.tcpListener(localAddr, remoteAddr)
	go s.udpListener(localAddr, remoteAddr)
	s.logger.Debugf("quic: listening on %s, forwarding to %s", localAddr, remoteAddr)
}

func (s *QuicTransport) tcpListener(localAddr, remoteAddr string) {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Fatalf("quic: failed to listen tcp on %s: %v", localAddr, err)
		return
	}
	defer ln.Close()
	go func() {
		<-s.ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Debugf("quic: tcp accept on %s: %v", localAddr, err)
				continue
			}
		}
		go s.handleTCP(conn, remoteAddr)
	}
}

func (s *QuicTransport) handleTCP(pub net.Conn, remoteAddr string) {
	conn := s.currentConn()
	if conn == nil {
		s.logger.Warn("quic: no active tunnel connection, dropping tcp connection")
		pub.Close()
		return
	}
	stream, err := conn.OpenStreamSync(s.ctx)
	if err != nil {
		s.logger.Errorf("quic: failed to open stream: %v", err)
		pub.Close()
		return
	}
	// Stream header: type + target address.
	if _, err := stream.Write([]byte{network.QuicStreamTCP}); err != nil {
		s.logger.Errorf("quic: failed to write stream header: %v", err)
		stream.CancelWrite(1)
		pub.Close()
		return
	}
	if err := network.WriteLPString(stream, remoteAddr); err != nil {
		s.logger.Errorf("quic: failed to write target addr: %v", err)
		stream.CancelWrite(1)
		pub.Close()
		return
	}
	port := 0
	if ta, ok := pub.LocalAddr().(*net.TCPAddr); ok {
		port = ta.Port
	}
	handlers.TCPConnectionHandler(s.ctx, false, pub, network.NewStreamConn(stream, conn), s.logger, s.usageMonitor, port, s.config.Sniffer)
}

func (s *QuicTransport) udpListener(localAddr, remoteAddr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		s.logger.Errorf("quic: resolve udp %s: %v", localAddr, err)
		return
	}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.logger.Errorf("quic: failed to listen udp on %s: %v", localAddr, err)
		return
	}
	defer pc.Close()
	go func() {
		<-s.ctx.Done()
		pc.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, src, err := pc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Debugf("quic: udp read on %s: %v", localAddr, err)
				return
			}
		}
		s.forwardUDP(pc, src, remoteAddr, buf[:n])
	}
}

func (s *QuicTransport) forwardUDP(pc *net.UDPConn, src *net.UDPAddr, remoteAddr string, data []byte) {
	conn := s.currentConn()
	if conn == nil {
		return
	}
	key := src.String()

	s.udpMu.Lock()
	sess := s.udpSessionByClient(key)
	s.udpMu.Unlock()

	if sess == nil {
		// Open the registration stream OUTSIDE the lock. OpenStreamSync can block
		// (peer stream limit / connection flow control); holding udpMu across it
		// would wedge the entire UDP path - every other forward and the datagram
		// return loop both need udpMu - which is the "stuck until restart" hang.
		stream, err := conn.OpenStreamSync(s.ctx)
		if err != nil {
			s.logger.Errorf("quic: failed to open udp session stream: %v", err)
			return
		}

		s.udpMu.Lock()
		if existing := s.udpSessionByClient(key); existing != nil {
			// A concurrent packet from the same source already registered a
			// session; drop the extra stream and reuse the existing one.
			s.udpMu.Unlock()
			stream.CancelWrite(0)
			_ = stream.Close()
			sess = existing
		} else {
			s.udpSeq++
			id := s.udpSeq
			sess = &quicUDPSession{id: id, clientAddr: src, pubConn: pc, stream: stream}
			sess.lastActive.Store(time.Now().UnixNano())
			s.udpSessions[id] = sess
			s.udpMu.Unlock()

			// Header writes can also block on flow control - keep them off the lock.
			hdr := []byte{network.QuicStreamUDP, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(hdr[1:], id)
			if _, err := stream.Write(hdr); err != nil {
				s.closeUDPSession(id)
				s.logger.Errorf("quic: failed to write udp session header: %v", err)
				return
			}
			if err := network.WriteLPString(stream, remoteAddr); err != nil {
				s.closeUDPSession(id)
				s.logger.Errorf("quic: failed to write udp target: %v", err)
				return
			}
			go s.watchUDPSession(id, stream)
		}
	}

	sess.lastActive.Store(time.Now().UnixNano())
	frags := network.FragmentUDP(sess.id, network.NextUDPPacketID(), data)
	if frags == nil {
		s.logger.Warnf("quic: udp packet from %s too large to fragment (%d bytes), dropping", src, len(data))
		return
	}
	for _, dgram := range frags {
		if err := conn.SendDatagram(dgram); err != nil {
			s.logger.Debugf("quic: send datagram failed: %v", err)
			return
		}
	}
	if s.config.Sniffer {
		s.usageMonitor.AddOrUpdatePort(int(portOf(pc.LocalAddr())), uint64(len(data)))
	}
}

// udpSessionByClient finds an existing session for a public client address.
// Caller holds udpMu.
func (s *QuicTransport) udpSessionByClient(key string) *quicUDPSession {
	for _, sess := range s.udpSessions {
		if sess.clientAddr.String() == key {
			return sess
		}
	}
	return nil
}

func (s *QuicTransport) closeUDPSession(id uint32) {
	s.udpMu.Lock()
	sess, ok := s.udpSessions[id]
	if ok {
		delete(s.udpSessions, id)
	}
	s.udpMu.Unlock()
	if ok && sess.stream != nil {
		sess.stream.CancelWrite(0)
		_ = sess.stream.Close()
	}
}

// watchUDPSession tears the session down when its registration stream closes or
// it goes idle.
func (s *QuicTransport) watchUDPSession(id uint32, stream *quic.Stream) {
	idleCheck := time.NewTicker(30 * time.Second)
	defer idleCheck.Stop()
	streamGone := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		_, _ = stream.Read(buf) // blocks until the peer closes/resets the stream
		close(streamGone)
	}()
	for {
		select {
		case <-s.ctx.Done():
			s.closeUDPSession(id)
			return
		case <-streamGone:
			s.closeUDPSession(id)
			return
		case <-idleCheck.C:
			s.udpMu.Lock()
			sess, ok := s.udpSessions[id]
			s.udpMu.Unlock()
			if !ok {
				return
			}
			if time.Since(time.Unix(0, sess.lastActive.Load())) > 60*time.Second {
				s.closeUDPSession(id)
				return
			}
		}
	}
}

// datagramReturnLoop reads datagrams the client sends back (service responses)
// and delivers them to the original public UDP client.
func (s *QuicTransport) datagramReturnLoop(conn *quic.Conn) {
	for {
		data, err := conn.ReceiveDatagram(s.ctx)
		if err != nil {
			return
		}
		id, payload, ok := s.reassembler.Push(data)
		if !ok {
			continue
		}
		s.udpMu.Lock()
		sess, ok := s.udpSessions[id]
		s.udpMu.Unlock()
		if !ok {
			continue
		}
		sess.lastActive.Store(time.Now().UnixNano())
		if _, err := sess.pubConn.WriteToUDP(payload, sess.clientAddr); err != nil {
			s.logger.Debugf("quic: udp write back failed: %v", err)
			continue
		}
		if s.config.Sniffer {
			s.usageMonitor.AddOrUpdatePort(int(portOf(sess.pubConn.LocalAddr())), uint64(len(payload)))
		}
	}
}

func portOf(a net.Addr) int {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.Port
	case *net.TCPAddr:
		return v.Port
	}
	return 0
}

// parseMapping parses a single "ports" entry. Supported forms:
//
//	"443"                  -> listen :443, forward to "443"
//	"443=1.2.3.4:80"       -> listen :443, forward to "1.2.3.4:80"
//	"127.0.0.1:443=host:80"-> listen 127.0.0.1:443, forward to "host:80"
//	"443-600"              -> range, each forwards to its own port number
//	"443-600=1.2.3.4:80"   -> range, all forward to "1.2.3.4:80"
func parseMapping(m string) (local, remote string, ranged bool, start, end int, ok bool) {
	parts := strings.SplitN(m, "=", 2)
	left := strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		remote = strings.TrimSpace(parts[1])
	}
	if strings.Contains(left, "-") {
		rp := strings.SplitN(left, "-", 2)
		a, err1 := strconv.Atoi(strings.TrimSpace(rp[0]))
		b, err2 := strconv.Atoi(strings.TrimSpace(rp[1]))
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || b < a {
			return "", "", false, 0, 0, false
		}
		return "", remote, true, a, b, true
	}
	if p, err := strconv.Atoi(left); err == nil {
		if p < 1 || p > 65535 {
			return "", "", false, 0, 0, false
		}
		local = fmt.Sprintf(":%d", p)
		if remote == "" {
			remote = strconv.Itoa(p)
		}
		return local, remote, false, 0, 0, true
	}
	// ip:port form on the left
	if _, _, err := net.SplitHostPort(left); err == nil {
		return left, remote, false, 0, 0, true
	}
	return "", "", false, 0, 0, false
}
