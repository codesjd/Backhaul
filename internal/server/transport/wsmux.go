package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/config" // for mode
	"github.com/musix/backhaul/internal/utils"
	"github.com/musix/backhaul/internal/utils/handlers"
	"github.com/musix/backhaul/internal/utils/network"
	"github.com/musix/backhaul/internal/utils/striping"
	"github.com/musix/backhaul/internal/web"
	"github.com/xtaci/smux"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type WsMuxTransport struct {
	config         *WsMuxConfig
	smuxConfig     *smux.Config
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan *smux.Session
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel *websocket.Conn
	usageMonitor   *web.Usage
	restartMutex   sync.Mutex
	streamCounter  int32
	sessionCounter int32
	stripedFlows   int32 // in-flight striped flows, bounded by the pool's stream budget

	// sessions is a live registry of pool sessions, used only when
	// StripeFactor > 1 so the striped dispatcher can pick several sessions
	// to open legs of the same logical connection on. The non-striped path
	// (StripeFactor <= 1, the default) never touches this.
	sessionsMu     sync.Mutex
	sessions       []*smux.Session
	stripeRotation uint32
	stripeGroupID  uint32

	fallbackProxy http.Handler
}

type WsMuxConfig struct {
	BindAddr             string
	Token                string
	SnifferLog           string
	TLSCertFile          string   // Path to the TLS certificate file
	TLSKeyFile           string   // Path to the TLS key file
	TLSCerts             []string // Optional: multiple cert files for SNI (multi-domain)
	TLSKeys              []string // Optional: key files aligned with TLSCerts
	TunnelStatus         string
	Ports                []string
	Nodelay              bool
	Sniffer              bool
	KeepAlive            time.Duration
	Heartbeat            time.Duration // in seconds
	ChannelSize          int
	MuxCon               int
	MuxVersion           int
	MaxFrameSize         int
	MaxReceiveBuffer     int
	MaxStreamBuffer      int
	WebPort              int
	Mode                 config.TransportType // ws or wss
	ProxyProtocol        bool
	Path                 string
	MuxKeepaliveDisabled bool
	StripeFactor         int
	Fallback             string // decoy backend for non-tunnel requests (host:port), optional
	TLSEngine            string // "go" (default) or "openssl" for wssmux TLS termination
}

func NewWSMuxServer(parentCtx context.Context, config *WsMuxConfig, logger *logrus.Logger) *WsMuxTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	// Build the decoy fallback proxy once, if configured. A bad address is
	// fatal here rather than silently disabling camouflage at runtime.
	fallbackProxy, err := network.NewFallbackProxy(config.Fallback)
	if err != nil {
		logger.Fatalf("invalid fallback address %q: %v", config.Fallback, err)
	}

	// Initialize the TcpTransport struct
	server := &WsMuxTransport{
		smuxConfig: &smux.Config{
			Version:           config.MuxVersion,
			KeepAliveDisabled: config.MuxKeepaliveDisabled,
			KeepAliveInterval: 20 * time.Second,
			KeepAliveTimeout:  40 * time.Second,
			MaxFrameSize:      config.MaxFrameSize,
			MaxReceiveBuffer:  config.MaxReceiveBuffer,
			MaxStreamBuffer:   config.MaxStreamBuffer,
		},
		config:         config,
		parentctx:      parentCtx,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		tunnelChannel:  make(chan *smux.Session, config.ChannelSize),
		localChannel:   make(chan LocalTCPConn, config.ChannelSize),
		reqNewConnChan: make(chan struct{}, config.ChannelSize),
		streamCounter:  0,
		sessionCounter: 0,
		controlChannel: nil, // will be set when a control connection is established
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
		fallbackProxy:  fallbackProxy,
	}

	return server
}

func (s *WsMuxTransport) Start() {
	// for  webui
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}

	s.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", s.config.Mode)

	go s.tunnelListener()

}

func (s *WsMuxTransport) Restart() {
	if !s.restartMutex.TryLock() {
		s.logger.Warn("server restart already in progress, skipping restart attempt")
		return
	}
	defer s.restartMutex.Unlock()

	s.logger.Info("restarting server...")

	// for removing timeout logs
	level := s.logger.Level
	s.logger.SetLevel(logrus.FatalLevel)

	if s.cancel != nil {
		s.cancel()
	}

	// Close control channel connection
	if s.controlChannel != nil {
		s.controlChannel.Close()
	}

	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithCancel(s.parentctx)
	s.ctx = ctx
	s.cancel = cancel

	// Re-initialize variables
	s.tunnelChannel = make(chan *smux.Session, s.config.ChannelSize)
	s.localChannel = make(chan LocalTCPConn, s.config.ChannelSize)
	s.reqNewConnChan = make(chan struct{}, s.config.ChannelSize)
	s.controlChannel = nil
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.config.TunnelStatus = ""
	s.streamCounter = 0
	s.sessionCounter = 0
	s.stripedFlows = 0

	s.sessionsMu.Lock()
	s.sessions = nil
	s.sessionsMu.Unlock()

	// set the log level again
	s.logger.SetLevel(level)

	go s.Start()
}

func (s *WsMuxTransport) channelHandler() {
	// A jittered timer (instead of a fixed-period ticker) so the heartbeat
	// cadence isn't perfectly periodic, which is an easy fingerprint for
	// traffic-pattern based DPI.
	heartbeatTimer := time.NewTimer(utils.JitterDuration(s.config.Heartbeat))
	defer heartbeatTimer.Stop()

	// Channel to receive the message or error
	messageChan := make(chan byte, 10)

	// Separate goroutine to continuously listen for messages
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return

			default:
				_, msg, err := s.controlChannel.ReadMessage()
				// Exit if there's an error
				if err != nil {
					if s.cancel != nil {
						s.logger.Error("failed to read from channel connection. ", err)
						go s.Restart()
					}
					return
				}
				if len(msg) == 0 {
					continue
				}
				messageChan <- msg[0]
			}
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			_ = utils.WriteControlSignal(s.controlChannel, utils.SG_Closed)
			return
		case <-s.reqNewConnChan:
			err := utils.WriteControlSignal(s.controlChannel, utils.SG_Chan)
			if err != nil {
				s.logger.Error("failed to send request new connection signal. ", err)
				go s.Restart()
				return
			}

		case <-heartbeatTimer.C:
			err := utils.WriteControlSignal(s.controlChannel, utils.SG_HB)
			if err != nil {
				s.logger.Errorf("failed to send heartbeat signal. Error: %v.", err)
				go s.Restart()
				return
			}
			s.logger.Debug("heartbeat signal sent successfully")
			heartbeatTimer.Reset(utils.JitterDuration(s.config.Heartbeat))

		case msg, ok := <-messageChan:
			if !ok {
				s.logger.Error("channel closed, likely due to an error in WebSocket read")
				return
			}
			switch msg {
			case utils.SG_HB:
				s.logger.Trace("heartbeat signal received successfully")

			case utils.SG_Closed:
				s.logger.Warn("control channel has been closed by the client")
				s.Restart()
				return

			default:
				s.logger.Errorf("unexpected response from channel: %v", msg)
				go s.Restart()
				return
			}

		}
	}
}

func (s *WsMuxTransport) tunnelListener() {
	addr := s.config.BindAddr
	basePath := network.NormalizeBasePath(s.config.Path)
	channelPath := basePath + "/channel"
	tunnelPathPrefix := basePath + "/tunnel"
	upgrader := websocket.Upgrader{
		ReadBufferSize:   64 * 1024,
		WriteBufferSize:  64 * 1024,
		HandshakeTimeout: 45 * time.Second,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// Create an HTTP server
	server := &http.Server{
		Addr:        addr,
		IdleTimeout: -1,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.logger.Tracef("received http request from %s", r.RemoteAddr)

			// A request is legitimate tunnel traffic only if it carries the
			// token AND targets the control or a tunnel path. Anything else -
			// a wrong/absent token, or a probe hitting "/" - is not upgraded:
			// if a decoy fallback is configured it is reverse-proxied there so
			// the origin looks like an ordinary website, otherwise it is
			// rejected as before.
			isTunnelPath := r.URL.Path == channelPath || strings.HasPrefix(r.URL.Path, tunnelPathPrefix)
			authHeader := r.Header.Get("Authorization")
			if authHeader != fmt.Sprintf("Bearer %v", s.config.Token) || !isTunnelPath {
				if s.fallbackProxy != nil {
					s.logger.Debugf("serving fallback for %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
					s.fallbackProxy.ServeHTTP(w, r)
					return
				}
				s.logger.Warnf("unauthorized request from %s, closing connection", r.RemoteAddr)
				http.Error(w, "unauthorized", http.StatusUnauthorized) // Send 401 Unauthorized response
				return
			}

			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				s.logger.Errorf("failed to upgrade connection from %s: %v", r.RemoteAddr, err)
				return
			}

			if r.URL.Path == channelPath {
				if s.controlChannel != nil {
					s.logger.Warn("new control channel requested.")
					s.controlChannel.Close()
					conn.Close()
					go s.Restart()
					return
				}

				s.controlChannel = conn

				s.logger.Info("control channel established successfully")

				numCPU := runtime.NumCPU()
				if numCPU > 4 {
					numCPU = 4 // Max allowed handler is 4
				}

				go s.channelHandler()
				go s.parsePortMappings()

				s.logger.Infof("starting %d handle loops on each CPU thread", numCPU)

				for i := 0; i < numCPU; i++ {
					go s.handleLoop()
				}

				if s.config.StripeFactor > 1 {
					go s.stripedDispatchLoop()
				}

				s.config.TunnelStatus = fmt.Sprintf("Connected (%s)", s.config.Mode)

			} else if strings.HasPrefix(r.URL.Path, tunnelPathPrefix) {
				session, err := smux.Client(conn.NetConn(), s.smuxConfig)
				if err != nil {
					s.logger.Errorf("failed to create MUX session for connection %s: %v", conn.RemoteAddr().String(), err)
					conn.Close()
					return
				}
				select {
				case s.tunnelChannel <- session: // ok
				default:
					s.logger.Warnf("tunnel listener channel is full, discarding TCP connection from %s", conn.LocalAddr().String())
					session.Close()
					conn.Close()
				}
			}
		}),
	}

	if s.config.Mode == config.WSMUX {
		go func() {
			s.logger.Infof("%s server starting, listening on %s", s.config.Mode, addr)
			if s.controlChannel == nil {
				s.logger.Infof("waiting for %s control channel connection", s.config.Mode)
			}
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	} else {
		go func() {
			engine := s.config.TLSEngine
			if engine == "" {
				engine = network.TLSEngineGo
			}
			s.logger.Infof("%s server starting, listening on %s (tls engine: %s)", s.config.Mode, addr, engine)
			if s.controlChannel == nil {
				s.logger.Infof("waiting for %s control channel connection", s.config.Mode)
			}
			certs, keys := network.ResolveCertPairs(s.config.TLSCertFile, s.config.TLSKeyFile, s.config.TLSCerts, s.config.TLSKeys)
			ln, err := network.NewTLSListener(s.config.TLSEngine, addr, certs, keys)
			if err != nil {
				s.logger.Fatalf("failed to create tls listener on %s: %v", addr, err)
			}
			if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	}

	<-s.ctx.Done()

	// close connection
	if s.controlChannel != nil {
		s.controlChannel.Close()
	}

	// Gracefully shutdown the server
	s.logger.Infof("shutting down the websocket server on %s", addr)
	if err := server.Shutdown(context.Background()); err != nil {
		s.logger.Errorf("Failed to gracefully shutdown the server: %v", err)
	}
}

func (s *WsMuxTransport) parsePortMappings() {
	for _, portMapping := range s.config.Ports {
		parts := strings.Split(portMapping, "=")

		var localAddr, remoteAddr string

		// Check if only a single port or a port range is provided (no "=" present)
		if len(parts) == 1 {
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = localPortOrRange // If no remote addr is provided, use the local port as the remote port

			// Check if it's a port range
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					s.logger.Fatalf("invalid port range format: %s", localPortOrRange)
				}

				// Parse and validate start and end ports
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					s.logger.Fatalf("invalid start port in range: %s", rangeParts[0])
				}

				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
					s.logger.Fatalf("invalid end port in range: %s", rangeParts[1])
				}

				// Create listeners for all ports in the range
				for port := startPort; port <= endPort; port++ {
					localAddr = fmt.Sprintf(":%d", port)
					go s.localListener(localAddr, strconv.Itoa(port)) // Use port as the remoteAddr
					time.Sleep(1 * time.Millisecond)                  // for wide port ranges
				}
				continue
			} else {
				// Handle single port case
				port, err := strconv.Atoi(localPortOrRange)
				if err != nil || port < 1 || port > 65535 {
					s.logger.Fatalf("invalid port format: %s", localPortOrRange)
				}
				localAddr = fmt.Sprintf(":%d", port)
			}
		} else if len(parts) == 2 {
			// Handle "local=remote" format
			localPortOrRange := strings.TrimSpace(parts[0])
			remoteAddr = strings.TrimSpace(parts[1])

			// Check if local port is a range
			if strings.Contains(localPortOrRange, "-") {
				rangeParts := strings.Split(localPortOrRange, "-")
				if len(rangeParts) != 2 {
					s.logger.Fatalf("invalid port range format: %s", localPortOrRange)
				}

				// Parse and validate start and end ports
				startPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				if err != nil || startPort < 1 || startPort > 65535 {
					s.logger.Fatalf("invalid start port in range: %s", rangeParts[0])
				}

				endPort, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				if err != nil || endPort < 1 || endPort > 65535 || endPort < startPort {
					s.logger.Fatalf("invalid end port in range: %s", rangeParts[1])
				}

				// Create listeners for all ports in the range
				for port := startPort; port <= endPort; port++ {
					localAddr = fmt.Sprintf(":%d", port)
					go s.localListener(localAddr, remoteAddr)
					time.Sleep(1 * time.Millisecond) // for wide port ranges
				}
				continue
			} else {
				// Handle single local port case
				port, err := strconv.Atoi(localPortOrRange)
				if err == nil && port > 1 && port < 65535 { // format port=remoteAddress
					localAddr = fmt.Sprintf(":%d", port)
				} else {
					localAddr = localPortOrRange // format ip:port=remoteAddress
				}
			}
		} else {
			s.logger.Fatalf("invalid port mapping format: %s", portMapping)
		}
		// Start listeners for single port
		go s.localListener(localAddr, remoteAddr)
	}
}

func (s *WsMuxTransport) localListener(localAddr string, remoteAddr string) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		s.logger.Fatalf("failed to start listener on %s: %v", localAddr, err)
		return
	}

	//close local listener after context cancellation
	defer listener.Close()

	go s.acceptLocalConn(listener, remoteAddr)

	s.logger.Infof("listener started successfully, listening on address: %s", listener.Addr().String())

	<-s.ctx.Done()
}

func (s *WsMuxTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
	for {
		select {
		case <-s.ctx.Done():
			return

		default:
			conn, err := listener.Accept()
			if err != nil {
				s.logger.Debugf("failed to accept connection on %s: %v", listener.Addr().String(), err)
				continue
			}

			// discard any non-tcp connection
			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				s.logger.Warnf("disarded non-TCP connection from %s", conn.RemoteAddr().String())
				conn.Close()
				continue
			}

			// trying to enable tcpnodelay
			if !s.config.Nodelay {
				if err := tcpConn.SetNoDelay(s.config.Nodelay); err != nil {
					s.logger.Warnf("failed to set TCP_NODELAY for %s: %v", tcpConn.RemoteAddr().String(), err)
				} else {
					s.logger.Tracef("TCP_NODELAY disabled for %s", tcpConn.RemoteAddr().String())
				}
			}

			// Set keep-alive settings
			if err := tcpConn.SetKeepAlive(true); err != nil {
				s.logger.Warnf("failed to enable TCP keep-alive for %s: %v", tcpConn.RemoteAddr().String(), err)
			} else {
				s.logger.Tracef("TCP keep-alive enabled for %s", tcpConn.RemoteAddr().String())
			}
			if err := tcpConn.SetKeepAlivePeriod(s.config.KeepAlive); err != nil {
				s.logger.Warnf("failed to set TCP keep-alive period for %s: %v", tcpConn.RemoteAddr().String(), err)
			}

			select {
			case s.localChannel <- LocalTCPConn{conn: conn, remoteAddr: remoteAddr, timeCreated: time.Now().UnixMilli()}:
				s.logger.Debugf("accepted incoming TCP connection from %s", tcpConn.RemoteAddr().String())

				// +1 for stream counter
				atomic.AddInt32(&s.streamCounter, 1)

				if atomic.LoadInt32(&s.streamCounter) >= atomic.LoadInt32(&s.sessionCounter)*int32(s.config.MuxCon) {
					s.logger.Tracef("stream counter: %v, session counter: %v", atomic.LoadInt32(&s.streamCounter), atomic.LoadInt32(&s.sessionCounter))
					// Attempt to request a new connection
					select {
					case s.reqNewConnChan <- struct{}{}:
					default:
						s.logger.Warn("failed to request new connection. channel is full")
					}
				}

			default: // channel is full, discard the connection
				s.logger.Warnf("local listener channel is full, discarding TCP connection from %s", tcpConn.LocalAddr().String())
				conn.Close()
			}
		}
	}

}

func (s *WsMuxTransport) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case session := <-s.tunnelChannel:
			// +1 for session counter
			atomic.AddInt32(&s.sessionCounter, 1)

			if s.config.StripeFactor > 1 {
				s.registerSession(session)
				go func(sess *smux.Session) {
					<-sess.CloseChan()
					s.unregisterSession(sess)
					atomic.AddInt32(&s.sessionCounter, -1)
				}(session)
				continue
			}

			go s.handleSession(session)
		}
	}
}

// registerSession/unregisterSession maintain the live-session pool the
// striped dispatcher picks legs from. Only used when StripeFactor > 1.
func (s *WsMuxTransport) registerSession(session *smux.Session) {
	s.sessionsMu.Lock()
	s.sessions = append(s.sessions, session)
	s.sessionsMu.Unlock()
}

func (s *WsMuxTransport) unregisterSession(session *smux.Session) {
	s.sessionsMu.Lock()
	for i, sess := range s.sessions {
		if sess == session {
			s.sessions = append(s.sessions[:i], s.sessions[i+1:]...)
			break
		}
	}
	s.sessionsMu.Unlock()
}

// openStripedLegs opens one stream on each of up to n distinct live
// sessions, rotating the starting point on every call so legs aren't always
// pulled from the same first few sessions.
func (s *WsMuxTransport) openStripedLegs(n int) ([]*smux.Stream, error) {
	s.sessionsMu.Lock()
	avail := make([]*smux.Session, len(s.sessions))
	copy(avail, s.sessions)
	s.sessionsMu.Unlock()

	if len(avail) == 0 {
		return nil, fmt.Errorf("no active pool sessions available for striping")
	}
	if n > len(avail) {
		n = len(avail)
	}

	start := int(atomic.AddUint32(&s.stripeRotation, 1))
	streams := make([]*smux.Stream, 0, n)
	for i := 0; i < n; i++ {
		sess := avail[(start+i)%len(avail)]
		stream, err := sess.OpenStream()
		if err != nil {
			for _, st := range streams {
				st.Close()
			}
			return nil, fmt.Errorf("failed to open stripe leg: %w", err)
		}
		streams = append(streams, stream)
	}
	return streams, nil
}

// stripedDispatchLoop replaces the per-session handleSession loop when
// StripeFactor > 1: for each incoming local connection it grabs one stream
// from several distinct pool sessions instead of one stream from one
// session, so the flow isn't pinned to a single underlying TCP connection.
func (s *WsMuxTransport) stripedDispatchLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case incomingConn := <-s.localChannel:
			// Set up each flow in its own goroutine. Opening the legs and writing
			// the per-leg stripe headers can block on smux flow control when the
			// pool is busy carrying bulk data; doing it inline would serialize
			// every new flow's startup behind that one blocking write (the
			// non-striped path avoids this by dispatching per session). Handing
			// off keeps a slow setup from inflating the time-to-first-byte of
			// every other pending connection.
			go s.dispatchStriped(incomingConn)
		}
	}
}

// dispatchStriped opens the striped legs for one incoming connection, sends the
// per-leg headers, and pumps the flow. streamCounter (incremented in
// localListener when the connection was accepted) is decremented exactly once
// for every connection that leaves this pipeline - dropped here, or handed to a
// handler that later finishes - mirroring handleSession on the non-striped path.
// A connection requeued onto localChannel keeps its count, since it passes
// through here again.
func (s *WsMuxTransport) dispatchStriped(incomingConn LocalTCPConn) {
	if time.Now().UnixMilli()-incomingConn.timeCreated > 3000 { // 3000ms
		s.logger.Debugf("timeouted local connection: %d ms", time.Now().UnixMilli()-incomingConn.timeCreated)
		incomingConn.conn.Close()
		atomic.AddInt32(&s.streamCounter, -1)
		return
	}

	// Bound concurrent striped flows to the pool's stream budget
	// (sessionCounter*MuxCon): each flow opens StripeFactor legs and drives a
	// local dial, so running more flows than the sessions can carry just floods
	// the pool and the local service. The bound scales with the live pool - as
	// load makes streamCounter request more sessions, more flows are admitted -
	// mirroring the non-striped path's per-session MuxCon cap. In the common
	// under-budget case the slot is taken immediately (no added latency); only a
	// genuinely saturated pool makes a new flow wait instead of piling on.
	if !s.acquireStripedSlot() {
		// ctx cancelled while waiting for a slot
		incomingConn.conn.Close()
		atomic.AddInt32(&s.streamCounter, -1)
		return
	}

	legs, err := s.openStripedLegs(s.config.StripeFactor)
	if err != nil {
		// Release the slot before sleeping/requeueing so a transient open
		// failure doesn't shrink the admission budget for everyone else.
		atomic.AddInt32(&s.stripedFlows, -1)
		s.logger.Tracef("striped dispatch: %v, retrying shortly", err)
		time.Sleep(100 * time.Millisecond)
		// Refresh the accept timestamp so a connection that waited for the
		// pool to warm up isn't immediately dropped by the 3s setup timeout
		// on the next attempt.
		incomingConn.timeCreated = time.Now().UnixMilli()
		s.requeueOrDrop(incomingConn)
		return
	}
	defer atomic.AddInt32(&s.stripedFlows, -1)

	gid := atomic.AddUint32(&s.stripeGroupID, 1)
	for i, stream := range legs {
		if err := utils.SendStripeHeader(stream, gid, uint8(i), uint8(len(legs)), incomingConn.remoteAddr); err != nil {
			s.logger.Tracef("failed to send stripe header: %v", err)
			for _, st := range legs {
				st.Close()
			}
			incomingConn.timeCreated = time.Now().UnixMilli()
			s.requeueOrDrop(incomingConn)
			return
		}
	}

	conns := make([]net.Conn, len(legs))
	for i, st := range legs {
		conns[i] = st
	}
	stripedConn := striping.New(conns, striping.DefaultChunkSize)

	defer atomic.AddInt32(&s.streamCounter, -1)
	handlers.TCPConnectionHandler(s.ctx, s.config.ProxyProtocol, incomingConn.conn, stripedConn, s.logger, s.usageMonitor, incomingConn.conn.LocalAddr().(*net.TCPAddr).Port, s.config.Sniffer)
}

// acquireStripedSlot reserves one in-flight striped-flow slot, blocking (with a
// short poll) while the pool is at its stream budget so a burst of new flows
// can't open more legs than the sessions can carry. The budget is
// sessionCounter*MuxCon streams and each flow uses StripeFactor legs, so at most
// sessionCounter*MuxCon/StripeFactor flows run at once; the budget grows as the
// pool does. Returns false only if the transport is shutting down.
func (s *WsMuxTransport) acquireStripedSlot() bool {
	sf := int32(s.config.StripeFactor)
	if sf < 1 {
		sf = 1
	}
	for {
		active := atomic.LoadInt32(&s.stripedFlows)
		budget := atomic.LoadInt32(&s.sessionCounter) * int32(s.config.MuxCon)
		if budget < sf {
			budget = sf // always admit at least one flow while the pool warms up
		}
		if (active+1)*sf <= budget {
			if atomic.CompareAndSwapInt32(&s.stripedFlows, active, active+1) {
				return true
			}
			continue // lost the CAS race, re-read and retry
		}
		// At the stream budget: ask the client to dial another pool session
		// so the admission ceiling can rise. With mux_stripe > 1 each flow
		// consumes StripeFactor streams, so the accept-path's
		// streamCounter>=sessions*MuxCon check under-counts and may never
		// fire - this is what actually grows the pool under striping load.
		select {
		case s.reqNewConnChan <- struct{}{}:
		default:
		}
		select {
		case <-s.ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// requeueOrDrop puts a connection whose striped setup could not complete back on
// localChannel to be retried, or closes it (and releases its streamCounter slot)
// if the channel is full.
func (s *WsMuxTransport) requeueOrDrop(incomingConn LocalTCPConn) {
	select {
	case s.localChannel <- incomingConn:
	default:
		incomingConn.conn.Close()
		atomic.AddInt32(&s.streamCounter, -1)
	}
}

func (s *WsMuxTransport) handleSession(session *smux.Session) {
	counter := make(chan struct{}, s.config.MuxCon)
	defer session.Close()
	defer close(counter)

	for {
		// +1 for mux connection counter
		counter <- struct{}{}

		select {
		case <-s.ctx.Done():
			return

		case incomingConn := <-s.localChannel:
			if time.Now().UnixMilli()-incomingConn.timeCreated > 3000 { // 3000ms
				s.logger.Debugf("timeouted local connection: %d ms", time.Now().UnixMilli()-incomingConn.timeCreated)
				incomingConn.conn.Close()

				// Decrement the counter
				atomic.AddInt32(&s.streamCounter, -1)
				<-counter
				continue
			}

			stream, err := session.OpenStream()
			if err != nil {
				s.handleSessionError(&incomingConn, err)
				return
			}

			// Send the target port over the tunnel connection
			if err := utils.SendBinaryString(stream, incomingConn.remoteAddr); err != nil {
				s.logger.Tracef("failed to send address over stream: %v", err)
				stream.Close()
				// Put local connection back to local channel without blocking
				// the session loop if the channel is full.
				select {
				case s.localChannel <- incomingConn:
				default:
					incomingConn.conn.Close()
					atomic.AddInt32(&s.streamCounter, -1)
				}
				<-counter
				continue
			}

			// Handle data exchange between connections
			go func() {
				handlers.TCPConnectionHandler(s.ctx, s.config.ProxyProtocol, incomingConn.conn, stream, s.logger, s.usageMonitor, incomingConn.conn.LocalAddr().(*net.TCPAddr).Port, s.config.Sniffer)
				atomic.AddInt32(&s.streamCounter, -1)
				<-counter // read signal from the channel
			}()
		}
	}
}

func (s *WsMuxTransport) handleSessionError(incomingConn *LocalTCPConn, err error) {
	s.logger.Tracef("failed to handle session: %v", err)

	// decrease session value
	atomic.AddInt32(&s.sessionCounter, -1)

	// Put local connection back to local channel without blocking forever if
	// the channel is already full (that used to deadlock the session goroutine
	// and permanently leak its MuxCon slot).
	select {
	case s.localChannel <- *incomingConn:
	default:
		incomingConn.conn.Close()
		atomic.AddInt32(&s.streamCounter, -1)
	}

	// Attempt to request a new connection
	select {
	case s.reqNewConnChan <- struct{}{}:
	default:
		s.logger.Warn("request new connection channel is full")
	}
}
