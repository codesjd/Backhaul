package transport

import (
	"context"
	"fmt"
	"io"
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
	"github.com/musix/backhaul/internal/web"
	"github.com/xtaci/smux"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// H2MuxTransport is the server side of the h2mux/h2smux transports: smux
// multiplexing runs over a pair of HTTP/2 request/response exchanges
// (a long-lived GET for server->client bytes, short bounded POSTs for
// client->server bytes - see network.H2SplitConn) instead of a WebSocket
// connection or a single duplex POST. CDNs/WAFs that buffer an entire
// request body before forwarding it break a single unbounded duplex POST,
// but generally pass bounded POSTs and streamed GET responses through
// untouched, since those match ordinary upload/download traffic.
//
// Unlike WS, an HTTP/2 request can't be hijacked into a raw net.Conn, so
// each GET request's handler goroutine stays blocked for the lifetime of
// the tunnel it represents, draining queued outbound bytes into the
// response, instead of handing off a detached connection.
type H2MuxTransport struct {
	config         *H2MuxConfig
	smuxConfig     *smux.Config
	parentctx      context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	logger         *logrus.Logger
	tunnelChannel  chan *smux.Session
	localChannel   chan LocalTCPConn
	reqNewConnChan chan struct{}
	controlChannel *network.H2SplitConn
	tunnelConns    map[string]*network.H2SplitConn
	tunnelConnsMu  sync.Mutex
	usageMonitor   *web.Usage
	restartMutex   sync.Mutex
	streamCounter  int32
	sessionCounter int32
}

type H2MuxConfig struct {
	BindAddr         string
	Token            string
	SnifferLog       string
	TLSCertFile      string // Path to the TLS certificate file
	TLSKeyFile       string // Path to the TLS key file
	TunnelStatus     string
	Ports            []string
	Nodelay          bool
	Sniffer          bool
	KeepAlive        time.Duration
	Heartbeat        time.Duration // in seconds
	ChannelSize      int
	MuxCon           int
	MuxVersion       int
	MaxFrameSize     int
	MaxReceiveBuffer int
	MaxStreamBuffer  int
	WebPort          int
	Mode             config.TransportType // h2mux or h2smux
	ProxyProtocol    bool
	Path             string
}

func NewH2MuxServer(parentCtx context.Context, config *H2MuxConfig, logger *logrus.Logger) *H2MuxTransport {
	// Create a derived context from the parent context
	ctx, cancel := context.WithCancel(parentCtx)

	server := &H2MuxTransport{
		smuxConfig: &smux.Config{
			Version:           config.MuxVersion,
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
		tunnelConns:    make(map[string]*network.H2SplitConn),
		streamCounter:  0,
		sessionCounter: 0,
		controlChannel: nil, // will be set when a control connection is established
		usageMonitor:   web.NewDataStore(fmt.Sprintf(":%v", config.WebPort), ctx, config.SnifferLog, config.Sniffer, &config.TunnelStatus, logger),
	}

	return server
}

func (s *H2MuxTransport) Start() {
	if s.config.WebPort > 0 {
		go s.usageMonitor.Monitor()
	}

	s.config.TunnelStatus = fmt.Sprintf("Disconnected (%s)", s.config.Mode)

	go s.tunnelListener()
}

func (s *H2MuxTransport) Restart() {
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
	s.tunnelConnsMu.Lock()
	s.tunnelConns = make(map[string]*network.H2SplitConn)
	s.tunnelConnsMu.Unlock()
	s.controlChannel = nil
	s.usageMonitor = web.NewDataStore(fmt.Sprintf(":%v", s.config.WebPort), ctx, s.config.SnifferLog, s.config.Sniffer, &s.config.TunnelStatus, s.logger)
	s.config.TunnelStatus = ""
	s.streamCounter = 0
	s.sessionCounter = 0

	// set the log level again
	s.logger.SetLevel(level)

	go s.Start()
}

// channelHandler owns the control channel's HTTP/2 stream for its entire
// lifetime: it blocks until the stream should end, which is what keeps the
// underlying HTTP handler (and thus the h2 stream) from returning early.
func (s *H2MuxTransport) channelHandler() {
	ticker := time.NewTicker(s.config.Heartbeat)
	defer ticker.Stop()

	// Channel to receive the message or error
	messageChan := make(chan byte, 10)

	// Separate goroutine to continuously listen for messages. Control
	// signals are always exactly one byte (see internal/utils/signals.go),
	// so a raw single-byte read is an unambiguous message boundary.
	go func() {
		buf := make([]byte, 1)
		for {
			select {
			case <-s.ctx.Done():
				return

			default:
				if _, err := io.ReadFull(s.controlChannel, buf); err != nil {
					if s.cancel != nil {
						s.logger.Error("failed to read from channel connection. ", err)
						go s.Restart()
					}
					return
				}
				messageChan <- buf[0]
			}
		}
	}()

	for {
		select {
		case <-s.ctx.Done():
			_, _ = s.controlChannel.Write([]byte{utils.SG_Closed})
			return
		case <-s.reqNewConnChan:
			if _, err := s.controlChannel.Write([]byte{utils.SG_Chan}); err != nil {
				s.logger.Error("failed to send request new connection signal. ", err)
				go s.Restart()
				return
			}

		case <-ticker.C:
			if _, err := s.controlChannel.Write([]byte{utils.SG_HB}); err != nil {
				s.logger.Errorf("failed to send heartbeat signal. Error: %v.", err)
				go s.Restart()
				return
			}
			s.logger.Debug("heartbeat signal sent successfully")

		case msg, ok := <-messageChan:
			if !ok {
				s.logger.Error("channel closed, likely due to an error in h2 read")
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

func (s *H2MuxTransport) tunnelListener() {
	addr := s.config.BindAddr
	basePath := network.NormalizeBasePath(s.config.Path)
	channelPath := basePath + "/channel"
	tunnelPathPrefix := basePath + "/tunnel"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.logger.Tracef("received http request from %s", r.RemoteAddr)

		authHeader := r.Header.Get("Authorization")
		if authHeader != fmt.Sprintf("Bearer %v", s.config.Token) {
			s.logger.Warnf("unauthorized request from %s, closing connection", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch {
		case r.URL.Path == channelPath && r.Method == http.MethodGet:
			if s.controlChannel != nil {
				s.logger.Warn("new control channel requested.")
				s.controlChannel.Close()
				go s.Restart()
				return
			}

			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unsupported", http.StatusInternalServerError)
				return
			}

			conn := network.NewH2SplitConn()
			s.controlChannel = conn

			setNoBufferHeaders(w)
			w.WriteHeader(http.StatusOK)
			flusher.Flush()

			s.logger.Info("control channel established successfully")

			numCPU := runtime.NumCPU()
			if numCPU > 4 {
				numCPU = 4 // Max allowed handler is 4
			}

			go s.parsePortMappings()
			go s.channelHandler()

			s.logger.Infof("starting %d handle loops on each CPU thread", numCPU)

			for i := 0; i < numCPU; i++ {
				go s.handleLoop()
			}

			s.config.TunnelStatus = fmt.Sprintf("Connected (%s)", s.config.Mode)

			// Blocks draining outbound bytes into the GET response for as
			// long as the control channel is alive, which is what keeps
			// this HTTP/2 stream open (no hijack is possible here).
			s.drainOutbound(conn, w, flusher, r)

		case r.URL.Path == channelPath && r.Method == http.MethodPost:
			if s.controlChannel == nil {
				http.Error(w, "no control channel", http.StatusGone)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 4096)) // control signals are tiny
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			s.controlChannel.PushInbound(body)
			w.WriteHeader(http.StatusOK)

		case strings.HasPrefix(r.URL.Path, tunnelPathPrefix) && r.Method == http.MethodGet:
			id := r.URL.Path

			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming unsupported", http.StatusInternalServerError)
				return
			}

			conn := network.NewH2SplitConn()
			s.tunnelConnsMu.Lock()
			s.tunnelConns[id] = conn
			s.tunnelConnsMu.Unlock()

			session, err := smux.Client(conn, s.smuxConfig)
			if err != nil {
				s.logger.Errorf("failed to create MUX session for connection %s: %v", r.RemoteAddr, err)
				conn.Close()
				s.removeTunnelConn(id)
				return
			}
			select {
			case s.tunnelChannel <- session: // ok
			default:
				s.logger.Warnf("tunnel listener channel is full, discarding connection from %s", r.RemoteAddr)
				conn.Close()
				session.Close()
				s.removeTunnelConn(id)
				return
			}

			setNoBufferHeaders(w)
			w.WriteHeader(http.StatusOK)
			flusher.Flush()

			s.drainOutbound(conn, w, flusher, r)
			s.removeTunnelConn(id)

		case strings.HasPrefix(r.URL.Path, tunnelPathPrefix) && r.Method == http.MethodPost:
			id := r.URL.Path

			s.tunnelConnsMu.Lock()
			conn, ok := s.tunnelConns[id]
			s.tunnelConnsMu.Unlock()
			if !ok {
				http.Error(w, "unknown tunnel", http.StatusGone)
				return
			}

			body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.config.MaxFrameSize)+4096))
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if !conn.PushInbound(body) {
				http.Error(w, "closed", http.StatusGone)
				return
			}
			w.WriteHeader(http.StatusOK)

		default:
			http.NotFound(w, r)
		}
	})

	h2s := &http2.Server{}

	var finalHandler http.Handler = handler
	server := &http.Server{
		Addr:        addr,
		IdleTimeout: -1,
	}

	if s.config.Mode == config.H2MUX {
		// Cleartext h2c, with a graceful fallback to plain HTTP/1.1 framing
		// for intermediaries (e.g. a reverse proxy) that don't speak h2c.
		finalHandler = h2c.NewHandler(handler, h2s)
		server.Handler = finalHandler

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
		server.Handler = finalHandler
		if err := http2.ConfigureServer(server, h2s); err != nil {
			s.logger.Fatalf("failed to configure h2 server: %v", err)
		}

		go func() {
			s.logger.Infof("%s server starting, listening on %s", s.config.Mode, addr)
			if s.controlChannel == nil {
				s.logger.Infof("waiting for %s control channel connection", s.config.Mode)
			}
			if err := server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				s.logger.Fatalf("failed to listen on %s: %v", addr, err)
			}
		}()
	}

	<-s.ctx.Done()

	if s.controlChannel != nil {
		s.controlChannel.Close()
	}

	s.tunnelConnsMu.Lock()
	for _, conn := range s.tunnelConns {
		conn.Close()
	}
	s.tunnelConnsMu.Unlock()

	s.logger.Infof("shutting down the h2 server on %s", addr)
	if err := server.Shutdown(context.Background()); err != nil {
		s.logger.Errorf("Failed to gracefully shutdown the server: %v", err)
	}
}

// setNoBufferHeaders tells intermediaries not to cache or buffer this GET
// response. A plain streamed GET (no Upgrade header, no chunked/SSE
// signaling) looks like ordinary cacheable content to a CDN/reverse proxy
// by default, which either serves a cached response instead of reaching
// origin, or buffers the response until it decides whether to cache it -
// either way breaking the "server writes over time" streaming this relies
// on. X-Accel-Buffering is nginx-specific; Cache-Control/Pragma cover the
// CDN edge and any other intermediary.
func setNoBufferHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Content-Type", "application/octet-stream")
}

// drainOutbound blocks writing queued outbound bytes (queued via conn's
// Write, called from elsewhere - e.g. channelHandler or a smux session) to
// the GET response as they arrive, until the connection closes or the
// request's context is cancelled (client disconnected). Since HTTP/2
// requests can't be hijacked, this is what keeps the response stream open
// for the connection's lifetime.
func (s *H2MuxTransport) drainOutbound(conn *network.H2SplitConn, w http.ResponseWriter, flusher http.Flusher, r *http.Request) {
	for {
		chunk, ok := conn.NextOutbound(r.Context().Done())
		if !ok {
			return
		}
		if _, err := w.Write(chunk); err != nil {
			conn.Close()
			return
		}
		flusher.Flush()
	}
}

func (s *H2MuxTransport) removeTunnelConn(id string) {
	s.tunnelConnsMu.Lock()
	delete(s.tunnelConns, id)
	s.tunnelConnsMu.Unlock()
}

func (s *H2MuxTransport) parsePortMappings() {
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

func (s *H2MuxTransport) localListener(localAddr string, remoteAddr string) {
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

func (s *H2MuxTransport) acceptLocalConn(listener net.Listener, remoteAddr string) {
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

func (s *H2MuxTransport) handleLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return

		case session := <-s.tunnelChannel:
			// +1 for session counter
			atomic.AddInt32(&s.sessionCounter, 1)

			go s.handleSession(session)
		}
	}
}

func (s *H2MuxTransport) handleSession(session *smux.Session) {
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
				// Put local connection back to local channel
				s.localChannel <- incomingConn
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

func (s *H2MuxTransport) handleSessionError(incomingConn *LocalTCPConn, err error) {
	s.logger.Tracef("failed to handle session: %v", err)

	// decrease session value
	atomic.AddInt32(&s.sessionCounter, -1)

	// Put local connection back to local channel
	s.localChannel <- *incomingConn

	// Attempt to request a new connection
	select {
	case s.reqNewConnChan <- struct{}{}:
	default:
		s.logger.Warn("request new connection channel is full")
	}
}
