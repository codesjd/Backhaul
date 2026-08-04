package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// h2SplitMaxInFlight bounds how many upload POSTs a single h2mux/h2smux
// connection keeps concurrently in flight. Each POST completes in roughly
// one RTT regardless of concurrency, so the effective upload throughput
// for small, frequent frames (protocol handshakes, interactive traffic -
// as opposed to a handful of large bulk-transfer frames) is bounded by
// roughly (h2SplitMaxInFlight * average frame size) / RTT. At 8 and a
// ~100 byte average frame over a 100ms RTT link, that ceiling is only
// ~8KB/s - fine for a bulk transfer dominated by big frames, but far too
// low for a chatty protocol, which is what made real application traffic
// (as opposed to the bulk-transfer tests this was first verified with)
// look like it "connects but is unusably slow". Raised well above what
// bulk transfers need so small-frame-heavy traffic isn't RTT-starved.
const h2SplitMaxInFlight = 64

// H2SplitDialerConfig carries what's needed to open one h2mux/h2smux
// "connection": a long-lived GET for the download direction, plus a
// *http2.Transport shared by subsequent bounded POSTs for the upload
// direction (see H2SplitConn for why the two are split).
type H2SplitDialerConfig struct {
	Addr               string // domain:port, used for the Host header and (for TLS) SNI
	EdgeIP             string // optional CDN edge IP dialed instead of Addr
	Path               string // base path, e.g. "" or "/custom"
	Token              string
	TLS                bool // h2smux (TLS+ALPN h2, via uTLS) vs h2mux (cleartext h2c)
	InsecureSkipVerify bool
	Timeout            time.Duration
	KeepAlive          time.Duration
	Nodelay            bool
	SO_RCVBUF          int
	SO_SNDBUF          int
}

// h2SplitClientConn is the client-side io.ReadWriteCloser: Read pulls from
// the long-lived GET response body. Write hands data off to a bounded pool
// of concurrent POSTs instead of blocking the caller (smux has one writer
// goroutine per session, so a blocking Write would serialize every frame
// of every multiplexed stream behind a full request/response round trip).
// Each POST is tagged with a monotonic sequence number so the server can
// restore the original order even if responses complete out of order.
type h2SplitClientConn struct {
	body   io.ReadCloser
	tr     *http2.Transport
	url    string
	token  string
	ctx    context.Context
	cancel context.CancelFunc

	seq atomic.Uint64
	sem chan struct{}
	wg  sync.WaitGroup

	errOnce sync.Once
	err     atomic.Pointer[error]
}

func (c *h2SplitClientConn) Read(p []byte) (int, error) {
	return c.body.Read(p)
}

func (c *h2SplitClientConn) Write(p []byte) (int, error) {
	if errPtr := c.err.Load(); errPtr != nil {
		return 0, *errPtr
	}

	seq := c.seq.Add(1) - 1
	buf := make([]byte, 8+len(p))
	binary.BigEndian.PutUint64(buf[:8], seq)
	copy(buf[8:], p)

	select {
	case c.sem <- struct{}{}:
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() { <-c.sem }()

		req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.url, bytes.NewReader(buf))
		if err != nil {
			c.setErr(err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.ContentLength = int64(len(buf))

		resp, err := c.tr.RoundTrip(req)
		if err != nil {
			c.setErr(err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			c.setErr(fmt.Errorf("unexpected status from h2 upload: %s", resp.Status))
			return
		}
		io.Copy(io.Discard, resp.Body)
	}()

	return len(p), nil
}

func (c *h2SplitClientConn) setErr(err error) {
	c.errOnce.Do(func() {
		c.err.Store(&err)
		c.cancel()
	})
}

func (c *h2SplitClientConn) Close() error {
	c.cancel()
	return c.body.Close()
}

// H2SplitDialer opens a new h2mux/h2smux connection - never reusing a
// pooled one, each call gets its own fresh TCP+h2 connection, mirroring
// how the ws/wsmux transports give every pooled connection its own
// physical socket. path should already include any base path, and end in
// "/channel" or "/tunnel/<id>".
func H2SplitDialer(ctx context.Context, cfg H2SplitDialerConfig, path string, retry int) (io.ReadWriteCloser, error) {
	var lastErr error
	backoff := 1 * time.Second

	for i := 0; i < retry; i++ {
		conn, err := attemptH2SplitDial(ctx, cfg, path)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if i == retry-1 {
			break
		}
		time.Sleep(backoff)
		backoff *= 2
	}

	return nil, lastErr
}

func attemptH2SplitDial(ctx context.Context, cfg H2SplitDialerConfig, path string) (io.ReadWriteCloser, error) {
	dialAddr := cfg.Addr
	if cfg.EdgeIP != "" {
		_, port, err := net.SplitHostPort(cfg.Addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format, failed to parse: %w", err)
		}
		dialAddr = fmt.Sprintf("%s:%s", cfg.EdgeIP, port)
	}

	sniHost, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		sniHost = cfg.Addr
	}

	scheme := "http"
	var tr *http2.Transport
	if cfg.TLS {
		scheme = "https"
		tr = &http2.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return UtlsDialTLS(ctx, dialAddr, sniHost, cfg.InsecureSkipVerify, []string{"h2"}, cfg.Timeout, cfg.KeepAlive, cfg.Nodelay, cfg.SO_RCVBUF, cfg.SO_SNDBUF)
			},
		}
	} else {
		tr = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return TcpDialer(ctx, dialAddr, "", cfg.Timeout, cfg.KeepAlive, cfg.Nodelay, 1, cfg.SO_RCVBUF, cfg.SO_SNDBUF, 0)
			},
		}
	}

	url := fmt.Sprintf("%s://%s%s", scheme, cfg.Addr, path)

	connCtx, cancel := context.WithCancel(ctx)

	req, err := http.NewRequestWithContext(connCtx, http.MethodGet, url, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("User-Agent", RandomUserAgent())

	resp, err := tr.RoundTrip(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		cancel()
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status from h2 download: %s", resp.Status)
	}

	return &h2SplitClientConn{
		body:   resp.Body,
		tr:     tr,
		url:    url,
		token:  cfg.Token,
		ctx:    connCtx,
		cancel: cancel,
		sem:    make(chan struct{}, h2SplitMaxInFlight),
	}, nil
}

// H2SplitTunnelPath builds a randomized /tunnel/<id> path so the tunnel
// endpoint isn't a static, fingerprintable string.
func H2SplitTunnelPath(basePath string) string {
	return fmt.Sprintf("%s/tunnel/%d", basePath, rand.Int31())
}
