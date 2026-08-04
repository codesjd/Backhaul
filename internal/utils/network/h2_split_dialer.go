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
// connection keeps concurrently in flight, as a safety net against a
// slow/lossy path backing up unboundedly. It is deliberately not the
// primary lever for chatty-traffic performance any more - see
// h2SplitCoalesceWindow below.
const h2SplitMaxInFlight = 64

// h2SplitCoalesceWindow and h2SplitDefaultCoalesceMax control write
// coalescing: instead of firing one POST per smux Write() (one HTTP
// request - with its own headers, HPACK state churn and, more
// importantly, its own entry in whatever request-rate heuristics a
// CDN/WAF applies - per frame, which for a chatty protocol doing many
// tiny sequential writes means many tiny requests per second), writes
// are buffered for a short window and merged into a single POST body.
// Since smux has one writer goroutine per session and Write() here
// never blocks, a burst of queued frames drains into the same buffer
// almost instantly, so coalescing costs at most ~h2SplitCoalesceWindow
// of added latency while cutting the request rate by however bursty the
// traffic is. This is the fix for "many small requests" - raising
// h2SplitMaxInFlight only lets more of them run at once, it doesn't
// reduce how many there are, and a burst of dozens of near-simultaneous
// tiny POSTs to the same path is exactly the shape a WAF's anti-flood
// heuristics look for.
//
// The coalesced body size must stay within what the server actually
// accepts: internal/server/transport/h2mux.go reads each upload POST via
// io.LimitReader(r.Body, MaxFrameSize+4096) and, if the body is longer
// than that, silently truncates it (LimitReader hitting its limit isn't
// an error) instead of rejecting it - so an oversized coalesced batch
// doesn't fail loudly, it corrupts the smux byte stream. h2SplitDialer
// wires the coalescing cap to the same MaxFrameSize the server uses, via
// H2SplitDialerConfig.MaxFrameSize; this constant is only the fallback
// for the (should-never-happen) case that's unset.
const (
	h2SplitCoalesceWindow     = 4 * time.Millisecond
	h2SplitDefaultCoalesceMax = 32 * 1024
)

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
	// MaxFrameSize bounds how large a coalesced upload POST body is
	// allowed to grow (see h2SplitDefaultCoalesceMax above) - must match
	// the server's mux_framesize so a coalesced batch never exceeds what
	// the server's LimitReader accepts. Falls back to
	// h2SplitDefaultCoalesceMax if zero.
	MaxFrameSize int
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

	coalesceMu  sync.Mutex
	coalesceMax int
	pending     []byte
	flushTimer  *time.Timer

	errOnce sync.Once
	err     atomic.Pointer[error]
}

func (c *h2SplitClientConn) Read(p []byte) (int, error) {
	return c.body.Read(p)
}

// Write buffers p and schedules it to go out as part of the next coalesced
// POST rather than sending it immediately, so a burst of small sequential
// smux frames turns into one larger request instead of one request each.
// It never lets the buffered batch grow past c.coalesceMax (flushing
// whatever's already pending first if p would push it over), since the
// server truncates - rather than rejects - an oversized upload body.
func (c *h2SplitClientConn) Write(p []byte) (int, error) {
	if errPtr := c.err.Load(); errPtr != nil {
		return 0, *errPtr
	}

	c.coalesceMu.Lock()
	if len(c.pending) > 0 && len(c.pending)+len(p) > c.coalesceMax {
		buf := c.pending
		c.pending = nil
		if c.flushTimer != nil {
			c.flushTimer.Stop()
			c.flushTimer = nil
		}
		c.coalesceMu.Unlock()
		c.dispatch(buf)
		c.coalesceMu.Lock()
	}

	c.pending = append(c.pending, p...)
	if len(c.pending) >= c.coalesceMax {
		buf := c.pending
		c.pending = nil
		if c.flushTimer != nil {
			c.flushTimer.Stop()
			c.flushTimer = nil
		}
		c.coalesceMu.Unlock()
		c.dispatch(buf)
		return len(p), nil
	}
	if c.flushTimer == nil {
		c.flushTimer = time.AfterFunc(h2SplitCoalesceWindow, c.flushPending)
	}
	c.coalesceMu.Unlock()

	return len(p), nil
}

func (c *h2SplitClientConn) flushPending() {
	c.coalesceMu.Lock()
	buf := c.pending
	c.pending = nil
	c.flushTimer = nil
	c.coalesceMu.Unlock()

	if len(buf) == 0 {
		return
	}
	c.dispatch(buf)
}

// dispatch fires a single POST carrying buf as a background goroutine,
// bounded by sem, without waiting for the response - Write (and the
// coalescing timer above) must never block on network round trips, since
// smux has one writer goroutine per session and a blocking Write would
// serialize every frame of every multiplexed stream behind a full request.
func (c *h2SplitClientConn) dispatch(buf []byte) {
	seq := c.seq.Add(1) - 1
	frame := make([]byte, 8+len(buf))
	binary.BigEndian.PutUint64(frame[:8], seq)
	copy(frame[8:], buf)

	select {
	case c.sem <- struct{}{}:
	case <-c.ctx.Done():
		c.setErr(c.ctx.Err())
		return
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() { <-c.sem }()

		req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.url, bytes.NewReader(frame))
		if err != nil {
			c.setErr(err)
			return
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.ContentLength = int64(len(frame))

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

	coalesceMax := cfg.MaxFrameSize
	if coalesceMax <= 0 {
		coalesceMax = h2SplitDefaultCoalesceMax
	}

	return &h2SplitClientConn{
		body:        resp.Body,
		tr:          tr,
		url:         url,
		token:       cfg.Token,
		ctx:         connCtx,
		cancel:      cancel,
		sem:         make(chan struct{}, h2SplitMaxInFlight),
		coalesceMax: coalesceMax,
	}, nil
}

// H2SplitTunnelPath builds a randomized /tunnel/<id> path so the tunnel
// endpoint isn't a static, fingerprintable string.
func H2SplitTunnelPath(basePath string) string {
	return fmt.Sprintf("%s/tunnel/%d", basePath, rand.Int31())
}
