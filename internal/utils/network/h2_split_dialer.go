package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
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
}

// h2SplitClientConn is the client-side io.ReadWriteCloser: Read pulls from
// the long-lived GET response body, Write issues a new bounded POST per
// call over the same (connection-reusing) *http2.Transport.
type h2SplitClientConn struct {
	body   io.ReadCloser
	tr     *http2.Transport
	url    string
	token  string
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *h2SplitClientConn) Read(p []byte) (int, error) {
	return c.body.Read(p)
}

func (c *h2SplitClientConn) Write(p []byte) (int, error) {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.url, bytes.NewReader(p))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.ContentLength = int64(len(p))

	resp, err := c.tr.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status from h2 upload: %s", resp.Status)
	}
	io.Copy(io.Discard, resp.Body)
	return len(p), nil
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
	}, nil
}

// H2SplitTunnelPath builds a randomized /tunnel/<id> path so the tunnel
// endpoint isn't a static, fingerprintable string.
func H2SplitTunnelPath(basePath string) string {
	return fmt.Sprintf("%s/tunnel/%d", basePath, rand.Int31())
}
