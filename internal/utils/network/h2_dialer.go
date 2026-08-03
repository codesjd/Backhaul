package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// H2DialerConfig carries what's needed to open one duplex HTTP/2 stream
// acting as a single backhaul "connection" - the same role a raw TCP or
// WebSocket connection plays for the tcp/ws transports.
type H2DialerConfig struct {
	Addr               string // domain:port, used for the Host header and (for TLS) SNI
	EdgeIP             string // optional CDN edge IP dialed instead of Addr
	Path               string
	Token              string
	TLS                bool // h2smux (TLS+ALPN h2, via uTLS) vs h2mux (cleartext h2c)
	InsecureSkipVerify bool
	Timeout            time.Duration
	KeepAlive          time.Duration
	Nodelay            bool
	SO_RCVBUF          int
	SO_SNDBUF          int
}

// H2Dialer opens a new HTTP/2 connection (never reusing a pooled one - each
// call gets its own fresh TCP+h2 connection, mirroring how the ws/wsmux
// transports give every pooled connection its own physical socket) and
// issues a streaming request against path, returning a duplex H2Conn once
// the response headers arrive.
func H2Dialer(ctx context.Context, cfg H2DialerConfig, retry int) (*H2Conn, error) {
	var lastErr error
	backoff := 1 * time.Second

	for i := 0; i < retry; i++ {
		conn, err := attemptH2Dial(ctx, cfg)
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

func attemptH2Dial(ctx context.Context, cfg H2DialerConfig) (*H2Conn, error) {
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

	path := cfg.Path
	if !strings.HasSuffix(path, "/channel") {
		path = fmt.Sprintf("%s/%s", path, strconv.Itoa(int(rand.Int31())))
	}

	pr, pw := io.Pipe()

	url := fmt.Sprintf("%s://%s%s", scheme, cfg.Addr, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, pr)
	if err != nil {
		pw.Close()
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %v", cfg.Token))
	req.Header.Set("X-User-Id", fmt.Sprintf("%d", rand.Int31()))
	req.Header.Set("User-Agent", RandomUserAgent())

	resp, err := tr.RoundTrip(req)
	if err != nil {
		pw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		pw.Close()
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status from h2 server: %s", resp.Status)
	}

	return NewH2Conn(resp.Body, pw, nil, func() error {
		pw.Close()
		return resp.Body.Close()
	}), nil
}
