package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/musix/backhaul/config"
)

func WebSocketDialer(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, userAgent string, mode config.TransportType, retry int, SO_RCVBUF int, SO_SNDBUF int, mss int, tlsVerify bool) (*websocket.Conn, error) {
	var tunnelWSConn *websocket.Conn
	var err error

	retries := retry           // Number of retries
	backoff := 1 * time.Second // Initial backoff duration

	for i := 0; i < retries; i++ {
		// Attempt to dial the WebSocket
		tunnelWSConn, err = attemptDialWebSocket(ctx, addr, edgeIP, path, timeout, keepalive, nodelay, token, userAgent, mode, SO_RCVBUF, SO_SNDBUF, mss, tlsVerify)
		if err == nil {
			// If successful, return the connection
			return tunnelWSConn, nil
		}

		// If this is the last retry, return the error
		if i == retries-1 {
			break
		}

		// Wait before retrying, but abandon the wait if the transport is
		// already shutting down. An unconditional Sleep here held a restart for
		// up to 1+2=3 seconds per in-flight dial (longer with a higher retry
		// count), and every pool connection dialing at once meant a restart
		// waited on all of them.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2 // Exponential backoff (double the wait time after each failure)
	}

	return nil, err
}

func attemptDialWebSocket(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, userAgent string, mode config.TransportType, SO_RCVBUF int, SO_SNDBUF int, mss int, tlsVerify bool) (*websocket.Conn, error) {
	// Generate a random X-user-id
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31))
	if err != nil {
		return nil, fmt.Errorf("failed to generate random user ID: %w", err)
	}
	randomUserID := int32(n.Int64())

	// Setup headers with authorization and X-user-id
	headers := http.Header{}
	headers.Add("Authorization", fmt.Sprintf("Bearer %v", token))
	headers.Add("X-User-Id", fmt.Sprintf("%d", randomUserID))
	headers.Add("User-Agent", userAgent)

	var wsURL string
	dialer := websocket.Dialer{}

	// Handle edgeIP assignment
	if edgeIP != "" {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format, failed to parse: %w", err)
		}

		edgeIP = fmt.Sprintf("%s:%s", edgeIP, port)
	} else {
		edgeIP = addr
	}

	// path generation; only the tunnel endpoint gets a random suffix, the
	// control channel path is used as-is (with or without a custom base path)
	if !strings.HasSuffix(path, "/channel") {
		path = fmt.Sprintf("%s/%s", path, strconv.Itoa(int(randomUserID)))
	}

	switch mode {
	case config.WS, config.WSMUX:
		wsURL = fmt.Sprintf("ws://%s%s", addr, path)

		dialer = websocket.Dialer{
			// Tunnel traffic underneath is smux/TLS binary that doesn't
			// compress, so permessage-deflate only burns CPU (and adds latency
			// if ever negotiated). The server upgrader doesn't enable it either.
			EnableCompression: false,
			HandshakeTimeout:  45 * time.Second, // default handshake timeout
			ReadBufferSize:    64 * 1024,        // match server upgrader; avoids falling back to gorilla's 4KB default
			WriteBufferSize:   64 * 1024,        // ditto, reduces syscall/copy overhead for large mux frames
			NetDial: func(_, addr string) (net.Conn, error) {
				conn, err := TcpDialer(ctx, edgeIP, "", timeout, keepalive, nodelay, 1, SO_RCVBUF, SO_SNDBUF, mss)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		}
	case config.WSS, config.WSSMUX:
		wsURL = fmt.Sprintf("wss://%s%s", addr, path)

		sniHost, _, err := net.SplitHostPort(addr)
		if err != nil {
			sniHost = addr
		}

		dialer = websocket.Dialer{
			// Tunnel traffic underneath is smux/TLS binary that doesn't
			// compress, so permessage-deflate only burns CPU (and adds latency
			// if ever negotiated). The server upgrader doesn't enable it either.
			EnableCompression: false,
			HandshakeTimeout:  45 * time.Second, // default handshake timeout
			ReadBufferSize:    64 * 1024,        // match server upgrader; avoids falling back to gorilla's 4KB default
			WriteBufferSize:   64 * 1024,        // ditto, reduces syscall/copy overhead for large mux frames
			// Handshake the TLS layer ourselves with uTLS so the ClientHello
			// mimics a real Chrome fingerprint instead of Go's crypto/tls
			// default, which passive DPI can key on. Gorilla ignores
			// TLSClientConfig once NetDialTLSContext is set.
			NetDialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				// insecureSkipVerify is the inverse of the operator's tls_verify:
				// off by default (self-signed friendly), but an on-path party can
				// then MITM the token-bearing handshake, so tls_verify=true is
				// available to pin the certificate.
				return UtlsDialTLS(ctx, edgeIP, sniHost, !tlsVerify, []string{"http/1.1"}, timeout, keepalive, nodelay, SO_RCVBUF, SO_SNDBUF, mss)
			},
		}
	}

	// Dial to the WebSocket server
	tunnelWSConn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		// On a bad handshake, gorilla still hands back the HTTP response the
		// server (or an on-path proxy/WAF/DPI) sent instead of the 101
		// Switching Protocols we expected. That status code and body are the
		// only clue to *why* the upgrade was rejected - e.g. a 403 from a
		// CDN's bot/DPI filter looks identical to a plain "bad handshake"
		// otherwise. The caller owns resp.Body once returned, so read and
		// close it here rather than leaking it.
		if resp != nil {
			defer resp.Body.Close()
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 512))
			if readErr == nil && len(bytes.TrimSpace(body)) > 0 {
				return nil, fmt.Errorf("%w (http status: %s, body: %q)", err, resp.Status, bytes.TrimSpace(body))
			}
			return nil, fmt.Errorf("%w (http status: %s)", err, resp.Status)
		}
		return nil, err
	}
	return tunnelWSConn, nil
}
