package network

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/musix/backhaul/config"
)

func WebSocketDialer(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, userAgent string, mode config.TransportType, retry int, SO_RCVBUF int, SO_SNDBUF int, mss int, tlsVerify bool) (*WebSocketConn, error) {
	var tunnelWSConn *WebSocketConn
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

func attemptDialWebSocket(ctx context.Context, addr string, edgeIP string, path string, timeout time.Duration, keepalive time.Duration, nodelay bool, token string, userAgent string, mode config.TransportType, SO_RCVBUF int, SO_SNDBUF int, mss int, tlsVerify bool) (*WebSocketConn, error) {
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
	dialer := ws.Dialer{Header: ws.HandshakeHeaderHTTP(http.Header{})}

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

		dialer = ws.Dialer{
			Header:  ws.HandshakeHeaderHTTP(headers),
			Timeout: 45 * time.Second,
			NetDial: func(ctx context.Context, _, addr string) (net.Conn, error) {
				conn, err := TcpDialer(ctx, edgeIP, "", timeout, keepalive, nodelay, 1, SO_RCVBUF, SO_SNDBUF, mss)
				if err != nil {
					return nil, err
				}
				return conn, nil
			},
		}
	case config.WSS, config.WSSMUX:
		wsURL = fmt.Sprintf("ws://%s%s", addr, path) // gobwas will double-wrap if wss:// is used

		sniHost, _, err := net.SplitHostPort(addr)
		if err != nil {
			sniHost = addr
		}

		dialer = ws.Dialer{
			Header:  ws.HandshakeHeaderHTTP(headers),
			Timeout: 45 * time.Second,
			NetDial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				// insecureSkipVerify is the inverse of the operator's tls_verify:
				// off by default (self-signed friendly), but an on-path party can
				// then MITM the token-bearing handshake, so tls_verify=true is
				// available to pin the certificate.
				return UtlsDialTLS(ctx, edgeIP, sniHost, !tlsVerify, []string{"http/1.1"}, timeout, keepalive, nodelay, SO_RCVBUF, SO_SNDBUF, mss)
			},
		}
	}

	// Dial to the WebSocket server
	conn, br, _, err := dialer.Dial(ctx, wsURL)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	return NewWebSocketConn(conn, ws.StateClientSide, br), nil
}
