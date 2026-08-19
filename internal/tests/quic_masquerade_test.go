package tests

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ctransport "github.com/musix/backhaul/internal/client/transport"
	stransport "github.com/musix/backhaul/internal/server/transport"

	"github.com/sagernet/quic-go/http3"
)

// TestQuicTunnelNoMasquerade guards the classic (non-masquerade) tunnel path,
// which the masquerade refactor left as the else branch: a TCP flow must still
// round-trip through the raw QUIC tunnel with masquerade off.
func TestQuicTunnelNoMasquerade(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "raw-token"
	serverPort := freeUDPPort(t)
	pubPort := freeTCPPort(t)
	echoPort := freeTCPPort(t)
	tcpEcho(t, ctx, echoPort)

	srv := stransport.NewQuicServer(ctx, &stransport.QuicConfig{
		BindAddr: fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:    token,
		Ports:    []string{fmt.Sprintf("%d=%d", pubPort, echoPort)},
		// Masquerade off: exercise the raw auth-stream path.
	}, quietLogger())
	go srv.Start()

	cli := ctransport.NewQuicClient(ctx, &ctransport.QuicConfig{
		RemoteAddr:    fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:         token,
		DialTimeOut:   5 * time.Second,
		RetryInterval: 500 * time.Millisecond,
	}, quietLogger())
	go cli.Start()

	payload := []byte("raw quic tunnel round trip")
	var conn net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial public tcp: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := readFull(conn, got); err != nil {
		t.Fatalf("tcp read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("raw tunnel echo mismatch: %q", got)
	}
}

// TestQuicMasqueradeDecoy verifies the nginx-style decoy: a real HTTP/3 client
// (standing in for an active censor probe) that connects to the QUIC port
// without the tunnel token is reverse-proxied to the configured fallback
// backend, so the endpoint answers like an ordinary website rather than
// resetting the connection.
func TestQuicMasqueradeDecoy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const decoyBody = "hello from the decoy origin"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, decoyBody)
	}))
	defer backend.Close()

	serverPort := freeUDPPort(t)
	srvCfg := &stransport.QuicConfig{
		BindAddr:   fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:      "the-real-secret",
		Masquerade: true,
		Fallback:   backend.Listener.Addr().String(), // reverse-proxy probes here
	}
	srv := stransport.NewQuicServer(ctx, srvCfg, quietLogger())
	go srv.Start()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
	}
	defer rt.Close()

	url := fmt.Sprintf("https://127.0.0.1:%d/", serverPort)

	// Retry while the server comes up.
	var body string
	var status int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body, status = string(b), resp.StatusCode
		break
	}

	if status != http.StatusOK {
		t.Fatalf("decoy probe: got status %d, want 200", status)
	}
	if body != decoyBody {
		t.Fatalf("decoy probe: body = %q, want %q (request should be reverse-proxied to the fallback backend)", body, decoyBody)
	}
}

// TestQuicMasqueradeDefaultPage verifies that, with no fallback configured, an
// unauthenticated HTTP/3 probe still gets a plausible generic page instead of a
// connection error.
func TestQuicMasqueradeDefaultPage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := freeUDPPort(t)
	srvCfg := &stransport.QuicConfig{
		BindAddr:   fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:      "secret",
		Masquerade: true, // no Fallback
	}
	srv := stransport.NewQuicServer(ctx, srvCfg, quietLogger())
	go srv.Start()

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
	}
	defer rt.Close()

	url := fmt.Sprintf("https://127.0.0.1:%d/", serverPort)
	var serverHdr string
	var got bool
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		serverHdr = resp.Header.Get("Server")
		got = true
		break
	}
	if !got {
		t.Fatal("no HTTP/3 response from the masquerade endpoint")
	}
	if serverHdr != "nginx" {
		t.Fatalf("default decoy page: Server header = %q, want %q", serverHdr, "nginx")
	}
}
