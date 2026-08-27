package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/musix/backhaul/internal/utils/network"
)

// wsPair returns the two ends of a real WebSocket connection, so the handler is
// exercised against actual framing rather than a stand-in.
func wsPair(t *testing.T) (client, server *network.WebSocketConn) {
	t.Helper()

	srvCh := make(chan *network.WebSocketConn, 1)

	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		netConn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		srvCh <- network.NewWebSocketConn(netConn, ws.StateServerSide, nil)
	}))
	t.Cleanup(hs.Close)

	netConn, br, _, err := ws.DefaultDialer.Dial(context.Background(), "ws"+strings.TrimPrefix(hs.URL, "http"))
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	c := network.NewWebSocketConn(netConn, ws.StateClientSide, br)
	t.Cleanup(func() { c.Close() })

	select {
	case s := <-srvCh:
		t.Cleanup(func() { s.Close() })
		return c, s
	case <-time.After(10 * time.Second):
		t.Fatal("websocket upgrade never completed")
		return nil, nil
	}
}

// TestWSConnectionHandlerHalfCloseKeepsReplyIntact wires up both halves of a
// real ws tunnel - server side (user <-> ws) and client side (ws <-> local
// service) - and drives it the way an HTTP/1.0 client does: send the request,
// half-close the upload, then read the reply.
//
// Before the EOF marker, the local half-close tripped a full close of the
// tunnel leg on the server side, so the reply was RST away and the user read
// zero (or partial) bytes. The reply also has to survive in the other
// direction: the local service's own close must reach the user as a clean EOF,
// or io.ReadAll below never returns.
func TestWSConnectionHandlerHalfCloseKeepsReplyIntact(t *testing.T) {
	upPayload := make([]byte, 3*copyBufferSize+777) // spans several frames
	downPayload := make([]byte, 2*copyBufferSize+321)
	rand.Read(upPayload)
	rand.Read(downPayload)

	// The local service behind the client: reads the whole upload, replies with
	// downPayload, then closes its write side.
	targetAddr, gotAtTarget := echoTarget(t, downPayload)

	wsClient, wsServer := wsPair(t)

	// Client side of the tunnel: ws leg <-> local service.
	localConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial local service: %v", err)
	}
	clientUsage := testUsage(t)
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		WSConnectionHandler(context.Background(), false, wsClient, localConn, testLogger(), clientUsage, 5555, true)
	}()

	// Server side of the tunnel: the user's connection <-> ws leg.
	userLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer userLn.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		conn, err := userLn.Accept()
		if err == nil {
			acceptedCh <- conn
		}
	}()

	userConn, err := net.Dial("tcp", userLn.Addr().String())
	if err != nil {
		t.Fatalf("dial user listener: %v", err)
	}
	accepted := <-acceptedCh

	serverUsage := testUsage(t)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		WSConnectionHandler(context.Background(), false, wsServer, accepted, testLogger(), serverUsage, 6666, true)
	}()

	// Drive the user side: upload, half-close, then read the reply to EOF.
	var got []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, _ = io.ReadAll(userConn)
	}()

	if _, err := userConn.Write(upPayload); err != nil {
		t.Fatalf("write upPayload: %v", err)
	}
	if err := userConn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("half-close upload: %v", err)
	}

	select {
	case gotUp := <-gotAtTarget:
		if !bytes.Equal(gotUp, upPayload) {
			t.Fatalf("local service got %d bytes, want %d matching upPayload", len(gotUp), len(upPayload))
		}
	case <-time.After(15 * time.Second):
		t.Fatal("local service never saw the full upload (half-close did not propagate through the tunnel)")
	}

	wg.Wait()
	if !bytes.Equal(got, downPayload) {
		t.Fatalf("user got %d bytes, want %d matching downPayload (reply truncated)", len(got), len(downPayload))
	}

	for name, done := range map[string]chan struct{}{"client": clientDone, "server": serverDone} {
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("%s-side WSConnectionHandler did not return after both directions finished", name)
		}
	}

	// The EOF marker carries no payload, so it must not show up as traffic.
	if got := portUsageTotal(serverUsage, 6666); got != uint64(len(upPayload)+len(downPayload)) {
		t.Fatalf("server sniffer recorded %d bytes, want %d", got, len(upPayload)+len(downPayload))
	}
}

// TestWSConnectionHandlerReturnsWhenTunnelDies guards the risk the half-close
// change introduces: now that a finished direction no longer closes both conns,
// a dead tunnel leg must still unblock the other direction rather than leaving
// the handler parked on wg.Wait forever.
func TestWSConnectionHandlerReturnsWhenTunnelDies(t *testing.T) {
	wsClient, wsServer := wsPair(t)
	local, peer := net.Pipe()
	defer peer.Close()

	usage := testUsage(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		WSConnectionHandler(context.Background(), false, wsClient, local, testLogger(), usage, 1234, false)
	}()

	wsServer.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after the tunnel connection died")
	}
}

// TestWSConnectionHandlerReturnsOnContextCancel covers the other teardown
// route: nothing dies on its own, the transport is just restarting.
func TestWSConnectionHandlerReturnsOnContextCancel(t *testing.T) {
	wsClient, _ := wsPair(t)
	local, peer := net.Pipe()
	defer peer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	usage := testUsage(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		WSConnectionHandler(ctx, false, wsClient, local, testLogger(), usage, 1234, false)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after the context was cancelled")
	}
}

// TestWSConnectionHandlerWritesProxyProtocol pins the ws/wss side of
// proxy_protocol: the option used to be accepted and silently ignored here, so
// the local service saw the tunnel's own address as every client's.
//
// The header has to arrive as its own frame - the peer reads this leg with
// NextReader, so a raw socket write would land mid-frame and desync the stream.
func TestWSConnectionHandlerWritesProxyProtocol(t *testing.T) {
	payload := []byte("hello from the user")

	wsClient, wsServer := wsPair(t)

	userLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer userLn.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		if conn, err := userLn.Accept(); err == nil {
			acceptedCh <- conn
		}
	}()

	userConn, err := net.Dial("tcp", userLn.Addr().String())
	if err != nil {
		t.Fatalf("dial user listener: %v", err)
	}
	defer userConn.Close()
	accepted := <-acceptedCh

	go WSConnectionHandler(context.Background(), true, wsServer, accepted, testLogger(), testUsage(t), 6666, false)

	if err := wsClient.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	_, header, err := wsClient.ReadMessage()
	if err != nil {
		t.Fatalf("read proxy protocol header: %v", err)
	}

	magic := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	if len(header) != 28 || !bytes.HasPrefix(header, magic) {
		t.Fatalf("first frame is not a v2 header: % x", header)
	}
	// src port sits after magic(12) + ver/cmd(1) + family(1) + len(2) + addrs(8).
	gotPort := int(binary.BigEndian.Uint16(header[24:26]))
	wantPort := userConn.LocalAddr().(*net.TCPAddr).Port
	if gotPort != wantPort {
		t.Fatalf("header source port %d, want the user's own port %d", gotPort, wantPort)
	}

	// ...and the data still follows it intact.
	if _, err := userConn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	_, got, err := wsClient.ReadMessage()
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload after the header is %q, want %q", got, payload)
	}
}
