package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.FatalLevel)
	return l
}

func testUsage(t *testing.T) *web.Usage {
	t.Helper()
	status := "test"
	return web.NewDataStore("", context.Background(), "", true, &status, testLogger())
}

// echoServer accepts one TCP connection and copies everything it reads back
// to the writer given, so a real *net.TCPConn is available as one leg of
// TCPConnectionHandler - the case where both ends being *net.TCPConn makes
// io.CopyBuffer eligible for the splice(2) fast path on Linux.
func echoTarget(t *testing.T, payload []byte) (addr string, gotCh <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer ln.Close()
		// A real server closes its connection once it has sent its reply. Doing
		// so here sends a clean FIN that lets the download direction reach EOF,
		// which is what the half-close pump needs to know the reply is complete
		// (an echo target that never closed would leave the reverse copy blocked
		// forever, since TCP has no in-band "reply done" signal).
		defer conn.Close()
		go func() {
			conn.Write(payload)
			if tcp, ok := conn.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
		}()
		got, _ := io.ReadAll(conn)
		ch <- got
	}()
	return ln.Addr().String(), ch
}

// TestTCPConnectionHandlerRealTCP exercises the case where both from and to
// are *net.TCPConn - the exact condition io.CopyBuffer needs to take Go's
// zero-copy splice(2) path on Linux instead of the pooled-buffer fallback.
// This only asserts correctness (splice is opaque from here), but that's
// the part that would actually break if the switch from a manual
// Read/Write loop to io.CopyBuffer changed behavior.
func TestTCPConnectionHandlerRealTCP(t *testing.T) {
	upPayload := make([]byte, 3*copyBufferSize+777) // spans several buffer-fuls
	downPayload := make([]byte, 2*copyBufferSize+321)
	rand.Read(upPayload)
	rand.Read(downPayload)

	targetAddr, gotAtTarget := echoTarget(t, downPayload)

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		t.Fatalf("dial target: %v", err)
	}

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer clientLn.Close()

	clientSideCh := make(chan net.Conn, 1)
	go func() {
		conn, err := clientLn.Accept()
		if err == nil {
			clientSideCh <- conn
		}
	}()

	dialerConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial client listener: %v", err)
	}
	fromConn := <-clientSideCh

	usage := testUsage(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		TCPConnectionHandler(context.Background(), false, fromConn, targetConn, testLogger(), usage, 4242, true)
	}()

	// Drive the "from" side like a real client: send upPayload, read
	// whatever comes back.
	var got []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, _ = io.ReadAll(dialerConn)
	}()
	if _, err := dialerConn.Write(upPayload); err != nil {
		t.Fatalf("write upPayload: %v", err)
	}
	dialerConn.(*net.TCPConn).CloseWrite()

	select {
	case gotUp := <-gotAtTarget:
		if !bytes.Equal(gotUp, upPayload) {
			t.Fatalf("target got %d bytes, want %d bytes matching upPayload", len(gotUp), len(upPayload))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("target never received the full upload payload")
	}

	wg.Wait()
	if !bytes.Equal(got, downPayload) {
		t.Fatalf("client got %d bytes, want %d bytes matching downPayload", len(got), len(downPayload))
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("TCPConnectionHandler did not return after both sides finished")
	}

	wantTotal := uint64(len(upPayload) + len(downPayload))
	if got := portUsageTotal(usage, 4242); got != wantTotal {
		t.Fatalf("sniffer recorded %d bytes for port 4242, want %d", got, wantTotal)
	}
}

// TestTCPConnectionHandlerNonTCPLeg covers the fallback path (one leg not a
// *net.TCPConn, e.g. a smux.Stream in real usage) via net.Pipe, which
// can't take the splice fast path and must go through the pooled buffer.
func TestTCPConnectionHandlerNonTCPLeg(t *testing.T) {
	appConn, pipeToApp := net.Pipe() // stands in for a smux.Stream
	tcpA, tcpB := net.Pipe()         // stands in for the real local target

	payload := make([]byte, 5*copyBufferSize+999)
	rand.Read(payload)

	usage := testUsage(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		TCPConnectionHandler(context.Background(), false, pipeToApp, tcpA, testLogger(), usage, 7777, true)
	}()

	var got []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, _ = io.ReadAll(tcpB)
	}()

	if _, err := appConn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	appConn.Close()

	wg.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %d bytes, want %d bytes matching payload", len(got), len(payload))
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("TCPConnectionHandler did not return")
	}

	if got := portUsageTotal(usage, 7777); got != uint64(len(payload)) {
		t.Fatalf("sniffer recorded %d bytes for port 7777, want %d", got, len(payload))
	}
}

func portUsageTotal(u *web.Usage, port int) uint64 {
	total, _ := u.GetPortUsage(port)
	return total
}

// TestTCPConnectionHandlerWritesProxyProtocol verifies that TCPConnectionHandler
// writes a correct Proxy Protocol v2 header when the proxyProtocol flag is true.
func TestTCPConnectionHandlerWritesProxyProtocol(t *testing.T) {
	upPayload := []byte("hello from the user via TCP")
	downPayload := []byte("hello from the target via TCP")
	remotePort := 4243

	// 1. Set up a target listener to act as the destination server.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	targetSideCh := make(chan net.Conn, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err == nil {
			targetSideCh <- conn
		}
	}()

	targetConn, err := net.Dial("tcp", targetLn.Addr().String())
	if err != nil {
		t.Fatalf("dial target listener: %v", err)
	}
	defer targetConn.Close()
	targetServerConn := <-targetSideCh
	defer targetServerConn.Close()

	// 2. Set up a client listener to act as the user.
	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer clientLn.Close()

	clientSideCh := make(chan net.Conn, 1)
	go func() {
		conn, err := clientLn.Accept()
		if err == nil {
			clientSideCh <- conn
		}
	}()

	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial client listener: %v", err)
	}
	defer clientConn.Close()
	fromConn := <-clientSideCh

	// 3. Run the TCPConnectionHandler
	usage := testUsage(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Enable proxyProtocol (true)
		TCPConnectionHandler(context.Background(), true, fromConn, targetConn, testLogger(), usage, remotePort, true)
	}()

	// Start a goroutine to read the response on the client side
	var gotDown []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		gotDown, _ = io.ReadAll(clientConn)
	}()

	// 4. Verify Proxy Protocol v2 header on the target side
	if err := targetServerConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	header := make([]byte, 28) // Proxy Protocol v2 header for IPv4 is 28 bytes
	_, err = io.ReadFull(targetServerConn, header)
	if err != nil {
		t.Fatalf("read proxy protocol header: %v", err)
	}

	magic := []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}
	if !bytes.HasPrefix(header, magic) {
		t.Fatalf("first frame is not a v2 header: % x", header)
	}

	// Check the source port in the header
	// In the proxy protocol v2 header for IPv4 (28 bytes total):
	// 12 bytes magic + 1 byte ver/cmd + 1 byte family/proto + 2 bytes len + 4 bytes srcIP + 4 bytes dstIP + 2 bytes srcPort + 2 bytes dstPort
	// srcPort starts at offset 12 + 1 + 1 + 2 + 4 + 4 = 24
	gotPort := int(binary.BigEndian.Uint16(header[24:26]))
	wantPort := clientConn.LocalAddr().(*net.TCPAddr).Port
	if gotPort != wantPort {
		t.Fatalf("header source port %d, want the user's own port %d", gotPort, wantPort)
	}

	// 5. Verify bidirectional data flow
	// Write upPayload to client
	if _, err := clientConn.Write(upPayload); err != nil {
		t.Fatalf("write upPayload: %v", err)
	}
	clientConn.(*net.TCPConn).CloseWrite() // half-close upload

	gotUp := make([]byte, len(upPayload))
	_, err = io.ReadFull(targetServerConn, gotUp)
	if err != nil {
		t.Fatalf("read upPayload: %v", err)
	}
	if !bytes.Equal(gotUp, upPayload) {
		t.Fatalf("upPayload after the header is %q, want %q", gotUp, upPayload)
	}

	// Write downPayload to target
	if _, err := targetServerConn.Write(downPayload); err != nil {
		t.Fatalf("write downPayload: %v", err)
	}
	targetServerConn.(*net.TCPConn).CloseWrite() // half-close download

	wg.Wait()
	if !bytes.Equal(gotDown, downPayload) {
		t.Fatalf("client got %q, want %q", gotDown, downPayload)
	}

	// Make sure handler returns
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TCPConnectionHandler did not return")
	}

	// 6. Verify usage tracking
	wantTotal := uint64(len(upPayload) + len(downPayload))
	if got := portUsageTotal(usage, remotePort); got != wantTotal {
		t.Fatalf("sniffer recorded %d bytes, want %d", got, wantTotal)
	}
}
