package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
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
		go func() {
			conn.Write(payload)
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
