package transport

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xtaci/smux"
)

// newRotateTestTransport builds the minimum retireSession touches: ctx, logger,
// sessionCounter and reqNewConnChan.
func newRotateTestTransport() *WsMuxTransport {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &WsMuxTransport{
		config:         &WsMuxConfig{MuxCon: 8, MaxConnAge: time.Minute},
		ctx:            context.Background(),
		logger:         logger,
		reqNewConnChan: make(chan struct{}, 4),
	}
}

// A connection being retired at max_conn_age must stay up while a flow is still
// running on it, and must ask for its replacement up front. That is the whole
// point of draining instead of closing: smux cannot move a live stream to
// another connection, so closing on schedule would cut long-lived flows (an SSH
// session, a large download) exactly as a CDN reset does.
func TestRetireSessionDrainsBeforeClosing(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	// Mirror the real pool: the server opens streams, the client accepts them.
	session, err := smux.Client(srvConn, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	peer, err := smux.Server(cliConn, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Server: %v", err)
	}
	defer peer.Close()
	go func() {
		for {
			st, err := peer.AcceptStream()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, st)
		}
	}()

	stream, err := session.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	s := newRotateTestTransport()
	done := make(chan struct{})
	go func() {
		s.retireSession(session)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("retireSession gave up on a session that still had a live stream")
	case <-time.After(2100 * time.Millisecond): // a couple of drain ticks
	}

	if session.IsClosed() {
		t.Fatal("session was closed while a stream was still live")
	}

	// Once the flow ends, the connection is free to go.
	stream.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("retireSession did not return after the last stream closed")
	}
}

// Rotation must not wedge on a connection the peer already tore down.
func TestRetireSessionReturnsOnClosedSession(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer cliConn.Close()

	session, err := smux.Client(srvConn, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	session.Close()

	s := newRotateTestTransport()
	done := make(chan struct{})
	go func() {
		s.retireSession(session)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retireSession did not return for an already-closed session")
	}
}

// Rotation must not retire a connection until its replacement is actually up.
// Nothing retries a failed pool dial (the client's tunnelDialer abandons one for
// good), so retiring on a timer alone would shrink the pool every time the CDN
// or edge IP was unreachable - exactly when capacity matters most.
func TestAwaitReplacementWaitsForNewConnection(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()

	session, err := smux.Client(srvConn, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}

	s := newRotateTestTransport()
	got := make(chan bool, 1)
	go func() { got <- s.awaitReplacement(session) }()

	// It orders the replacement up front.
	select {
	case <-s.reqNewConnChan:
	case <-time.After(2 * time.Second):
		t.Fatal("awaitReplacement did not request a replacement connection")
	}

	// No connection admitted: it keeps waiting rather than freeing the old one.
	select {
	case <-got:
		t.Fatal("awaitReplacement returned while the pool had no replacement")
	case <-time.After(2200 * time.Millisecond): // a couple of poll ticks
	}

	// A connection joins the pool, as handleLoop would record it.
	atomic.AddInt32(&s.admittedSessions, 1)
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("awaitReplacement reported failure after a replacement was admitted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("awaitReplacement did not notice the replacement connection")
	}
}

// A session that dies while waiting has nothing left to rotate.
func TestAwaitReplacementAbandonsDeadSession(t *testing.T) {
	srvConn, cliConn := net.Pipe()
	defer cliConn.Close()

	session, err := smux.Client(srvConn, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}

	s := newRotateTestTransport()
	got := make(chan bool, 1)
	go func() { got <- s.awaitReplacement(session) }()

	<-s.reqNewConnChan
	session.Close()

	select {
	case ok := <-got:
		if ok {
			t.Fatal("awaitReplacement reported success for a dead session")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("awaitReplacement did not return for a dead session")
	}
}
