package transport

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// resourceLimitErr stands in for EMFILE/ENFILE: the failure mode that used to
// spin, because it does not clear on its own and Accept returns instantly for
// as long as it holds.
type resourceLimitErr struct{}

func (resourceLimitErr) Error() string   { return "accept: too many open files" }
func (resourceLimitErr) Timeout() bool   { return false }
func (resourceLimitErr) Temporary() bool { return true }

// failingListener fails every Accept with err, counting the attempts, until
// okAfter of them have failed - then it hands over conn (if one was set).
type failingListener struct {
	err     error
	calls   int32
	conn    net.Conn
	okAfter int32
}

func (l *failingListener) Accept() (net.Conn, error) {
	if n := atomic.AddInt32(&l.calls, 1); l.conn != nil && n > l.okAfter {
		return l.conn, nil
	}
	return nil, l.err
}
func (l *failingListener) Close() error   { return nil }
func (l *failingListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 1} }

func acceptTestLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	return logger
}

// TestAcceptWithBackoffDoesNotSpin is the whole point of the helper: a listener
// that keeps failing must leave the loop idling, not burning a core. The old
// log-and-continue hit this listener tens of thousands of times in the same
// window.
func TestAcceptWithBackoffDoesNotSpin(t *testing.T) {
	listener := &failingListener{err: resourceLimitErr{}}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	if conn := acceptWithBackoff(ctx, listener, acceptTestLogger()); conn != nil {
		t.Fatal("got a connection from a listener that only ever fails")
	}
	// 5+10+20+40+80+160ms covers the window in ~6 attempts.
	if n := atomic.LoadInt32(&listener.calls); n > 20 {
		t.Fatalf("Accept called %d times in 250ms - the backoff is not being applied", n)
	}
}

// TestAcceptWithBackoffRecovers: backing off must not mean giving up. A
// descriptor limit clears once the peak passes, and the loop has to pick up
// again by itself.
func TestAcceptWithBackoffRecovers(t *testing.T) {
	want, peer := net.Pipe()
	defer want.Close()
	defer peer.Close()

	listener := &failingListener{err: resourceLimitErr{}, conn: want, okAfter: 3}

	if got := acceptWithBackoff(context.Background(), listener, acceptTestLogger()); got != want {
		t.Fatalf("expected the connection accepted after the transient failures, got %v", got)
	}
	if n := atomic.LoadInt32(&listener.calls); n != 4 {
		t.Fatalf("Accept called %d times, want 4 (3 failures then the connection)", n)
	}
}

// TestAcceptWithBackoffGivesUpOnClosedListener covers the other way the old
// loops spun: net.ErrClosed is permanent, so retrying it never terminates.
func TestAcceptWithBackoffGivesUpOnClosedListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listener.Close()

	done := make(chan net.Conn, 1)
	go func() { done <- acceptWithBackoff(context.Background(), listener, acceptTestLogger()) }()

	select {
	case conn := <-done:
		if conn != nil {
			t.Fatal("a closed listener produced a connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("acceptWithBackoff kept retrying a closed listener instead of returning")
	}
}
