package network

import (
	"io"
	"sync"
)

// H2SplitConn is a server-side io.ReadWriteCloser backing one h2mux/h2smux
// "connection" (control channel or tunnel) that is implemented as two
// separate HTTP/2 request/response exchanges instead of one long-lived
// duplex POST: a long-lived GET response carries server->client bytes,
// and a sequence of short, bounded POST requests carries client->server
// bytes. CDNs/WAFs that buffer an entire request body before forwarding it
// (which breaks a single unbounded duplex POST, since the body never ends)
// generally don't buffer bounded POST bodies or streamed GET responses,
// since those match ordinary upload/download traffic.
type H2SplitConn struct {
	inbound   chan []byte // fed by POST handlers, drained by Read
	outbound  chan []byte // fed by Write, drained by the GET handler
	readBuf   []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func NewH2SplitConn() *H2SplitConn {
	return &H2SplitConn{
		inbound:  make(chan []byte, 64),
		outbound: make(chan []byte, 64),
		closed:   make(chan struct{}),
	}
}

func (c *H2SplitConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	select {
	case chunk, ok := <-c.inbound:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, chunk)
		if n < len(chunk) {
			c.readBuf = chunk[n:]
		}
		return n, nil
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *H2SplitConn) Write(p []byte) (int, error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.outbound <- buf:
		return len(p), nil
	case <-c.closed:
		return 0, io.ErrClosedPipe
	}
}

func (c *H2SplitConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// Done is closed once Close has been called.
func (c *H2SplitConn) Done() <-chan struct{} {
	return c.closed
}

// PushInbound delivers bytes received from a POST body to Read. It blocks
// while the inbound queue is full, applying backpressure to the POST
// handler; it returns false if the connection is already closed.
func (c *H2SplitConn) PushInbound(p []byte) bool {
	buf := make([]byte, len(p))
	copy(buf, p)
	select {
	case c.inbound <- buf:
		return true
	case <-c.closed:
		return false
	}
}

// NextOutbound blocks until there is data queued by Write, the connection
// closes, or done fires (e.g. the GET request's context being cancelled),
// whichever happens first.
func (c *H2SplitConn) NextOutbound(done <-chan struct{}) ([]byte, bool) {
	select {
	case chunk, ok := <-c.outbound:
		return chunk, ok
	case <-c.closed:
		return nil, false
	case <-done:
		return nil, false
	}
}
