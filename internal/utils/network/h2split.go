package network

import (
	"encoding/binary"
	"io"
	"sync"
)

// ParseH2SplitFrame splits a POST body into the 8-byte big-endian sequence
// number the client prefixed it with and the payload that follows. ok is
// false if body is shorter than the 8-byte header.
func ParseH2SplitFrame(body []byte) (seq uint64, payload []byte, ok bool) {
	if len(body) < 8 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint64(body[:8]), body[8:], true
}

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
	inbound   chan []byte // fed by PushInbound (in order), drained by Read
	outbound  chan []byte // fed by Write, drained by the GET handler
	readBuf   []byte
	closed    chan struct{}
	closeOnce sync.Once

	// POSTs carrying inbound bytes are sent concurrently by the client and
	// can complete out of order; reorderMu/expectedSeq/pending restore the
	// original send order before anything reaches inbound.
	reorderMu   sync.Mutex
	expectedSeq uint64
	pending     map[uint64][]byte
}

func NewH2SplitConn() *H2SplitConn {
	return &H2SplitConn{
		// Sized to comfortably hold h2SplitMaxInFlight concurrent upload
		// POSTs without the channel send in PushInbound applying backpressure
		// before Read has a chance to drain it.
		inbound:  make(chan []byte, 128),
		outbound: make(chan []byte, 128),
		closed:   make(chan struct{}),
		pending:  make(map[uint64][]byte),
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

// PushInbound delivers bytes received from a POST body, identified by the
// monotonic sequence number the client tagged it with. Chunks that arrive
// out of order (concurrent POSTs completing in a different order than they
// were sent) are held until the missing earlier sequence numbers show up,
// so Read always sees the original send order. Blocks while the inbound
// queue is full, applying backpressure; returns false if already closed.
func (c *H2SplitConn) PushInbound(seq uint64, p []byte) bool {
	buf := make([]byte, len(p))
	copy(buf, p)

	c.reorderMu.Lock()
	if seq != c.expectedSeq {
		c.pending[seq] = buf
		c.reorderMu.Unlock()
		return true
	}
	c.expectedSeq++
	ready := [][]byte{buf}
	for {
		next, ok := c.pending[c.expectedSeq]
		if !ok {
			break
		}
		delete(c.pending, c.expectedSeq)
		ready = append(ready, next)
		c.expectedSeq++
	}
	c.reorderMu.Unlock()

	for _, chunk := range ready {
		select {
		case c.inbound <- chunk:
		case <-c.closed:
			return false
		}
	}
	return true
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
