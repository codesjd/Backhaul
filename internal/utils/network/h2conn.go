package network

import (
	"io"
	"sync"
)

// H2Conn adapts one duplex HTTP/2 request/response exchange (a stream of
// raw bytes flowing both ways over a single HTTP/2 stream, the same trick
// gRPC-style streaming uses) into an io.ReadWriteCloser, so it can be
// handed to smux exactly like a raw TCP or WebSocket connection is
// elsewhere in this package.
type H2Conn struct {
	reader    io.ReadCloser
	writer    io.Writer
	flush     func()
	closeFn   func() error
	closeOnce sync.Once
	closed    chan struct{}
}

func NewH2Conn(reader io.ReadCloser, writer io.Writer, flush func(), closeFn func() error) *H2Conn {
	return &H2Conn{
		reader:  reader,
		writer:  writer,
		flush:   flush,
		closeFn: closeFn,
		closed:  make(chan struct{}),
	}
}

func (c *H2Conn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *H2Conn) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	if err == nil && c.flush != nil {
		c.flush()
	}
	return n, err
}

func (c *H2Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		if c.closeFn != nil {
			err = c.closeFn()
		} else {
			err = c.reader.Close()
		}
	})
	return err
}

// Done is closed once Close has been called. HTTP/2 requests can't be
// hijacked like a WS upgrade can, so the handler goroutine that owns this
// conn's underlying request must stay blocked for the connection's
// lifetime; it does so by waiting on Done.
func (c *H2Conn) Done() <-chan struct{} {
	return c.closed
}
