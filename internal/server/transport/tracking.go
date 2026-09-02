package transport

import (
	"net"
	"sync/atomic"
)

type trackingConn struct {
	net.Conn
	bytesWritten atomic.Int64
	bytesRead    atomic.Int64
	onClose      func(written, read int64)
}

func (c *trackingConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	if n > 0 {
		c.bytesWritten.Add(int64(n))
	}
	return
}

func (c *trackingConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 {
		c.bytesRead.Add(int64(n))
	}
	return
}

func (c *trackingConn) Close() error {
	c.onClose(c.bytesWritten.Load(), c.bytesRead.Load())
	return c.Conn.Close()
}

// Add CloseWrite and CloseRead if net.Conn implements them, because
// wrapping net.Conn hides optional interfaces like CloseWrite!
// The plain flow depends on CloseWrite to not truncate data.
func (c *trackingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	// Fallback: we cannot half-close, but this should only be called by tcp_handler.go closeWrite if it exists.
	return c.Conn.Close()
}
