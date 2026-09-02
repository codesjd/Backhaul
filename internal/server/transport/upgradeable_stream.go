package transport

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type UpgradeableStream struct {
	mu           sync.Mutex
	conn         net.Conn
	upgrading    int32
	bytesWritten atomic.Int64
}

func NewUpgradeableStream(initialConn net.Conn) *UpgradeableStream {
	return &UpgradeableStream{
		conn: initialConn,
	}
}

func (u *UpgradeableStream) Swap(newConn net.Conn) {
	u.mu.Lock()
	u.conn = newConn
	atomic.StoreInt32(&u.upgrading, 0)
	u.mu.Unlock()
}

func (u *UpgradeableStream) Read(b []byte) (n int, err error) {
	for {
		u.mu.Lock()
		c := u.conn
		u.mu.Unlock()

		if c == nil {
			return 0, io.EOF
		}

		n, err = c.Read(b)

		if err != nil && atomic.LoadInt32(&u.upgrading) == 1 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		return n, err
	}
}

func (u *UpgradeableStream) Write(b []byte) (n int, err error) {
	for {
		u.mu.Lock()
		c := u.conn
		u.mu.Unlock()

		if c == nil {
			return 0, io.ErrClosedPipe
		}

		n, err = c.Write(b)
		if n > 0 {
			u.bytesWritten.Add(int64(n))
		}

		if err != nil && atomic.LoadInt32(&u.upgrading) == 1 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		return n, err
	}
}

func (u *UpgradeableStream) Close() error {
	u.mu.Lock()
	c := u.conn
	u.conn = nil
	u.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

func (u *UpgradeableStream) CloseWrite() error {
	u.mu.Lock()
	c := u.conn
	u.mu.Unlock()

	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	if c != nil {
		return c.Close()
	}
	return nil
}

func (u *UpgradeableStream) LocalAddr() net.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conn.LocalAddr()
}

func (u *UpgradeableStream) RemoteAddr() net.Addr {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conn.RemoteAddr()
}

func (u *UpgradeableStream) SetDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conn.SetDeadline(t)
}

func (u *UpgradeableStream) SetReadDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conn.SetReadDeadline(t)
}

func (u *UpgradeableStream) SetWriteDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conn.SetWriteDeadline(t)
}

func (u *UpgradeableStream) SetUpgrading() {
	atomic.StoreInt32(&u.upgrading, 1)
}
