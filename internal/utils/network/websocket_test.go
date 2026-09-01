package network

import (
	"net"
	"testing"
	"time"

	"github.com/gobwas/ws"
)

// countingConn records the size of every Write that reaches the socket, so a
// test can assert how many syscalls one WriteMessage turns into.
type countingConn struct {
	net.Conn
	writes []int
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, len(p))
	return len(p), nil
}

func (c *countingConn) Read(p []byte) (int, error)  { return 0, net.ErrClosed }
func (c *countingConn) Close() error                { return nil }
func (c *countingConn) LocalAddr() net.Addr         { return nil }
func (c *countingConn) RemoteAddr() net.Addr        { return nil }
func (c *countingConn) SetDeadline(time.Time) error { return nil }

func (c *countingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countingConn) SetWriteDeadline(time.Time) error { return nil }

// A full-sized payload must leave as one frame in one socket write.
//
// The writer used to run with wsutil's 4KB default buffer while the data path
// handed it up to handlers.copyBufferSize (64KB) at a time. Anything larger
// than the buffer took gobwas's WriteThrough path, which cost three socket
// writes and two frames per message: a tiny header write, the payload as a
// non-final fragment, then an empty continuation frame carrying only fin.
// Under TCP_NODELAY those became three TCP segments, two of them a few bytes,
// and on wss three separate TLS records.
//
// This is also what pins the writer's buffer to copyBufferSize: grow the copy
// buffer past it and the fragmented path returns silently, so this test fails
// rather than letting the regression through.
func TestWriteMessageSingleWrite(t *testing.T) {
	const copyBufferSize = 64 * 1024 // handlers.copyBufferSize

	for _, tc := range []struct {
		name  string
		state ws.State
	}{
		{"server", ws.StateServerSide},
		{"client", ws.StateClientSide},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, size := range []int{1, 1024, 4096, copyBufferSize} {
				cc := &countingConn{}
				conn := NewWebSocketConn(cc, tc.state, nil)

				if err := conn.WriteMessage(BinaryMessage, make([]byte, size)); err != nil {
					t.Fatalf("payload %d: WriteMessage: %v", size, err)
				}

				if len(cc.writes) != 1 {
					t.Errorf("payload %d: got %d socket writes %v, want 1 - "+
						"the writer fell back to the fragmented WriteThrough path",
						size, len(cc.writes), cc.writes)
				}
			}
		})
	}
}
