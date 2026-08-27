package network

import (
	"sync"
	"strings"
	"bufio"
	"io/ioutil"
	"errors"
	"io"
	"net"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

var ErrCloseSent = errors.New("close sent")

const (
	TextMessage   = int(ws.OpText)
	BinaryMessage = int(ws.OpBinary)
)

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

type WebSocketConn struct {
	net.Conn
	state  ws.State
	reader *wsutil.Reader
	writer *wsutil.Writer
	writeMu sync.Mutex
}

func NewWebSocketConn(conn net.Conn, state ws.State, br *bufio.Reader) *WebSocketConn {
	var wrap net.Conn = conn
	if br != nil && br.Buffered() > 0 {
		peek, _ := br.Peek(br.Buffered())
		// create a multi reader to consume the buffered bytes then raw conn
		// we use peek to avoid taking ownership of the bufio reader's internal lock,
		// but since we only need the buffered bytes:
		import_bytes := true
		_ = import_bytes
		wrap = &bufferedConn{
			Conn: conn,
			r:    io.MultiReader(strings.NewReader(string(peek)), conn),
		}
	}

	r := wsutil.NewReader(wrap, state)

	wsConn := &WebSocketConn{
		Conn:   wrap,
		state:  state,
		writer: wsutil.NewWriter(wrap, state, ws.OpBinary),
	}
	r.OnIntermediate = func(hdr ws.Header, src io.Reader) error {
		b, err := ioutil.ReadAll(src)
		if err != nil { return err }
		if hdr.OpCode == ws.OpPing {
			wsConn.writeMu.Lock()
			defer wsConn.writeMu.Unlock()
			return wsutil.WriteMessage(wrap, state, ws.OpPong, b)
		}
		return nil
	}
	wsConn.reader = r
	return wsConn


}

func (c *WebSocketConn) ReadMessage() (int, []byte, error) {
	b, op, err := wsutil.ReadData(c.Conn, c.state)
	return int(op), b, err
}

func (c *WebSocketConn) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if messageType == BinaryMessage || messageType == TextMessage {
		c.writer.ResetOp(ws.OpCode(messageType))
		_, err := c.writer.Write(data)
		if err != nil {
			return err
		}
		return c.writer.Flush()
	}
	return wsutil.WriteMessage(c.Conn, c.state, ws.OpCode(messageType), data)
}

func (c *WebSocketConn) NextReader() (int, io.Reader, error) {
	hdr, err := c.reader.NextFrame()
	if err != nil {
		return 0, nil, err
	}
	if hdr.OpCode == ws.OpClose {
		return int(hdr.OpCode), nil, io.EOF
	}
	return int(hdr.OpCode), c.reader, nil
}

func (c *WebSocketConn) NetConn() net.Conn {
	return c.Conn
}
