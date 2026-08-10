package handlers

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/gorilla/websocket"
	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

// WebSocketToTCPConnectionHandler handles data transfer between a WebSocket and a TCP connection
func WSConnectionHandler(ctx context.Context, wsConn *websocket.Conn, tcpConn net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	done := make(chan struct{})

	// Close both ends as soon as the transport context is cancelled (e.g. on a
	// tunnel restart). The transfer loops below block on a read until the peer
	// closes, so without this watcher an idle tunnelled connection would linger
	// long past the restart, leaking sockets that pile up across repeated
	// restarts. Closing the connections unblocks both directions at once.
	go func() {
		select {
		case <-ctx.Done():
			wsConn.Close()
			tcpConn.Close()
		case <-done:
		}
	}()

	go func() {
		defer close(done)
		transferWebSocketToTCP(wsConn, tcpConn, logger, usage, remotePort, sniffer)
	}()

	transferTCPToWebSocket(tcpConn, wsConn, logger, usage, remotePort, sniffer)

	// Wait for the reverse copy to finish; both directions close both ends on
	// return, so this resolves promptly once either side completes.
	<-done
}

// transferWebSocketToTCP transfers data from a WebSocket connection to a TCP connection
func transferWebSocketToTCP(wsConn *websocket.Conn, tcpConn net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	for {
		// Read message from the WebSocket connection
		messageType, message, err := wsConn.ReadMessage()
		if err != nil {
			if errors.Is(err, websocket.ErrCloseSent) || errors.Is(err, io.EOF) {
				logger.Trace("WebSocket reader stream closed or EOF received")
			} else {
				logger.Trace("unable to read from the WebSocket connection: ", err)
			}
			wsConn.Close()
			tcpConn.Close()
			return
		}

		// Only handle text or binary messages (ignore control messages like pings)
		if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
			// Write the message to the TCP connection
			w, err := tcpConn.Write(message)
			if err != nil {
				logger.Trace("unable to write to the TCP connection: ", err)
				wsConn.Close()
				tcpConn.Close()
				return
			}
			logger.Tracef("transferred data from WebSocket to TCP: %d bytes", w)
			if sniffer {
				usage.AddOrUpdatePort(remotePort, uint64(w))
			}
		}
	}
}

// transferTCPToWebSocket transfers data from a TCP connection to a WebSocket connection
func transferTCPToWebSocket(tcpConn net.Conn, wsConn *websocket.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	// Reuse the same pooled 64KB buffer as the TCP handler instead of a fresh
	// per-connection allocation. This runs once per tunnelled connection, and
	// the buffer is consumed synchronously each iteration (read, then written
	// to the WebSocket before the next read), so it's safe to return to the
	// pool. WriteMessage doesn't retain the slice past its return.
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		// Read data from the TCP connection
		n, err := tcpConn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				logger.Trace("TCP reader stream closed or EOF received")
			} else {
				logger.Trace("unable to read from the TCP connection: ", err)
			}
			tcpConn.Close()
			wsConn.Close()
			return
		}

		// Write the data to the WebSocket connection as a binary message
		err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
		if err != nil {
			if errors.Is(err, websocket.ErrCloseSent) || errors.Is(err, io.EOF) {
				logger.Trace("WebSocket writer stream closed or EOF received")
			} else {
				logger.Trace("unable to write to the WebSocket connection: ", err)
			}
			tcpConn.Close()
			wsConn.Close()
			return
		}

		logger.Tracef("transferred data from TCP to WebSocket: %d bytes", n)
		if sniffer {
			usage.AddOrUpdatePort(remotePort, uint64(n))
		}
	}
}
