package handlers

import (
	"context"
	"errors"
	"github.com/musix/backhaul/internal/utils/network"
	"io"
	"net"
	"sync"

	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

// wsEOFMarker is how one direction tells its peer "I have no more data to send"
// without killing the reverse direction with it.
//
// A WebSocket has no half-close: gorilla offers no CloseWrite, and its default
// close handler echoes a Close frame straight back, which would tear down the
// reply path we are trying to protect. So the shutdown is signalled in band as
// a zero-length binary frame. That is unambiguous - the data path never emits
// an empty message, it only writes buf[:n] for n > 0 - and it degrades safely
// against a peer that predates it: the old loop handed the payload to
// tcpConn.Write, and a zero-length write is a no-op.
var wsEOFMarker = []byte{}

// onlyWriter hides every method but Write. io.CopyBuffer prefers the
// destination's ReadFrom when it has one, and *net.TCPConn does - but it has no
// zero-copy path from a WebSocket reader, so it would fall back to allocating a
// buffer of its own and ignore the pooled one we just handed over.
type onlyWriter struct {
	io.Writer
}

// WSConnectionHandler moves data between a WebSocket tunnel leg and a plain TCP
// connection, and tears the pair down only once BOTH directions have finished.
//
// The old code fully closed both conns the moment either direction ended, so a
// local peer that half-closed its upload - a clean FIN, the normal end of an
// HTTP request - tripped a full close while its reply was still in flight. On a
// socket with unread data that full close is an RST, which discards the
// buffered tail: the same silent reply truncation that TCPConnectionHandler was
// fixed for, still live on ws/wss because this handler never got the fix.
func WSConnectionHandler(ctx context.Context, proxyProtocol bool, wsConn *network.WebSocketConn, tcpConn net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	// Write Proxy Protocol V2 Header. proxy_protocol was accepted and silently
	// ignored on ws/wss - the local service saw the tunnel's address as the
	// client's on every request, which for anything doing per-IP rate limiting,
	// geo, or audit logging is worse than the option not existing.
	if proxyProtocol {
		header, err := ProxyProtocolHeader(tcpConn.RemoteAddr(), wsConn.RemoteAddr())
		if err != nil {
			logger.Error(err)
			wsConn.Close()
			tcpConn.Close()
			return
		}
		// Sent as a frame rather than written to the socket: the peer reads this
		// leg with NextReader, so a raw write would land mid-frame and corrupt
		// the stream.
		if err := wsConn.WriteMessage(network.BinaryMessage, header); err != nil {
			logger.Errorf("failed to send Proxy Protocol v2 header: %v", err)
			wsConn.Close()
			tcpConn.Close()
			return
		}
	}

	done := make(chan struct{})

	// Close both ends as soon as the transport context is cancelled (e.g. on a
	// tunnel restart). The transfer loops below block on a read until the peer
	// closes, so without this watcher an idle tunnelled connection would linger
	// long past the restart, leaking sockets that pile up across repeated
	// restarts. Closing the connections unblocks both directions at once.
	go func() {
		select {
		case <-ctx.Done():
			logger.Trace("WSConnectionHandler ctx cancelled!")
			wsConn.Close()
			tcpConn.Close()
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		transferWebSocketToTCP(wsConn, tcpConn, logger, usage, remotePort, sniffer)
	}()
	go func() {
		defer wg.Done()
		transferTCPToWebSocket(tcpConn, wsConn, logger, usage, remotePort, sniffer)
	}()
	wg.Wait()

	close(done)
	wsConn.Close()
	tcpConn.Close()
}

// transferWebSocketToTCP transfers data from a WebSocket connection to a TCP connection
func transferWebSocketToTCP(wsConn *network.WebSocketConn, tcpConn net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	// Each direction takes its own buffer from the pool - they run
	// concurrently, so they cannot share one.
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)

	for {
		// NextReader + CopyBuffer rather than ReadMessage: ReadMessage is
		// io.ReadAll underneath, which allocates a fresh buffer per message and
		// regrows it as the message arrives - roughly eight reallocations and
		// copies for a 64KB message, on the hot path of every tunnelled byte.
		// Streaming through the pooled buffer allocates nothing. NextReader
		// only ever yields text or binary frames, so
		_, r, err := wsConn.NextReader()
		if err != nil {
			if errors.Is(err, network.ErrCloseSent) || errors.Is(err, io.EOF) {
				logger.Trace("WebSocket reader stream closed or EOF received")
			} else {
				logger.Trace("unable to read from the WebSocket connection: ", err)
			}
			// The tunnel leg itself is gone, so there is no reply left to
			// protect: tear the pair down.
			wsConn.Close()
			tcpConn.Close()
			return
		}

		n, err := io.CopyBuffer(onlyWriter{tcpConn}, r, *bufPtr)
		if err != nil {
			logger.Trace("unable to write to the TCP connection: ", err)
			wsConn.Close()
			tcpConn.Close()
			return
		}

		if n == 0 {
			// wsEOFMarker: the peer is done sending. Half-close our write side
			// so the local peer sees a clean EOF, then stop reading - but leave
			// the reverse direction running so an in-flight reply still drains.
			logger.Trace("EOF marker received from the WebSocket peer")
			closeWrite(tcpConn)
			return
		}

		logger.Tracef("transferred data from WebSocket to TCP: %d bytes", n)
		if sniffer {
			usage.AddOrUpdatePort(remotePort, uint64(n))
		}
	}
}

// transferTCPToWebSocket transfers data from a TCP connection to a WebSocket connection
func transferTCPToWebSocket(tcpConn net.Conn, wsConn *network.WebSocketConn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, err := tcpConn.Read(buf)

		if n > 0 {
			if werr := wsConn.WriteMessage(network.BinaryMessage, buf[:n]); werr != nil {
				if errors.Is(werr, network.ErrCloseSent) || errors.Is(werr, io.EOF) {
					logger.Trace("WebSocket writer stream closed or EOF received")
				} else {
					logger.Trace("unable to write to the WebSocket connection: ", werr)
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

		switch {
		case err == nil:
			continue

		case errors.Is(err, io.EOF):
			// Clean half-close by the local peer: it is done sending but is
			// still waiting for the reply. Signal EOF in band and stop reading,
			// leaving the reverse direction free to relay that reply. A full
			// close here is what used to truncate it.
			logger.Trace("TCP reader stream closed or EOF received")
			if werr := wsConn.WriteMessage(network.BinaryMessage, wsEOFMarker); werr != nil {
				logger.Trace("unable to send the EOF marker: ", werr)
				tcpConn.Close()
				wsConn.Close()
			}
			return

		default:
			// net.ErrClosed means our own side was already torn down by the
			// other direction; anything else is a real transport error. Either
			// way the pair is finished and there is nothing to drain.
			if errors.Is(err, net.ErrClosed) {
				logger.Trace("TCP writer stream closed")
			} else {
				logger.Trace("unable to read from the TCP connection: ", err)
			}
			tcpConn.Close()
			wsConn.Close()
			return
		}
	}
}
