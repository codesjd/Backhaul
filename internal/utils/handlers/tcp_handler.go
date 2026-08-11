package handlers

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

// copyBufferSize bounds how much data moves per Read/Write syscall pair when
// a zero-copy path isn't available (see transferData). Bigger than the
// previous 16KB to cut syscall/goroutine-wake count per byte transferred,
// which matters more on low-core-count hosts where there's little spare
// parallelism to hide that overhead behind.
const copyBufferSize = 64 * 1024

// copyBufferPool avoids allocating a fresh buffer for every single
// connection - this handler runs per tunneled connection, and backhaul's
// own stated design goal is handling many of those concurrently.
var copyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufferSize)
		return &b
	},
}

func TCPConnectionHandler(ctx context.Context, proxyProtocol bool, from net.Conn, to net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	// Write Proxy Protocol V2 Header
	if proxyProtocol {
		err := WriteProxyProtocol(from, to)
		if err != nil {
			logger.Error(err)
			from.Close()
			to.Close()
			return
		}
	}

	done := make(chan struct{})

	// Close both connections as soon as the transport context is cancelled
	// (e.g. on a tunnel restart). The io.CopyBuffer calls below block until the
	// peer sends EOF, so without this watcher an idle tunnelled connection would
	// linger long past the restart. Those leaked sockets pile up across repeated
	// restarts and keep splitting traffic with the fresh generation. Closing the
	// connections unblocks both copy directions at once.
	go func() {
		select {
		case <-ctx.Done():
			from.Close()
			to.Close()
		case <-done:
		}
	}()

	// Pump both directions independently and only tear the pair down once BOTH
	// have finished. The old code fully closed both conns the moment either
	// direction ended - so a client that half-closed its upload (a clean FIN,
	// the normal end of a request) would trip a full close on the peer while its
	// reply was still in flight. On a socket with data still unread that full
	// close is an RST, discarding the buffered tail: silent reply truncation on
	// tcp/tcpmux/ws/wsmux. Each direction now half-closes only the write side it
	// finished feeding (see transferData), leaving the reverse copy free to
	// drain; the pair is fully closed here once both are done.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		transferData(from, to, logger, usage, remotePort, sniffer)
	}()
	go func() {
		defer wg.Done()
		transferData(to, from, logger, usage, remotePort, sniffer)
	}()
	wg.Wait()

	close(done)
	from.Close()
	to.Close()
}

// transferData pumps from -> to until either side closes or errors.
//
// io.CopyBuffer replaces what used to be a manual Read/Write loop. That
// matters beyond style: when both from and to are *net.TCPConn - true for
// tcp/tcpmux forwarding, where neither end is multiplexed - Go's runtime
// routes the copy straight to splice(2) on Linux, moving bytes kernel-side
// without ever landing them in this process's memory. wsmux/ws legs can't
// take that path (one end is always a smux.Stream or a WS connection, not a
// raw socket), but still benefit from the pooled buffer below instead of a
// fresh allocation per connection.
func transferData(from net.Conn, to net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)

	n, err := io.CopyBuffer(to, from, *bufPtr)

	if err != nil && !errors.Is(err, net.ErrClosed) {
		// A copy that ends on a real transport error - not a clean EOF, and not
		// our own side being closed by the other direction's teardown
		// (net.ErrClosed) - means the byte stream feeding `to` was truncated at
		// the source. For a striped destination, tell it so it does not emit the
		// end-of-stream marker that would certify the partial stream as
		// complete: the far end's Read then reports io.ErrUnexpectedEOF instead
		// of a clean EOF that silently hides the lost tail. The connection is
		// broken, so tear both directions down.
		if aw, ok := to.(interface{ AbortWrite() }); ok {
			aw.AbortWrite()
		}
		from.Close()
		to.Close()
	} else {
		// Clean EOF (err == nil), or our own side was already closed by the
		// other direction (net.ErrClosed). Propagate the EOF by half-closing
		// only `to`'s write side, so an in-flight reply on the reverse copy is
		// not truncated by a full close. Conn types that can't half-close
		// (smux.Stream, striping.Conn) fall back to a full close - no worse than
		// the previous behavior for them; the reverse copy is torn down and the
		// pair is fully closed by the caller once both directions return.
		closeWrite(to)
	}

	switch {
	case err == nil:
		logger.Trace("reader stream closed or EOF received")
	case errors.Is(err, net.ErrClosed):
		logger.Trace("writer stream closed or EOF received")
	default:
		logger.Trace("unable to transfer data: ", err)
	}

	logger.Tracef("transferred data: %d bytes", n)
	if sniffer && n > 0 {
		usage.AddOrUpdatePort(remotePort, uint64(n))
	}
}

// closeWrite shuts down only the write half of c when the conn supports it
// (*net.TCPConn, *tls.Conn, and the WS-over-raw legs whose NetConn is one of
// those), sending a clean FIN that lets the peer finish replying. Conn types
// without a half-close (smux.Stream, striping.Conn) fall back to a full close.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	c.Close()
}
