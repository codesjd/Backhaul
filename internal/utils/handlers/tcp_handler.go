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
	done := make(chan struct{})

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

	go func() {
		defer close(done)
		transferData(from, to, logger, usage, remotePort, sniffer)
	}()

	transferData(to, from, logger, usage, remotePort, sniffer)

	select {
	case <-ctx.Done():
		from.Close()
		to.Close()
		return
	case <-done:
	}
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

	from.Close()
	to.Close()

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
