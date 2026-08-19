//go:build windows

package network

import (
	"context"
	"net"
	"time"
)

// ListenWithBuffers on Windows creates a plain keep-alive TCP listener. The
// SO_RCVBUF/SO_SNDBUF/MSS/TCP_NODELAY tuning the Unix build applies (see
// listener.go, //go:build !windows) uses setsockopt options absent on Windows.
// Windows is a dev-only target (deployment is Linux), so the tuning is skipped
// rather than reimplemented; the listener itself is fully functional.
func ListenWithBuffers(network, address string, rcvBufSize, sndBufSize, mss int, keepAlivePeriod time.Duration, dis_nodelay bool) (net.Listener, error) {
	lc := &net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Interval: keepAlivePeriod, Count: 9, Idle: 0},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return lc.Listen(ctx, network, address)
}
