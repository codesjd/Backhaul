//go:build windows

package network

import "syscall"

// Windows stubs for the socket tunings applied on Unix. These use Linux/Unix
// setsockopt options (SO_REUSEPORT, SO_RCVBUF/SO_SNDBUF, TCP_MAXSEG) that either
// don't exist or take a different fd type on Windows, so the file next to this one
// (reuse_port.go) is built only with //go:build !windows. Windows is a
// development-only target - the tunnel is deployed on Linux - so the tuning is a
// no-op here: sockets still work, just without the extra tuning.
func ReusePortControl(network, address string, s syscall.RawConn) error { return nil }

func setDialerSockOpts(s syscall.RawConn, soRcvBuf, soSndBuf, mss int) error { return nil }
