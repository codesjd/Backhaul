//go:build !windows

package network

import (
	"fmt"
	"runtime"
	"syscall"
)

func ReusePortControl(network, address string, s syscall.RawConn) error {
	var controlErr error

	// Set socket options
	err := s.Control(func(fd uintptr) {
		// Set SO_REUSEADDR
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			controlErr = fmt.Errorf("failed to set SO_REUSEADDR: %v", err)
			return
		}

		// Conditionally set SO_REUSEPORT only on Linux
		if runtime.GOOS == "linux" {
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 0xf /* SO_REUSEPORT */, 1); err != nil {
				controlErr = fmt.Errorf("failed to set SO_REUSEPORT: %v", err)
				return
			}
		}
	})

	if err != nil {
		return err
	}

	return controlErr
}

// setDialerSockOpts applies SO_RCVBUF, SO_SNDBUF and the TCP MSS clamp to a
// dialing socket, each only when > 0. Split out of TcpDialer so the dialer stays
// portable: these setsockopt options don't exist on Windows, where the build uses
// the no-op in reuse_port_windows.go.
func setDialerSockOpts(s syscall.RawConn, soRcvBuf, soSndBuf, mss int) error {
	var ctrlErr error
	err := s.Control(func(fd uintptr) {
		if soRcvBuf > 0 {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, soRcvBuf); e != nil {
				ctrlErr = fmt.Errorf("failed to set SO_RCVBUF: %v", e)
				return
			}
		}
		if soSndBuf > 0 {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, soSndBuf); e != nil {
				ctrlErr = fmt.Errorf("failed to set SO_SNDBUF: %v", e)
				return
			}
		}
		if mss > 0 {
			if e := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss); e != nil {
				ctrlErr = fmt.Errorf("failed to set MSS: %v", e)
				return
			}
		}
	})
	if err != nil {
		return err
	}
	return ctrlErr
}
