package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ResolveRemoteAddr parses the remote address a peer sent us and returns the
// port together with a fully dialable "host:port" string (callers hand the
// second value straight to a dialer, so it must always carry the port).
//
//   - "host:port"      -> (port, "host:port")      unchanged, host preserved
//   - "[::1]:port"     -> (port, "[::1]:port")     IPv6, now parsed correctly
//   - ":port"          -> (port, ":port")          empty host preserved
//   - "port"           -> (port, "127.0.0.1:port") bare port defaults to localhost
//
// Anything else (missing/invalid port, garbage) is a hard error.
func ResolveRemoteAddr(remoteAddr string) (int, string, error) {
	// A bare port with no host (e.g. "8080"): default the host to localhost,
	// matching the long-standing behavior the transports rely on.
	if port, err := strconv.Atoi(strings.TrimSpace(remoteAddr)); err == nil {
		return port, fmt.Sprintf("127.0.0.1:%d", port), nil
	}

	// net.SplitHostPort correctly handles bracketed IPv6 literals, unlike a
	// naive strings.Split on ":".
	_, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid remote address %q: %w", remoteAddr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid port %q in remote address: %w", portStr, err)
	}

	// Return the original address untouched: it is already a dialable
	// host:port (SplitHostPort just validated it), so callers keep the exact
	// string the peer sent.
	return port, remoteAddr, nil
}
