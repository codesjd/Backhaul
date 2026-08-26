package network

import (
	"fmt"
	"net"
	"strconv"
)

func ResolveRemoteAddr(remoteAddr string) (int, string, error) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid remote address format: %v", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid port number: %v", err)
	}

	return port, host, nil
}
