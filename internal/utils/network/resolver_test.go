package network

import (
	"testing"
)

func TestResolveRemoteAddr(t *testing.T) {
	tests := []struct {
		name         string
		remoteAddr   string
		expectedPort int
		expectedAddr string
		expectError  bool
	}{
		{
			name:         "host and port",
			remoteAddr:   "example.com:443",
			expectedPort: 443,
			expectedAddr: "example.com:443",
		},
		{
			name:         "bare port defaults to localhost",
			remoteAddr:   "8080",
			expectedPort: 8080,
			expectedAddr: "127.0.0.1:8080",
		},
		{
			name:         "empty host with port",
			remoteAddr:   ":8080",
			expectedPort: 8080,
			expectedAddr: ":8080",
		},
		{
			name:         "IPv4 and port",
			remoteAddr:   "127.0.0.1:8080",
			expectedPort: 8080,
			expectedAddr: "127.0.0.1:8080",
		},
		{
			name:         "IPv6 and port",
			remoteAddr:   "[::1]:8443",
			expectedPort: 8443,
			expectedAddr: "[::1]:8443",
		},
		{
			name:        "invalid port string",
			remoteAddr:  "example.com:invalid",
			expectError: true,
		},
		{
			name:        "missing port",
			remoteAddr:  "example.com:",
			expectError: true,
		},
		{
			name:        "empty input",
			remoteAddr:  "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, addr, err := ResolveRemoteAddr(tt.remoteAddr)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected an error for %q, got nil (port=%d addr=%q)", tt.remoteAddr, port, addr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.remoteAddr, err)
			}
			if port != tt.expectedPort {
				t.Errorf("port = %d, want %d", port, tt.expectedPort)
			}
			if addr != tt.expectedAddr {
				t.Errorf("addr = %q, want %q (must stay dialable host:port)", addr, tt.expectedAddr)
			}
		})
	}
}
