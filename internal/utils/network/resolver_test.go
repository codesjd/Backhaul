package network

import (
	"testing"
)

func TestResolveRemoteAddr(t *testing.T) {
	tests := []struct {
		name         string
		remoteAddr   string
		expectedPort int
		expectedHost string
		expectError  bool
	}{
		{
			name:         "Host and port provided",
			remoteAddr:   "example.com:443",
			expectedPort: 443,
			expectedHost: "example.com",
			expectError:  false,
		},
		{
			name:         "Only port provided (missing colon, triggers error)",
			remoteAddr:   "8080",
			expectedPort: 0,
			expectedHost: "",
			expectError:  true,
		},
		{
			name:         "Empty host with port",
			remoteAddr:   ":8080",
			expectedPort: 8080,
			expectedHost: "",
			expectError:  false,
		},
		{
			name:         "IPv4 and port provided",
			remoteAddr:   "127.0.0.1:8080",
			expectedPort: 8080,
			expectedHost: "127.0.0.1",
			expectError:  false,
		},
		{
			name:         "IPv6 and port provided",
			remoteAddr:   "[::1]:8443",
			expectedPort: 8443,
			expectedHost: "::1",
			expectError:  false,
		},
		{
			name:         "Invalid port string",
			remoteAddr:   "example.com:invalid",
			expectedPort: 0,
			expectedHost: "",
			expectError:  true,
		},
		{
			name:         "No port provided",
			remoteAddr:   "example.com:",
			expectedPort: 0,
			expectedHost: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, host, err := ResolveRemoteAddr(tt.remoteAddr)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected an error, but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if port != tt.expectedPort {
				t.Errorf("expected port %d, got %d", tt.expectedPort, port)
			}

			if host != tt.expectedHost {
				t.Errorf("expected host %q, got %q", tt.expectedHost, host)
			}
		})
	}
}
