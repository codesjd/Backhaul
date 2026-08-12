package config

// TransportType defines the type of transport.
type TransportType string

const (
	TCP    TransportType = "tcp"
	TCPMUX TransportType = "tcpmux"
	WS     TransportType = "ws"
	WSS    TransportType = "wss"
	WSMUX  TransportType = "wsmux"
	WSSMUX TransportType = "wssmux"
	UDP    TransportType = "udp"
	QUIC   TransportType = "quic"
)

// ServerConfig represents the configuration for the server.
type ServerConfig struct {
	BindAddr             string        `toml:"bind_addr"`
	Transport            TransportType `toml:"transport"`
	Token                string        `toml:"token"`
	Nodelay              bool          `toml:"nodelay"`
	Keepalive            int           `toml:"keepalive_period"`
	ChannelSize          int           `toml:"channel_size"`
	LogLevel             string        `toml:"log_level"`
	Ports                []string      `toml:"ports"`
	PPROF                bool          `toml:"pprof"`
	MuxSession           int           `toml:"mux_session"`
	MuxVersion           int           `toml:"mux_version"`
	MaxFrameSize         int           `toml:"mux_framesize"`
	MaxReceiveBuffer     int           `toml:"mux_recievebuffer"`
	MaxStreamBuffer      int           `toml:"mux_streambuffer"`
	MuxKeepaliveDisabled bool          `toml:"mux_keepalive_disabled"`
	StripeFactor         int           `toml:"mux_stripe"`
	Sniffer              bool          `toml:"sniffer"`
	WebPort              int           `toml:"web_port"`
	SnifferLog           string        `toml:"sniffer_log"`
	TLSCertFile          string        `toml:"tls_cert"`
	TLSKeyFile           string        `toml:"tls_key"`
	TLSCerts             []string      `toml:"tls_certs"` // optional: multiple cert files for SNI (multi-domain); pairs with tls_keys by index
	TLSKeys              []string      `toml:"tls_keys"`  // optional: key files matching tls_certs by index
	Heartbeat            int           `toml:"heartbeat"`
	MuxCon               int           `toml:"mux_con"`
	AcceptUDP            bool          `toml:"accept_udp"`
	SkipOptz             bool          `toml:"skip_optz"`
	MSS                  int           `toml:"mss"`
	SO_RCVBUF            int           `toml:"so_rcvbuf"`
	SO_SNDBUF            int           `toml:"so_sndbuf"`
	ProxyProtocol        bool          `toml:"proxy_protocol"`
	Path                 string        `toml:"path"`
	Fallback             string        `toml:"fallback"`
	TLSEngine            string        `toml:"tls_engine"`
	QuicUpMbps           int           `toml:"quic_up_mbps"`       // quic: target upload bandwidth in Mbps. >0 enables real Brutal congestion control on the send path; 0 = default (Cubic).
	QuicDownMbps         int           `toml:"quic_down_mbps"`     // quic: target download bandwidth in Mbps; sizes QUIC flow-control windows. 0 = default.
	QuicObfs             string        `toml:"quic_obfs_password"` // quic: Salamander-style packet obfuscation password. Must match the client. Empty = plain QUIC.
	QuicMasquerade       bool          `toml:"quic_masquerade"`    // quic: advertise ALPN "h3" so the handshake blends with HTTP/3 web traffic. Must match the client.
	QuicPortRange        []int         `toml:"quic_port_range"`    // quic: [start, end] UDP port range for port hopping to defeat per-flow throttling. Server must accept this range (via iptables REDIRECT or native binding). Empty = single port.
	QuicObfsSTUN         bool          `toml:"quic_obfs_stun"`     // quic: prepend a mimicked STUN header to obfuscated packets so they don't look full-entropy to the fully-encrypted-traffic classifier. Requires quic_obfs_password. Must match the client.
	QuicKeepaliveMin     int           `toml:"quic_keepalive_min"` // quic: min seconds for the randomized (jittered) keep-alive period. 0 = derive from keepalive (default 15s).
	QuicKeepaliveMax     int           `toml:"quic_keepalive_max"` // quic: max seconds for the randomized (jittered) keep-alive period. 0 = derive from keepalive (default 45s).
}

// ClientConfig represents the configuration for the client.
type ClientConfig struct {
	RemoteAddr           string        `toml:"remote_addr"`
	RemoteAddrs          []string      `toml:"remote_addrs"` // optional: multiple tunnel endpoints (e.g. same origin behind several CDNs/domains); the ws/wss/wsmux/wssmux pool spreads across them round-robin. Falls back to remote_addr when empty.
	EdgeIPs              []string      `toml:"edge_ips"`     // optional: edge IP to dial per remote_addrs entry (aligned by index); empty entries dial the domain directly.
	Transport            TransportType `toml:"transport"`
	Token                string        `toml:"token"`
	ConnectionPool       int           `toml:"connection_pool"`
	RetryInterval        int           `toml:"retry_interval"`
	Nodelay              bool          `toml:"nodelay"`
	Keepalive            int           `toml:"keepalive_period"`
	LogLevel             string        `toml:"log_level"`
	PPROF                bool          `toml:"pprof"`
	MuxSession           int           `toml:"mux_session"`
	MuxVersion           int           `toml:"mux_version"`
	MaxFrameSize         int           `toml:"mux_framesize"`
	MaxReceiveBuffer     int           `toml:"mux_recievebuffer"`
	MaxStreamBuffer      int           `toml:"mux_streambuffer"`
	MuxKeepaliveDisabled bool          `toml:"mux_keepalive_disabled"`
	StripeFactor         int           `toml:"mux_stripe"`
	Sniffer              bool          `toml:"sniffer"`
	WebPort              int           `toml:"web_port"`
	SnifferLog           string        `toml:"sniffer_log"`
	DialTimeout          int           `toml:"dial_timeout"`
	AggressivePool       bool          `toml:"aggressive_pool"`
	EdgeIP               string        `toml:"edge_ip"`
	SkipOptz             bool          `toml:"skip_optz"`
	MSS                  int           `toml:"mss"`
	SO_RCVBUF            int           `toml:"so_rcvbuf"`
	SO_SNDBUF            int           `toml:"so_sndbuf"`
	Path                 string        `toml:"path"`
	TLSVerify            bool          `toml:"tls_verify"`         // wss/wssmux/quic: verify the server's TLS certificate. Off by default for self-signed setups; enable to stop an on-path party from MITMing the token-bearing handshake.
	QuicUpMbps           int           `toml:"quic_up_mbps"`       // quic: target upload bandwidth in Mbps. >0 enables real Brutal congestion control on the send path; 0 = default (Cubic).
	QuicDownMbps         int           `toml:"quic_down_mbps"`     // quic: target download bandwidth in Mbps; sizes QUIC flow-control windows. 0 = default.
	QuicObfs             string        `toml:"quic_obfs_password"` // quic: Salamander-style packet obfuscation password. Must match the server. Empty = plain QUIC.
	QuicMasquerade       bool          `toml:"quic_masquerade"`    // quic: advertise ALPN "h3" so the handshake blends with HTTP/3 web traffic. Must match the server.
	QuicPortRange        []int         `toml:"quic_port_range"`    // quic: [start, end] UDP port range for port hopping to defeat per-flow throttling. Client rotates destination port across this range. Empty = single port from remote_addr.
	QuicObfsSTUN         bool          `toml:"quic_obfs_stun"`     // quic: prepend a mimicked STUN header to obfuscated packets so they don't look full-entropy to the fully-encrypted-traffic classifier. Requires quic_obfs_password. Must match the server.
	QuicKeepaliveMin     int           `toml:"quic_keepalive_min"` // quic: min seconds for the randomized (jittered) keep-alive period. 0 = derive from keepalive (default 15s).
	QuicKeepaliveMax     int           `toml:"quic_keepalive_max"` // quic: max seconds for the randomized (jittered) keep-alive period. 0 = derive from keepalive (default 45s).
}

// Config represents the complete configuration, including both server and client settings.
type Config struct {
	Server ServerConfig `toml:"server"`
	Client ClientConfig `toml:"client"`
}
