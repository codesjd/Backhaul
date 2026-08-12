package network

// HTTP/3 decoy masquerade.
//
// With quic_masquerade the QUIC listener presents itself as a genuine HTTP/3
// origin. The server runs an http3.Server on every accepted connection:
//
//   - The tunnel client authenticates with one ordinary-looking HTTP/3 request
//     carrying the shared token in an Authorization header. On success the server
//     keeps the underlying *quic.Conn as the active tunnel and drives it exactly
//     as before (server-opened streams for TCP flows, QUIC datagrams for UDP).
//   - Every other request - an active censor probe, a curious scanner, a real
//     browser - is reverse-proxied to a configured decoy backend, so the endpoint
//     answers like a normal website (the nginx-style behaviour ws/wss already
//     have via `fallback`). No token, no tunnel: just the decoy.
//
// This closes the hole in the ALPN-only masquerade, where an active HTTP/3 probe
// got a connection error no real h3 server would ever return.
import (
	"net/http"

	"github.com/sagernet/quic-go/http3"
)

const (
	// H3AuthHeader carries the tunnel token on the masquerade auth request. Both
	// ends must agree; it is a normal request header so the exchange looks like
	// ordinary authenticated HTTP/3 to anyone without the token.
	H3AuthHeader = "Authorization"
	// H3AuthScheme is the token's scheme prefix in H3AuthHeader.
	H3AuthScheme = "Bearer "
)

// NewH3ClientTransport builds an HTTP/3 Transport for the tunnel client's
// masquerade auth. HTTP/3 datagrams are disabled so the raw QUIC datagrams the
// UDP tunnel relies on pass through untouched; the transport is only used to
// wrap an already-dialed *quic.Conn via NewRawClientConn.
func NewH3ClientTransport() *http3.Transport {
	return &http3.Transport{EnableDatagrams: false}
}

// DecoyHandler wraps an optional reverse-proxy so that, when no decoy backend is
// configured, probes still get a plausible generic response instead of an error.
func DecoyHandler(proxy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proxy != nil {
			proxy.ServeHTTP(w, r)
			return
		}
		// No backend configured: answer like a bare, idle web server.
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>\n"))
	})
}
