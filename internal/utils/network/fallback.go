package network

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewFallbackProxy builds a reverse proxy for requests that are NOT valid
// tunnel traffic (a wrong/absent token, or a path that isn't the tunnel's).
// Such requests are forwarded to a decoy backend - typically a local web
// server rendering an innocuous site.
//
// This lets a single backhaul ws/wss/wsmux/wssmux origin both carry the tunnel
// under a secret path and look like an ordinary website to any probe, crawler,
// or curious visitor that reaches it. With it, the obfuscation front (an nginx
// terminating TLS and serving a decoy under the same hostname) no longer has
// to sit in the tunnel's data path - where, having no zero-copy path for a
// proxied WebSocket, it copies every byte in userspace and burns roughly a
// core per Gbps. Point the CDN/origin straight at backhaul instead and let
// this handle the camouflage.
//
// fallbackAddr is a host:port dialed over plain HTTP; the decoy is expected to
// be local (e.g. 127.0.0.1:8080). The original Host header is preserved so the
// decoy sees the real hostname. Returns nil when fallbackAddr is empty, so
// callers can treat "no fallback configured" as "reject as before".
func NewFallbackProxy(fallbackAddr string) (http.Handler, error) {
	if fallbackAddr == "" {
		return nil, nil
	}
	target, err := url.Parse("http://" + fallbackAddr)
	if err != nil {
		return nil, err
	}
	return httputil.NewSingleHostReverseProxy(target), nil
}
