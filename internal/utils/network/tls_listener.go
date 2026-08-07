package network

import (
	"crypto/tls"
	"fmt"
	"net"
)

// TLS engine names for the server's wss/wssmux `tls_engine` option.
const (
	TLSEngineGo      = "go"      // Go crypto/tls - the default; keeps pure-Go static builds
	TLSEngineOpenSSL = "openssl" // system OpenSSL via cgo - requires a binary built with -tags openssl
)

// NewTLSListener returns a listener that terminates TLS with the chosen engine.
// The listener yields already-decrypted net.Conns, so callers hand it straight
// to http.Server.Serve.
//
// engine "" or "go" uses Go's crypto/tls. engine "openssl" uses the system
// OpenSSL library, whose server-side handshake fingerprint (TLS 1.3 cipher
// choice, ServerHello extension order) matches a same-version nginx far more
// closely than Go's stack can be made to - which matters when the origin's IP
// is directly reachable and a censor can fingerprint it. The OpenSSL path only
// exists in binaries built with the "openssl" build tag; otherwise it returns
// an explanatory error instead of silently falling back.
func NewTLSListener(engine, addr, certFile, keyFile string) (net.Listener, error) {
	switch engine {
	case "", TLSEngineGo:
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls keypair: %w", err)
		}
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		return tls.Listen("tcp", addr, cfg)
	case TLSEngineOpenSSL:
		return newOpenSSLListener(addr, certFile, keyFile)
	default:
		return nil, fmt.Errorf("unknown tls_engine %q (want %q or %q)", engine, TLSEngineGo, TLSEngineOpenSSL)
	}
}
