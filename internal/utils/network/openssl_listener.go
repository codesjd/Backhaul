//go:build openssl

package network

import (
	"fmt"
	"net"

	openssl "github.com/libp2p/go-openssl"
)

// newOpenSSLListener terminates TLS with the system OpenSSL library instead of
// Go's crypto/tls. The SSL_CTX is configured to mirror a stock nginx:
//
//   - TLS 1.2 + 1.3 only (SSLv2/3 disabled).
//   - Server cipher preference on - nginx's `ssl_prefer_server_ciphers on`. On
//     OpenSSL 3.0 this makes TLS 1.3 negotiate AES-256-GCM first, the same
//     choice nginx makes and the one Go's stack cannot be configured to make
//     (Go hardcodes AES-128-GCM first when AES-NI is present, and does not
//     expose TLS 1.3 ciphersuite ordering at all).
//   - ALPN advertising http/1.1.
//
// Because this is the same OpenSSL that nginx links, the ServerHello it emits -
// extension order included - matches nginx's, so a direct probe of the origin
// can't distinguish them on the TLS handshake. That is the whole reason this
// path exists.
//
// Caveats, stated plainly:
//   - Match nginx's OpenSSL *major* version for the closest fingerprint; build
//     against and run on the same one.
//   - nginx's `http2` directive also advertises h2 in ALPN. This listener
//     speaks HTTP/1.1 only (the WebSocket tunnel needs it), so for the tightest
//     parity drop `http2` from any nginx you benchmark against.
//   - The TLS 1.3 ciphersuite list is left at OpenSSL's default on purpose - it
//     already leads with AES-256-GCM exactly as nginx does.
func newOpenSSLListener(addr, certFile, keyFile string) (net.Listener, error) {
	ctx, err := openssl.NewCtxFromFiles(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("openssl ctx from files: %w", err)
	}
	if !ctx.SetMinProtoVersion(openssl.TLS1_2_VERSION) {
		return nil, fmt.Errorf("openssl: failed to set min proto version")
	}
	if !ctx.SetMaxProtoVersion(openssl.TLS1_3_VERSION) {
		return nil, fmt.Errorf("openssl: failed to set max proto version")
	}
	ctx.SetOptions(openssl.CipherServerPreference | openssl.NoSSLv2 | openssl.NoSSLv3)
	if err := ctx.SetNextProtos([]string{"http/1.1"}); err != nil {
		return nil, fmt.Errorf("openssl set alpn: %w", err)
	}
	return openssl.Listen("tcp", addr, ctx)
}
