package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	ctransport "github.com/musix/backhaul/internal/client/transport"
	stransport "github.com/musix/backhaul/internal/server/transport"
)

// TestQuicServerReleasesSocketOnCancel guards the hot-reload crash: quic.Listen
// is handed a socket we opened, so quic-go's createdConn is false and it never
// closes it. If Start doesn't close the socket itself on ctx cancel, the UDP port
// stays bound and the next instance (config hot-reload cancels the old context and
// binds a fresh one on the same port) dies with "address already in use". This
// starts a server, cancels it, and requires the port to become bindable again.
func TestQuicServerReleasesSocketOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	port := freeUDPPort(t)
	bind := fmt.Sprintf("127.0.0.1:%d", port)

	srv := stransport.NewQuicServer(ctx, &stransport.QuicConfig{BindAddr: bind, Token: "t"}, quietLogger())
	go srv.Start()
	time.Sleep(300 * time.Millisecond) // let it bind

	cancel()

	var rebindErr error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ua, _ := net.ResolveUDPAddr("udp", bind)
		pc, err := net.ListenUDP("udp", ua)
		if err == nil {
			pc.Close()
			rebindErr = nil
			break
		}
		rebindErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if rebindErr != nil {
		t.Fatalf("server did not release the listen socket after cancel (hot-reload would crash): %v", rebindErr)
	}
}

// TestQuicTunnelPortHopping exercises the client's PortHoppingPacketConn through a
// real QUIC handshake. A single-port range [P,P] makes the wrapper always rewrite
// the destination to P - the port the server actually listens on - so the handshake
// runs through the dest-port rewrite and source-address normalization without the
// server-side NAT redirect (which needs iptables/CAP_NET_ADMIN and can't run in CI).
// This covers the previously-untested claim that the wrapper is transparent to a
// live connection; the multi-port range-folding rule is covered by TestPortHoppingRuleSpec.
func TestQuicTunnelPortHopping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "test-token"
	serverPort := freeUDPPort(t)
	pubPort := freeTCPPort(t)
	echoPort := freeTCPPort(t)
	tcpEcho(t, ctx, echoPort)

	srvCfg := &stransport.QuicConfig{
		BindAddr: fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:    token,
		Ports:    []string{fmt.Sprintf("%d=%d", pubPort, echoPort)},
		// Server binds P normally; no PortRange here so the test doesn't need the
		// NAT rule. The client hops within [P,P], which resolves to P.
	}
	srv := stransport.NewQuicServer(ctx, srvCfg, quietLogger())
	go srv.Start()

	cliCfg := &ctransport.QuicConfig{
		RemoteAddr:    fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:         token,
		DialTimeOut:   5 * time.Second,
		RetryInterval: 500 * time.Millisecond,
		PortRange:     []int{serverPort, serverPort},
	}
	cli := ctransport.NewQuicClient(ctx, cliCfg, quietLogger())
	go cli.Start()

	payload := make([]byte, 64*1024)
	rand.Read(payload)

	var tcpConn net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		tcpConn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial public tcp (port-hopping handshake never completed): %v", err)
	}
	defer tcpConn.Close()

	if _, err := tcpConn.Write(payload); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	got := make([]byte, len(payload))
	_ = tcpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := readFull(tcpConn, got); err != nil {
		t.Fatalf("tcp read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("tcp echo mismatch through the port-hopping tunnel")
	}
}
