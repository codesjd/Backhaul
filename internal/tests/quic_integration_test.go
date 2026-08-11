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

	"github.com/sirupsen/logrus"
)

func quietLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.FatalLevel)
	return l
}

// freeUDPPort grabs an ephemeral UDP port and releases it, returning the number.
// Good enough for a local test even with the small reuse race.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("free udp port: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free tcp port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// tcpEcho serves a TCP echo on the given port until ctx is cancelled.
func tcpEcho(t *testing.T, ctx context.Context, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("tcp echo listen: %v", err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
}

// udpEcho serves a UDP echo on the given port until ctx is cancelled.
func udpEcho(t *testing.T, ctx context.Context, port int) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
}

// TestQuicTunnelTCPAndUDP stands up the QUIC server and client transports over
// localhost and verifies a TCP flow and a UDP flow both round-trip through the
// tunnel to a local echo service.
func TestQuicTunnelTCPAndUDP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "test-token"

	serverPort := freeUDPPort(t) // QUIC listens on UDP
	pubPort := freeTCPPort(t)    // public port clients hit (used for both TCP and UDP)
	echoPort := freeTCPPort(t)   // one number, served by a TCP echo and a UDP echo

	// The QUIC server forwards both protocols of a mapped port to the same
	// remote address, so run a TCP echo and a UDP echo on the same port number
	// (different protocols share a port fine).
	tcpEcho(t, ctx, echoPort)
	udpEcho(t, ctx, echoPort)

	const obfs = "s3cret-obfs" // exercise Salamander packet obfuscation end to end

	srvCfg := &stransport.QuicConfig{
		BindAddr:     fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:        token,
		Ports:        []string{fmt.Sprintf("%d=127.0.0.1:%d", pubPort, echoPort)},
		Keepalive:    30 * time.Second,
		ObfsPassword: obfs,
		UpMbps:       100, // exercise Brutal congestion control on both directions
		DownMbps:     100,
	}
	srv := stransport.NewQuicServer(ctx, srvCfg, quietLogger())
	go srv.Start()

	cliCfg := &ctransport.QuicConfig{
		RemoteAddr:    fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:         token,
		KeepAlive:     30 * time.Second,
		DialTimeOut:   5 * time.Second,
		RetryInterval: 500 * time.Millisecond,
		ObfsPassword:  obfs,
		UpMbps:        100,
		DownMbps:      100,
	}
	cli := ctransport.NewQuicClient(ctx, cliCfg, quietLogger())
	go cli.Start()

	// --- TCP round trip ---
	payload := make([]byte, 128*1024) // spans many buffers
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
		t.Fatalf("dial public tcp: %v", err)
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
		t.Fatalf("tcp echo mismatch (got %d bytes)", len(got))
	}

	// --- UDP round trip ---
	udpConn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", pubPort))
	if err != nil {
		t.Fatalf("dial public udp: %v", err)
	}
	defer udpConn.Close()

	msg := []byte("hello over quic datagrams")
	var udpOK bool
	for attempt := 0; attempt < 20 && !udpOK; attempt++ {
		if _, err := udpConn.Write(msg); err != nil {
			t.Fatalf("udp write: %v", err)
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		ubuf := make([]byte, 2048)
		n, err := udpConn.Read(ubuf)
		if err == nil && bytes.Equal(ubuf[:n], msg) {
			udpOK = true
		}
	}
	if !udpOK {
		t.Fatal("udp echo did not round-trip through the quic tunnel")
	}

	// --- large UDP round trip (exercises datagram fragmentation/reassembly) ---
	big := make([]byte, 6000) // several fragments' worth
	rand.Read(big)
	var bigOK bool
	for attempt := 0; attempt < 20 && !bigOK; attempt++ {
		if _, err := udpConn.Write(big); err != nil {
			t.Fatalf("large udp write: %v", err)
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(time.Second))
		rbuf := make([]byte, 8192)
		n, err := udpConn.Read(rbuf)
		if err == nil && bytes.Equal(rbuf[:n], big) {
			bigOK = true
		}
	}
	if !bigOK {
		t.Fatal("fragmented UDP packet did not round-trip through the quic tunnel")
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
