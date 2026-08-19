package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	ctransport "github.com/musix/backhaul/internal/client/transport"
	stransport "github.com/musix/backhaul/internal/server/transport"
)

// bulkSink accepts one TCP connection on `port`, drains it to EOF, and reports
// the total byte count on the returned channel. Stands in for the client-side
// local service that the tunnel forwards to.
func bulkSink(t *testing.T, ctx context.Context, port int) <-chan int64 {
	t.Helper()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("bulk sink listen: %v", err)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	total := make(chan int64, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			total <- -1
			return
		}
		defer conn.Close()
		n, _ := io.Copy(io.Discard, conn)
		total <- n
	}()
	return total
}

// runBulkUpload pushes `size` bytes through the tunnel in the "upload" direction
// (public listener on the server -> QUIC stream -> client -> local sink) and
// fails if the whole payload does not arrive within the timeout. This is the
// server->client stream send path that the field report says stalls.
func runBulkUpload(t *testing.T, srvCfg *stransport.QuicConfig, cliCfg *ctransport.QuicConfig, pubPort, sinkPort int, size int64) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sinkTotal := bulkSink(t, ctx, sinkPort)

	srv := stransport.NewQuicServer(ctx, srvCfg, quietLogger())
	go srv.Start()
	cli := ctransport.NewQuicClient(ctx, cliCfg, quietLogger())
	go cli.Start()

	// Connect to the public port (retry while the tunnel comes up).
	var pub net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pub, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial public tcp: %v", err)
	}

	// Push `size` bytes as fast as possible, then half-close so the sink sees EOF.
	go func() {
		buf := make([]byte, 64*1024)
		var sent int64
		for sent < size {
			n := int64(len(buf))
			if size-sent < n {
				n = size - sent
			}
			if _, werr := pub.Write(buf[:n]); werr != nil {
				return
			}
			sent += n
		}
		if cw, ok := pub.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	select {
	case got := <-sinkTotal:
		if got != size {
			t.Fatalf("bulk upload stalled/truncated: sink received %d of %d bytes", got, size)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("bulk upload TIMED OUT: payload did not fully arrive within 30s (size=%d)", size)
	}
	pub.Close()
}

// TestQuicConnChurn opens many short connections in sequence and requires every
// one to round-trip. A speed test does exactly this, and a stream that isn't
// fully released on teardown would leak stream credit until OpenStreamSync blocks
// and the tunnel wedges - which this guards against.
func TestQuicConnChurn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := freeUDPPort(t)
	pubPort := freeTCPPort(t)
	echoPort := freeTCPPort(t)
	tcpEcho(t, ctx, echoPort)
	const obfs = "churn-obfs"

	srv := stransport.NewQuicServer(ctx, &stransport.QuicConfig{
		BindAddr: fmt.Sprintf("127.0.0.1:%d", serverPort), Token: "t",
		Ports:        []string{fmt.Sprintf("%d=%d", pubPort, echoPort)},
		ObfsPassword: obfs, ObfsSTUN: true, Masquerade: true,
	}, quietLogger())
	go srv.Start()
	cli := ctransport.NewQuicClient(ctx, &ctransport.QuicConfig{
		RemoteAddr: fmt.Sprintf("127.0.0.1:%d", serverPort), Token: "t",
		DialTimeOut: 5 * time.Second, RetryInterval: 500 * time.Millisecond,
		ObfsPassword: obfs, ObfsSTUN: true, Masquerade: true,
	}, quietLogger())
	go cli.Start()

	// Wait for the tunnel to come up via a first successful round trip.
	msg := []byte("ping")
	deadline := time.Now().Add(10 * time.Second)
	up := false
	for time.Now().Before(deadline) && !up {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), time.Second)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c.SetDeadline(time.Now().Add(time.Second))
		c.Write(msg)
		got := make([]byte, len(msg))
		if _, err := readFull(c, got); err == nil {
			up = true
		}
		c.Close()
	}
	if !up {
		t.Fatal("tunnel never came up")
	}

	const n = 300
	for i := 0; i < n; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), 2*time.Second)
		if err != nil {
			t.Fatalf("conn %d dial: %v", i, err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("conn %d write: %v", i, err)
		}
		got := make([]byte, len(msg))
		if _, err := readFull(c, got); err != nil {
			t.Fatalf("conn %d read (tunnel wedged after %d conns?): %v", i, i, err)
		}
		c.Close()
	}
}

// TestQuicBulkUploadObfs reproduces the upload path with obfuscation only.
func TestQuicBulkUploadObfs(t *testing.T) {
	serverPort := freeUDPPort(t)
	pubPort := freeTCPPort(t)
	sinkPort := freeTCPPort(t)
	const obfs = "bulk-obfs"
	runBulkUpload(t,
		&stransport.QuicConfig{
			BindAddr: fmt.Sprintf("127.0.0.1:%d", serverPort), Token: "t",
			Ports:        []string{fmt.Sprintf("%d=%d", pubPort, sinkPort)},
			ObfsPassword: obfs,
			UpMbps:       100, DownMbps: 100,
		},
		&ctransport.QuicConfig{
			RemoteAddr: fmt.Sprintf("127.0.0.1:%d", serverPort), Token: "t",
			DialTimeOut: 5 * time.Second, RetryInterval: 500 * time.Millisecond,
			ObfsPassword: obfs, UpMbps: 100, DownMbps: 100,
		},
		pubPort, sinkPort, 32*1024*1024)
}

// TestQuicBulkUploadMasquerade reproduces the upload path with the full stack
// the field config uses (obfs + STUN + masquerade).
func TestQuicBulkUploadMasquerade(t *testing.T) {
	serverPort := freeUDPPort(t)
	pubPort := freeTCPPort(t)
	sinkPort := freeTCPPort(t)
	const obfs = "bulk-obfs"
	runBulkUpload(t,
		&stransport.QuicConfig{
			BindAddr: fmt.Sprintf("127.0.0.1:%d", serverPort), Token: "t",
			Ports:        []string{fmt.Sprintf("%d=%d", pubPort, sinkPort)},
			ObfsPassword: obfs, ObfsSTUN: true, Masquerade: true,
			UpMbps: 100, DownMbps: 100,
		},
		&ctransport.QuicConfig{
			RemoteAddr: fmt.Sprintf("127.0.0.1:%d", serverPort), Token: "t",
			DialTimeOut: 5 * time.Second, RetryInterval: 500 * time.Millisecond,
			ObfsPassword: obfs, ObfsSTUN: true, Masquerade: true, UpMbps: 100, DownMbps: 100,
		},
		pubPort, sinkPort, 32*1024*1024)
}
