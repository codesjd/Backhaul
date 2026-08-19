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

// TestQuicSTUNThroughRealHandshake exercises obfs+STUN through a real quic-go
// handshake (the unit test only covers the codec in isolation). Masquerade off.
func TestQuicSTUNThroughRealHandshake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "stun-token"
	const obfs = "stun-obfs-pass"
	serverPort := freeUDPPort(t)
	pubPort := freeTCPPort(t)
	echoPort := freeTCPPort(t)
	tcpEcho(t, ctx, echoPort)

	srv := stransport.NewQuicServer(ctx, &stransport.QuicConfig{
		BindAddr:     fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:        token,
		Ports:        []string{fmt.Sprintf("%d=%d", pubPort, echoPort)},
		ObfsPassword: obfs,
		ObfsSTUN:     true,
	}, quietLogger())
	go srv.Start()

	cli := ctransport.NewQuicClient(ctx, &ctransport.QuicConfig{
		RemoteAddr:    fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:         token,
		DialTimeOut:   5 * time.Second,
		RetryInterval: 500 * time.Millisecond,
		ObfsPassword:  obfs,
		ObfsSTUN:      true,
	}, quietLogger())
	go cli.Start()

	payload := make([]byte, 64*1024)
	rand.Read(payload)
	var conn net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial public tcp: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := readFull(conn, got); err != nil {
		t.Fatalf("tcp read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("stun tunnel echo mismatch")
	}
}

// TestQuicSTUNPlusMasquerade exercises the full stack the sample configs enable:
// obfs + STUN + HTTP/3 masquerade together, through a real handshake and tunnel.
func TestQuicSTUNPlusMasquerade(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const token = "combo-token"
	const obfs = "combo-obfs-pass"
	serverPort := freeUDPPort(t)
	pubPort := freeTCPPort(t)
	echoPort := freeTCPPort(t)
	tcpEcho(t, ctx, echoPort)

	srv := stransport.NewQuicServer(ctx, &stransport.QuicConfig{
		BindAddr:     fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:        token,
		Ports:        []string{fmt.Sprintf("%d=%d", pubPort, echoPort)},
		ObfsPassword: obfs,
		ObfsSTUN:     true,
		Masquerade:   true,
	}, quietLogger())
	go srv.Start()

	cli := ctransport.NewQuicClient(ctx, &ctransport.QuicConfig{
		RemoteAddr:    fmt.Sprintf("127.0.0.1:%d", serverPort),
		Token:         token,
		DialTimeOut:   5 * time.Second,
		RetryInterval: 500 * time.Millisecond,
		ObfsPassword:  obfs,
		ObfsSTUN:      true,
		Masquerade:    true,
	}, quietLogger())
	go cli.Start()

	payload := make([]byte, 96*1024)
	rand.Read(payload)
	var conn net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pubPort), time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial public tcp: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := readFull(conn, got); err != nil {
		t.Fatalf("tcp read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("obfs+stun+masquerade tunnel echo mismatch")
	}
}
