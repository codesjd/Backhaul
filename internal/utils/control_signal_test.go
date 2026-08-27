package utils

import (
	"context"
	"github.com/gobwas/ws"
	"github.com/musix/backhaul/internal/utils/network"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// wsPair returns the two ends of a real WebSocket connection, so the handler is
// exercised against actual framing rather than a stand-in.
func wsPair(t *testing.T) (client, server *network.WebSocketConn) {
	t.Helper()

	srvCh := make(chan *network.WebSocketConn, 1)

	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		srvCh <- network.NewWebSocketConn(c, ws.StateServerSide, nil)
	}))
	t.Cleanup(hs.Close)

	conn, br, _, err := ws.Dial(context.Background(), "ws"+strings.TrimPrefix(hs.URL, "http"))
	c := network.NewWebSocketConn(conn, ws.StateClientSide, br)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	select {
	case s := <-srvCh:
		t.Cleanup(func() { s.Close() })
		return c, s
	case <-time.After(10 * time.Second):
		t.Fatal("websocket upgrade never completed")
		return nil, nil
	}
}

func TestWriteControlSignal(t *testing.T) {
	wsClient, wsServer := wsPair(t)

	// Happy path: We'll write to wsClient and read from wsServer
	var signal byte = 0x42

	err := WriteControlSignal(wsClient, signal)
	if err != nil {
		t.Fatalf("WriteControlSignal failed: %v", err)
	}

	msgType, p, err := wsServer.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if msgType != network.BinaryMessage {
		t.Errorf("expected binary message, got type %d", msgType)
	}

	if len(p) < 1 {
		t.Fatal("received empty message")
	}

	if p[0] != signal {
		t.Errorf("expected signal %v, got %v", signal, p[0])
	}

	// Error path: attempting to write to a closed connection
	wsClient.Close()
	err = WriteControlSignal(wsClient, signal)
	if err == nil {
		t.Fatalf("expected error when writing to closed connection, got nil")
	}
}
