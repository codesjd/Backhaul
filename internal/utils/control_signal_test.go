package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// wsPair returns the two ends of a real WebSocket connection, so the handler is
// exercised against actual framing rather than a stand-in.
func wsPair(t *testing.T) (client, server *websocket.Conn) {
	t.Helper()

	upgrader := websocket.Upgrader{ReadBufferSize: 64 * 1024, WriteBufferSize: 64 * 1024}
	srvCh := make(chan *websocket.Conn, 1)

	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		srvCh <- c
	}))
	t.Cleanup(hs.Close)

	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(hs.URL, "http"), nil)
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

	if msgType != websocket.BinaryMessage {
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
