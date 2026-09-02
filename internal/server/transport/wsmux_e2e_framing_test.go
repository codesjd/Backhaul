package transport

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestWsMuxPlainFramingE2E(t *testing.T) {
	// A simple test ensuring that the new framing works for plain flows.
	// We'll set MuxVersion = 2 and ensure shouldStripe is false.
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	conf := &WsMuxConfig{
		StripeFactor: 1, // Start as plain
		MuxVersion:   2,
		ChannelSize:  100,
		MuxCon:       10,
	}

	server := NewWSMuxServer(context.Background(), conf, logger)

	localConn := LocalTCPConn{
		remoteAddr:  "127.0.0.1:8080",
		timeCreated: time.Now().UnixMilli(),
	}

	// Should not be striped initially
	assert.False(t, server.shouldStripe(localConn))
}
