package transport

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestElephantTrackerE2E(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	conf := &WsMuxConfig{
		PromoteBytes: 1000,
		StripeFactor: 1, // Start as plain
		MuxVersion:   2,
		ChannelSize:  100,
		MuxCon:       10,
	}

	server := NewWSMuxServer(context.Background(), conf, logger)
	assert.NotNil(t, server.elephantTracker)

	localConn := LocalTCPConn{
		remoteAddr:  "127.0.0.1:8080",
		timeCreated: time.Now().UnixMilli(),
	}

	// Should not be striped initially
	assert.False(t, server.shouldStripe(localConn))

	// Record bytes directly (simulating what TCPConnectionHandler does)
	server.elephantTracker.RecordBytes("127.0.0.1:8080", 2000)

	// Now it should be striped
	assert.True(t, server.shouldStripe(localConn))
}
