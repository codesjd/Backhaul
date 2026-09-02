package transport

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestWsMuxPlainFramingE2E(t *testing.T) {
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

	assert.False(t, server.shouldStripe(localConn))
}
