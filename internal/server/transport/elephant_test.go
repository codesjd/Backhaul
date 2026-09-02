package transport

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestElephantTracker(t *testing.T) {
	tracker := NewElephantTracker(1000) // 1000 bytes threshold

	assert.False(t, tracker.IsElephant("1.1.1.1:443"))

	// Record 500 bytes (below threshold)
	tracker.RecordBytes("1.1.1.1:443", 500)
	assert.False(t, tracker.IsElephant("1.1.1.1:443"))

	// Record another 600 bytes (above threshold)
	tracker.RecordBytes("1.1.1.1:443", 600)
	assert.True(t, tracker.IsElephant("1.1.1.1:443"))
}
