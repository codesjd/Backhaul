package transport

import (
	"sync"
)

type ElephantTracker struct {
	mu        sync.RWMutex
	elephants map[string]int64 // remoteAddr -> bytes
	threshold uint64
	maxItems  int
}

func NewElephantTracker(threshold uint64) *ElephantTracker {
	return &ElephantTracker{
		elephants: make(map[string]int64),
		threshold: threshold,
		maxItems:  10000, // Hard limit to avoid unbounded growth
	}
}

func (et *ElephantTracker) RecordBytes(remoteAddr string, bytes int64) {
	if et.threshold == 0 {
		return
	}
	et.mu.Lock()
	defer et.mu.Unlock()

	if len(et.elephants) >= et.maxItems {
		// Extremely simple eviction to prevent memory leak:
		// clear the map when it gets too large. It will relearn.
		et.elephants = make(map[string]int64)
	}

	et.elephants[remoteAddr] += bytes
}

func (et *ElephantTracker) IsElephant(remoteAddr string) bool {
	if et.threshold == 0 {
		return false
	}
	et.mu.RLock()
	defer et.mu.RUnlock()
	return uint64(et.elephants[remoteAddr]) > et.threshold
}
