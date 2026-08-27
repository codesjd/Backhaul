package network

import (
	"testing"
)

func TestRandomUserAgent(t *testing.T) {
	// Call RandomUserAgent multiple times to ensure it works and doesn't panic
	for i := 0; i < 100; i++ {
		ua := RandomUserAgent()
		found := false
		for _, v := range browserUserAgents {
			if ua == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("RandomUserAgent returned an unexpected value: %s", ua)
		}
	}
}
