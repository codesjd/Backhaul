package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
)

func BenchmarkStatsHandler(b *testing.B) {
	// Create a dummy Usage instance
	logger := logrus.New()
	tunnelStatus := "running"
	u := NewDataStore(":8080", context.Background(), "sniffer.log", false, &tunnelStatus, logger)

	req, err := http.NewRequest("GET", "/stats", nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		u.statsHandler(rr, req)
	}
}
