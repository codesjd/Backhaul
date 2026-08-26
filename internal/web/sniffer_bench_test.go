package web

import (
	"context"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
)

func BenchmarkHandleData(b *testing.B) {
	// Create a dummy sniffer log file
	tmpfile, err := os.CreateTemp("", "sniffer_log*.json")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	tmpfile.Write([]byte(`[{"Port":80,"Usage":1024},{"Port":443,"Usage":2048}]`))
	tmpfile.Close()

	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.ErrorLevel)

	dummyStatus := "active"
	u := NewDataStore("127.0.0.1:0", context.Background(), tmpfile.Name(), true, &dummyStatus, logger)

	req := httptest.NewRequest("GET", "/data", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		u.handleData(rr, req)
	}
}
