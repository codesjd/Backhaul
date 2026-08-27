package utils

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// mockErrorConn is a mock net.Conn that returns an error on Read.
type mockErrorConn struct{}

func (m *mockErrorConn) Read(b []byte) (n int, err error) {
	return 0, errors.New("mock read error")
}
func (m *mockErrorConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}
func (m *mockErrorConn) Close() error {
	return nil
}
func (m *mockErrorConn) LocalAddr() net.Addr {
	return nil
}
func (m *mockErrorConn) RemoteAddr() net.Addr {
	return nil
}
func (m *mockErrorConn) SetDeadline(t time.Time) error {
	return nil
}
func (m *mockErrorConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (m *mockErrorConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestReceiveBinaryByte_ErrorPath(t *testing.T) {
	conn := &mockErrorConn{}
	b, err := ReceiveBinaryByte(conn)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock read error")
	assert.Equal(t, byte(0), b)
}
