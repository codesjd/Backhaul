package utils

import (
	"math/rand"
	"time"

	"github.com/gorilla/websocket"
)

// maxControlPadding bounds the random padding appended to control-channel
// frames (heartbeat/chan/closed signals). Without it every control frame is
// exactly 1 byte, which under TLS still shows up as a fixed-size message at
// a fixed interval - an easy statistical fingerprint for DPI.
const maxControlPadding = 64

// heartbeatJitterFraction is how far a heartbeat interval may drift from its
// configured value (+/- this fraction), so the control channel doesn't beat
// with perfectly periodic timing.
const heartbeatJitterFraction = 0.3

// WriteControlSignal writes a single control byte to conn, padded with a
// random amount of random bytes so control frames don't all share the same
// on-wire size. Readers only ever look at the first byte of a control
// message, so the padding is transparent to them.
func WriteControlSignal(conn *websocket.Conn, signal byte) error {
	padLen := rand.Intn(maxControlPadding + 1)
	buf := make([]byte, 1+padLen)
	buf[0] = signal
	if padLen > 0 {
		rand.Read(buf[1:])
	}
	return conn.WriteMessage(websocket.BinaryMessage, buf)
}

// JitterDuration returns base randomly shifted by up to
// +/- heartbeatJitterFraction, so repeated intervals (e.g. heartbeats) don't
// form a perfectly periodic pattern. Falls back to base for non-positive
// durations.
func JitterDuration(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	spread := float64(base) * heartbeatJitterFraction
	offset := (rand.Float64()*2 - 1) * spread // in [-spread, +spread]
	return base + time.Duration(offset)
}
