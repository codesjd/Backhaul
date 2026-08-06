// Package striping lets a single logical byte stream be split across several
// underlying net.Conn legs instead of pinned to one. A single TCP-based leg
// (one pooled tunnel connection) caps a flow's throughput at roughly
// window/RTT; spreading one flow's bytes round-robin across N legs gives it
// N independent congestion windows instead of one.
//
// This is a prototype: if a leg dies mid-transfer, any sequence numbers that
// were assigned to it are gone for good and Read blocks forever waiting for
// them. There is no retransmission or leg-failure recovery. It is meant for
// links where all legs are healthy for the life of the connection, not as a
// general-purpose reliability layer.
package striping

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// DefaultChunkSize is the payload size each write is sliced into before
// being round-robined across legs. Small enough that legs interleave
// frequently (so one slow leg doesn't hold up a large share of the data),
// large enough that the 8-byte per-chunk header is negligible overhead.
const DefaultChunkSize = 16 * 1024

const headerSize = 8 // 4 bytes sequence number + 4 bytes payload length

type chunk struct {
	seq  uint32
	data []byte
}

// Conn stripes Read/Write over multiple legs. It implements net.Conn so it
// is a drop-in replacement anywhere a single stream/connection was used.
type Conn struct {
	legs      []net.Conn
	chunkSize int

	wmu      sync.Mutex
	writeSeq uint32
	writeIdx int

	rmu     sync.Mutex
	nextSeq uint32
	pending map[uint32]chunk
	readBuf []byte
	readErr error

	chunkCh chan chunk
	errCh   chan error

	closeOnce sync.Once
	closed    chan struct{}
}

// New wraps legs (already-connected, already correlated to the same logical
// flow on both ends) into a single striped net.Conn.
func New(legs []net.Conn, chunkSize int) *Conn {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	c := &Conn{
		legs:      legs,
		chunkSize: chunkSize,
		pending:   make(map[uint32]chunk),
		chunkCh:   make(chan chunk, len(legs)*4),
		errCh:     make(chan error, len(legs)),
		closed:    make(chan struct{}),
	}
	for _, leg := range legs {
		go c.readLeg(leg)
	}
	return c
}

func (c *Conn) readLeg(leg net.Conn) {
	header := make([]byte, headerSize)
	for {
		if _, err := io.ReadFull(leg, header); err != nil {
			c.reportErr(err)
			return
		}
		seq := binary.BigEndian.Uint32(header[0:4])
		length := binary.BigEndian.Uint32(header[4:8])

		data := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(leg, data); err != nil {
				c.reportErr(err)
				return
			}
		}

		select {
		case c.chunkCh <- chunk{seq: seq, data: data}:
		case <-c.closed:
			return
		}
	}
}

func (c *Conn) reportErr(err error) {
	select {
	case c.errCh <- err:
	case <-c.closed:
	}
}

// Write splits p into DefaultChunkSize pieces, each tagged with a global
// sequence number, and round-robins them across the legs.
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > c.chunkSize {
			n = c.chunkSize
		}
		part := p[:n]
		p = p[n:]

		leg := c.legs[c.writeIdx%len(c.legs)]
		c.writeIdx++

		header := make([]byte, headerSize)
		binary.BigEndian.PutUint32(header[0:4], c.writeSeq)
		binary.BigEndian.PutUint32(header[4:8], uint32(n))
		c.writeSeq++

		if _, err := leg.Write(header); err != nil {
			return total, err
		}
		if _, err := leg.Write(part); err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// Read reassembles chunks arriving out of order across legs into the
// original in-order byte stream.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	for len(c.readBuf) == 0 {
		if ch, ok := c.pending[c.nextSeq]; ok {
			delete(c.pending, c.nextSeq)
			c.readBuf = ch.data
			c.nextSeq++
			continue
		}

		select {
		case ch := <-c.chunkCh:
			if ch.seq == c.nextSeq {
				c.readBuf = ch.data
				c.nextSeq++
			} else {
				c.pending[ch.seq] = ch
			}
		case err := <-c.errCh:
			if c.readErr == nil {
				c.readErr = err
			}
			// A leg failing doesn't necessarily mean the chunk we're
			// waiting on is lost - drain whatever is already queued
			// before giving up.
			select {
			case ch := <-c.chunkCh:
				if ch.seq == c.nextSeq {
					c.readBuf = ch.data
					c.nextSeq++
				} else {
					c.pending[ch.seq] = ch
				}
			default:
				return 0, c.readErr
			}
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		for _, leg := range c.legs {
			if e := leg.Close(); e != nil {
				err = e
			}
		}
	})
	return err
}

func (c *Conn) LocalAddr() net.Addr  { return c.legs[0].LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.legs[0].RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	return c.forEachLeg(func(l net.Conn) error { return l.SetDeadline(t) })
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.forEachLeg(func(l net.Conn) error { return l.SetReadDeadline(t) })
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.forEachLeg(func(l net.Conn) error { return l.SetWriteDeadline(t) })
}

func (c *Conn) forEachLeg(f func(net.Conn) error) error {
	var firstErr error
	for _, leg := range c.legs {
		if e := f(leg); e != nil && firstErr == nil {
			firstErr = fmt.Errorf("leg error: %w", e)
		}
	}
	return firstErr
}
