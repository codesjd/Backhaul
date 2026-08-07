// Package striping lets a single logical byte stream be split across several
// underlying net.Conn legs instead of pinned to one. A single TCP-based leg
// (one pooled tunnel connection) caps a flow's throughput at roughly
// window/RTT; spreading one flow's bytes across N legs gives it N
// independent congestion windows instead of one - but only if the legs are
// actually kept busy in proportion to how fast each one drains, and only if
// a leg that stops responding gets detected and torn down instead of
// hanging the whole connection forever.
//
// Three things are handled here:
//   - Writes are handed to whichever leg is free next (a work-stealing
//     queue), not round-robined blindly - a congested leg naturally gets
//     fewer chunks instead of stalling the reorder buffer on the receiving
//     end waiting for its share.
//   - A congestionScheduler (scheduler.go) paces how many legs may be
//     sending at once, backing off when per-chunk latency rises. Legs
//     pooled through one CDN connection usually don't have independent
//     capacity - they share one real bottleneck - and blindly driving all
//     of them at once just adds contention/loss on that shared link
//     instead of throughput. This lets the ensemble behave like fewer,
//     better-behaved flows when that's what the link actually calls for,
//     while still using full parallelism when there's genuine headroom.
//   - Every leg write carries a deadline, and Read gives up waiting for a
//     missing sequence number after stallTimeout. Either one closes the
//     whole Conn (all legs), which unblocks the other direction's I/O too,
//     instead of leaking goroutines and streams on a silently dead leg.
//
// This still isn't real reliability: a lost/timed-out leg's in-flight byte
// range can't be recovered, so the stream ends in an error like a dropped
// TCP connection would - there's no retransmission. What changed is that it
// now *does* end, promptly, instead of hanging.
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
// being handed to a leg. Small enough that legs interleave frequently (so
// one slow leg doesn't hold up a large share of the data), large enough
// that the 8-byte per-chunk header is negligible overhead.
const DefaultChunkSize = 16 * 1024

// defaultStallTimeout bounds how long a leg write or a Read waiting on a
// missing sequence number can block before the whole Conn is torn down.
const defaultStallTimeout = 20 * time.Second

const headerSize = 8 // 4 bytes sequence number + 4 bytes payload length

type chunk struct {
	seq  uint32
	data []byte
}

type writeJob struct {
	seq  uint32
	data []byte
}

// Conn stripes Read/Write over multiple legs. It implements net.Conn so it
// is a drop-in replacement anywhere a single stream/connection was used.
type Conn struct {
	legs         []net.Conn
	chunkSize    int
	stallTimeout time.Duration

	wmu        sync.Mutex // guards writeSeq only; queueing itself is lock-free via the channel
	writeSeq   uint32
	writeQueue chan writeJob
	sched      *congestionScheduler

	// rmu guards only the reassembly state below (nextSeq/pending/readBuf)
	// and is held for as long as Read blocks waiting on the network. permErr
	// deliberately has its own lock: Read and Write must be able to proceed
	// concurrently the way any net.Conn allows, and sharing rmu with Write
	// (even just to peek at permErr) deadlocks a bidirectional flow - one
	// side's Read blocks on rmu waiting for data, which is exactly the lock
	// the other side's Write needs to even start sending it.
	rmu     sync.Mutex
	nextSeq uint32
	pending map[uint32]chunk
	readBuf []byte

	errMu   sync.Mutex
	permErr error // sticky once set: every Read/Write after this returns it

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
		legs:         legs,
		chunkSize:    chunkSize,
		stallTimeout: defaultStallTimeout,
		pending:      make(map[uint32]chunk),
		chunkCh:      make(chan chunk, len(legs)*4),
		errCh:        make(chan error, len(legs)),
		writeQueue:   make(chan writeJob, len(legs)*2),
		sched:        newCongestionScheduler(len(legs)),
		closed:       make(chan struct{}),
	}
	go c.sched.run(c.closed)
	for _, leg := range legs {
		go c.readLeg(leg)
		go c.writeLeg(leg)
	}
	return c
}

func (c *Conn) readLeg(leg net.Conn) {
	header := make([]byte, headerSize)
	for {
		if _, err := io.ReadFull(leg, header); err != nil {
			c.fail(err)
			return
		}
		seq := binary.BigEndian.Uint32(header[0:4])
		length := binary.BigEndian.Uint32(header[4:8])

		data := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(leg, data); err != nil {
				c.fail(err)
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

// writeLeg is a worker that pulls the next queued chunk - whichever one is
// available first - and sends it on this leg. A leg that's draining fast
// comes back for more sooner, so faster/less congested legs naturally end
// up carrying more of the flow instead of every leg getting a fixed,
// round-robined share regardless of how quickly it can move it.
//
// Before actually sending, it waits for a slot from sched: on a link where
// the legs are truly independent, cwnd stays maxed out and this never
// blocks meaningfully. On a shared bottleneck, sched throttles how many
// legs are allowed to be pushing at once, based on observed latency,
// instead of letting all of them race the same queue unthrottled.
func (c *Conn) writeLeg(leg net.Conn) {
	header := make([]byte, headerSize)
	for {
		var job writeJob
		select {
		case job = <-c.writeQueue:
		case <-c.closed:
			return
		}

		if !c.sched.acquire(c.closed) {
			return // Conn is closing
		}

		start := time.Now()
		if err := leg.SetWriteDeadline(time.Now().Add(c.stallTimeout)); err != nil {
			c.sched.release(c.stallTimeout)
			c.fail(err)
			return
		}

		binary.BigEndian.PutUint32(header[0:4], job.seq)
		binary.BigEndian.PutUint32(header[4:8], uint32(len(job.data)))

		if _, err := leg.Write(header); err != nil {
			c.sched.release(time.Since(start))
			c.fail(err)
			return
		}
		if len(job.data) > 0 {
			if _, err := leg.Write(job.data); err != nil {
				c.sched.release(time.Since(start))
				c.fail(err)
				return
			}
		}
		c.sched.release(time.Since(start))
	}
}

// fail records the first error seen (from either direction) and tears the
// whole striped connection down. Without this, one leg going quietly dead
// (no error, just never progressing) would leave Read blocked forever and
// the streams/goroutines behind the other legs never released.
//
// permErr is set here directly rather than only inside Read's error
// handling: a write-side failure (a leg's write deadline expiring) has to
// be visible to the *next* Write call even if nothing ever calls Read on
// this Conn to drain errCh.
func (c *Conn) fail(err error) {
	c.setPermErr(err)
	select {
	case c.errCh <- err:
	default:
	}
	c.Close()
}

// setPermErr records the first permanent error seen, from either Read or
// Write's side of the connection.
func (c *Conn) setPermErr(err error) {
	c.errMu.Lock()
	if c.permErr == nil {
		c.permErr = err
	}
	c.errMu.Unlock()
}

func (c *Conn) getPermErr() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.permErr
}

// Write slices p into chunkSize pieces, each tagged with a global sequence
// number, and queues them for whichever leg picks them up first.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.getPermErr(); err != nil {
		return 0, err
	}

	c.wmu.Lock()
	defer c.wmu.Unlock()

	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > c.chunkSize {
			n = c.chunkSize
		}
		data := make([]byte, n)
		copy(data, p[:n])
		p = p[n:]

		seq := c.writeSeq
		c.writeSeq++

		select {
		case c.writeQueue <- writeJob{seq: seq, data: data}:
			total += n
		case <-c.closed:
			return total, c.currentErr()
		}
	}
	return total, nil
}

// Read reassembles chunks arriving out of order across legs into the
// original in-order byte stream. It gives up - and tears the whole Conn
// down - if the next sequence number in line doesn't show up within
// stallTimeout, rather than blocking forever on a leg that's gone silent
// without actually erroring.
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if len(c.readBuf) == 0 {
		if err := c.getPermErr(); err != nil {
			return 0, err
		}
	}

	for len(c.readBuf) == 0 {
		if ch, ok := c.pending[c.nextSeq]; ok {
			delete(c.pending, c.nextSeq)
			c.readBuf = ch.data
			c.nextSeq++
			continue
		}

		timer := time.NewTimer(c.stallTimeout)
		select {
		case ch := <-c.chunkCh:
			timer.Stop()
			if ch.seq == c.nextSeq {
				c.readBuf = ch.data
				c.nextSeq++
			} else {
				c.pending[ch.seq] = ch
			}

		case err := <-c.errCh:
			timer.Stop()
			c.setPermErr(err)
			// A leg erroring doesn't necessarily mean the chunk we're
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
				if len(c.readBuf) == 0 {
					return 0, c.getPermErr()
				}
			}

		case <-timer.C:
			stallErr := fmt.Errorf("striping: stalled waiting for sequence %d for %s", c.nextSeq, c.stallTimeout)
			c.setPermErr(stallErr)
			c.Close()
			return 0, stallErr
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// currentErr returns the first recorded leg error, or a generic closed
// error if the Conn was closed locally (e.g. via Close()) without one.
func (c *Conn) currentErr() error {
	select {
	case err := <-c.errCh:
		return err
	default:
		return net.ErrClosed
	}
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closed)
		c.sched.stop()
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
