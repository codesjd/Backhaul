package handlers

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/musix/backhaul/internal/web"
	"github.com/sirupsen/logrus"
)

type PumpSwapper struct {
	mu        sync.Mutex
	tunnel    net.Conn
	newTunnel net.Conn

	upLimit uint64
	dlLimit uint64

	swapped         bool
	sPhaseRemaining int32

	upBytes uint64
	dlBytes uint64
	done    chan struct{}
}

func (p *PumpSwapper) DoneWait() <-chan struct{} {
	return p.done
}

func (p *PumpSwapper) finishSPhase() {
	if atomic.AddInt32(&p.sPhaseRemaining, -1) == 0 {
		p.mu.Lock()
		if p.tunnel != nil {
			p.tunnel.Close()
			p.tunnel = nil
		}
		p.mu.Unlock()
	}
}

// PromotablePump replaces io.CopyBuffer with a custom loop for promotable flows.
func PromotablePump(
	ctx context.Context, proxyProtocol bool, app net.Conn, tunnel net.Conn,
	logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool,
) *PumpSwapper {

	if proxyProtocol {
		if err := WriteProxyProtocol(app, tunnel); err != nil {
			logger.Error(err)
			app.Close()
			tunnel.Close()
			return nil
		}
	}

	p := &PumpSwapper{
		tunnel:          tunnel,
		upLimit:         ^uint64(0),
		dlLimit:         ^uint64(0),
		done:            make(chan struct{}),
		sPhaseRemaining: 2,
	}

	go func() {
		select {
		case <-ctx.Done():
			app.Close()
			p.mu.Lock()
			if p.tunnel != nil {
				p.tunnel.Close()
			}
			if p.newTunnel != nil {
				p.newTunnel.Close()
			}
			p.mu.Unlock()
		case <-p.done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// App -> Tunnel (Upload direction relative to the plain tunnel's writes)
	go func() {
		defer wg.Done()
		p.pumpAppToTunnel(app, logger, usage, remotePort, sniffer)
	}()

	// Tunnel -> App (Download direction relative to the plain tunnel's reads)
	go func() {
		defer wg.Done()
		p.pumpTunnelToApp(app, logger, usage, remotePort, sniffer)
	}()

	go func() {
		wg.Wait()
		close(p.done)
		app.Close()
		p.mu.Lock()
		if p.tunnel != nil {
			p.tunnel.Close()
		}
		if p.newTunnel != nil {
			p.newTunnel.Close()
		}
		p.mu.Unlock()
	}()

	return p
}

func (p *PumpSwapper) UpBytes() uint64 {
	return atomic.LoadUint64(&p.upBytes)
}

func (p *PumpSwapper) DlBytes() uint64 {
	return atomic.LoadUint64(&p.dlBytes)
}

func (p *PumpSwapper) FreezeUp() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.upLimit = atomic.LoadUint64(&p.upBytes)
	return p.upLimit
}

func (p *PumpSwapper) Install(newTunnel net.Conn, dlLimit uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.newTunnel = newTunnel
	p.dlLimit = dlLimit
	p.swapped = true
}

func (p *PumpSwapper) pumpAppToTunnel(app net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer copyBufferPool.Put(bufPtr)

	var err error
	var total uint64
	var writingToNew bool

	for {
		p.mu.Lock()
		dest := p.tunnel
		limit := p.upLimit
		isSwapped := p.swapped
		if writingToNew {
			dest = p.newTunnel
		} else if isSwapped && total >= limit {
			// Ready to switch!
			p.finishSPhase()
			writingToNew = true
			dest = p.newTunnel
		} else if total >= limit {
			// Limit hit (FreezeUp called) but Install not yet called! Wait!
			p.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			continue
		}
		p.mu.Unlock()

		if dest == nil {
			break
		}

		var toRead int = len(buf)
		if limit < ^uint64(0) && !writingToNew {
			if limit > total {
				rem := int(limit - total)
				if rem < toRead {
					toRead = rem
				}
			} else {
				continue
			}
		}

		n, readErr := app.Read(buf[:toRead])
		if n > 0 {
			var writeErr error
			written := 0
			for written < n {
				w, wErr := dest.Write(buf[written:n])
				if w > 0 {
					written += w
					total += uint64(w)
					atomic.AddUint64(&p.upBytes, uint64(w))
				}
				if wErr != nil {
					writeErr = wErr
					break
				}
			}

			if sniffer {
				usage.AddOrUpdatePort(remotePort, uint64(n))
			}

			if writeErr != nil {
				err = writeErr
				break
			}
		}

		if readErr != nil {
			if limit < ^uint64(0) && total >= limit {
				err = nil
			} else {
				err = readErr
			}
			break
		}
	}

	if err != nil && !errors.Is(err, net.ErrClosed) && p.tunnel != nil {
		if aw, ok := p.tunnel.(interface{ AbortWrite() }); ok {
			aw.AbortWrite()
		}
	}
	closeWrite(app)
	if p.newTunnel != nil {
		closeWrite(p.newTunnel)
	}
}

func (p *PumpSwapper) pumpTunnelToApp(app net.Conn, logger *logrus.Logger, usage *web.Usage, remotePort int, sniffer bool) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer copyBufferPool.Put(bufPtr)

	var err error
	var total uint64
	var readingFromNew bool

	for {
		p.mu.Lock()
		src := p.tunnel
		limit := p.dlLimit
		isSwapped := p.swapped
		if readingFromNew {
			src = p.newTunnel
		} else if isSwapped && total >= limit {
			// Ready to switch!
			p.finishSPhase()
			readingFromNew = true
			src = p.newTunnel
		} else if total >= limit {
			p.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			continue
		}
		p.mu.Unlock()

		if src == nil {
			break
		}

		var toRead int = len(buf)
		if isSwapped && !readingFromNew {
			if limit > total {
				rem := int(limit - total)
				if rem < toRead {
					toRead = rem
				}
			} else {
				continue
			}
		}

		n, readErr := src.Read(buf[:toRead])
		if n > 0 {
			written := 0
			var writeErr error
			for written < n {
				w, wErr := app.Write(buf[written:n])
				if w > 0 {
					written += w
					total += uint64(w)
					if !readingFromNew {
						atomic.AddUint64(&p.dlBytes, uint64(w))
					}
				}
				if wErr != nil {
					writeErr = wErr
					break
				}
			}

			if sniffer {
				usage.AddOrUpdatePort(remotePort, uint64(n))
			}

			if writeErr != nil {
				err = writeErr
				break
			}
		}

		if readErr != nil {
			if isSwapped && total >= limit {
				err = nil
			} else {
				err = readErr
			}
			break
		}

		if !readingFromNew && isSwapped && total >= limit && n == 0 {
			continue
		}
	}

	if err != nil && !errors.Is(err, net.ErrClosed) && app != nil {
		if aw, ok := app.(interface{ AbortWrite() }); ok {
			aw.AbortWrite()
		}
	} else if app != nil {
		closeWrite(app)
	}
}
