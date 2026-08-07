package striping

import (
	"math"
	"sync"
	"time"
)

// congestionScheduler paces how many chunks may be in flight across all legs
// at once (cwnd), the same idea as TCP's AIMD congestion control but applied
// one level up, across the whole ensemble of legs.
//
// Why this exists: the per-leg work-stealing queue already lets a slow leg
// carry less than a fast one, but it still lets every leg push as hard as
// its own local OS send buffer allows, independently. When the legs don't
// actually have independent bottlenecks - they share one physical link, as
// pooled connections through one CDN edge do - that's N flows all
// independently racing to fill the *same* queue, which just means more
// contention and loss than a single well-behaved flow would cause, not more
// throughput. Capping and adapting the total in-flight count based on
// observed per-chunk latency lets the ensemble back off toward "behave like
// one flow" when the shared link is the bottleneck, while still using full
// per-leg parallelism when there's genuine spare capacity.
//
// This is a proxy for real congestion control, not a replacement for it -
// it has no notion of packet loss vs. reordering vs. scheduling jitter, only
// "did this chunk take longer to hand to the OS than usual". It exists to
// stop naive full-parallelism from actively making things worse on a shared
// bottleneck, not to out-perform a single flow's own TCP congestion control.
type congestionScheduler struct {
	mu   sync.Mutex
	cond *sync.Cond

	cwnd     float64
	minCwnd  float64
	maxCwnd  float64
	inFlight int

	minLatency  time.Duration
	ewmaLatency time.Duration
	samples     int

	stopped bool
}

const (
	schedulerAdjustInterval = 150 * time.Millisecond
	// congestionRatio: EWMA latency this far above the best-ever observed
	// latency is treated as a congestion signal.
	congestionRatio = 1.5
	// backoffFactor: multiplicative decrease applied to cwnd on congestion.
	backoffFactor = 0.7
)

func newCongestionScheduler(legCount int) *congestionScheduler {
	s := &congestionScheduler{
		cwnd:    float64(legCount),
		minCwnd: 1,
		maxCwnd: float64(legCount),
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// acquire blocks until a slot is available under the current window, then
// reserves it. Every acquire must be paired with exactly one release.
func (s *congestionScheduler) acquire(closed <-chan struct{}) bool {
	s.mu.Lock()
	for !s.stopped && float64(s.inFlight) >= s.cwnd {
		// sync.Cond has no channel-based wait, so nothing here can select
		// on closed directly; run/stop is instead observed via s.stopped,
		// flipped by stop() which also broadcasts to wake every waiter.
		s.cond.Wait()
	}
	if s.stopped {
		s.mu.Unlock()
		return false
	}
	s.inFlight++
	s.mu.Unlock()
	return true
}

// release returns the slot acquired by acquire and records how long the
// write it guarded took, which feeds the next window adjustment.
func (s *congestionScheduler) release(latency time.Duration) {
	s.mu.Lock()
	s.inFlight--
	if s.minLatency == 0 || latency < s.minLatency {
		s.minLatency = latency
	}
	if s.ewmaLatency == 0 {
		s.ewmaLatency = latency
	} else {
		// alpha = 0.2: react within a handful of samples without being
		// thrown off by a single slow chunk.
		s.ewmaLatency = time.Duration(0.8*float64(s.ewmaLatency) + 0.2*float64(latency))
	}
	s.samples++
	s.cond.Signal()
	s.mu.Unlock()
}

// stop wakes every blocked acquire so writeLeg goroutines can exit once the
// Conn is closing, instead of leaking on a permanently blocked Wait.
func (s *congestionScheduler) stop() {
	s.mu.Lock()
	s.stopped = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// run periodically adjusts cwnd based on recent latency samples. It exits
// when closed fires.
func (s *congestionScheduler) run(closed <-chan struct{}) {
	ticker := time.NewTicker(schedulerAdjustInterval)
	defer ticker.Stop()

	for {
		select {
		case <-closed:
			return
		case <-ticker.C:
			s.adjust()
		}
	}
}

func (s *congestionScheduler) adjust() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.samples == 0 || s.minLatency == 0 {
		return // nothing sent this interval, nothing to learn from
	}

	congested := s.ewmaLatency > s.minLatency+s.minLatency/2 // > 1.5x best-ever
	if congested {
		s.cwnd = math.Max(s.minCwnd, s.cwnd*backoffFactor)
	} else if s.cwnd < s.maxCwnd {
		s.cwnd++ // additive increase: probe for a bit more room
	}
	s.samples = 0
	s.cond.Broadcast()
}
