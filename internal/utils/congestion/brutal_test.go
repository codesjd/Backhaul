package congestion

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

// fakeRTT is a minimal RTTStatsProvider returning a fixed smoothed RTT.
type fakeRTT struct{ rtt time.Duration }

func (f fakeRTT) MinRTT() time.Duration        { return f.rtt }
func (f fakeRTT) LatestRTT() time.Duration     { return f.rtt }
func (f fakeRTT) SmoothedRTT() time.Duration   { return f.rtt }
func (f fakeRTT) MeanDeviation() time.Duration { return 0 }
func (f fakeRTT) MaxAckDelay() time.Duration   { return 0 }
func (f fakeRTT) PTO(bool) time.Duration       { return f.rtt }
func (f fakeRTT) UpdateRTT(_, _ time.Duration) {}
func (f fakeRTT) SetMaxAckDelay(time.Duration) {}
func (f fakeRTT) SetInitialRTT(time.Duration)  {}

func TestBrutalImplementsInterface(t *testing.T) {
	var _ congestion.CongestionControlEx = NewBrutalSender(1000)
}

// TestBrutalCongestionWindowScalesWithBandwidth checks the window grows with the
// target bandwidth and the RTT (window ~= bps * rtt * multiplier).
func TestBrutalCongestionWindowScalesWithBandwidth(t *testing.T) {
	const bps = 12_500_000 // 100 Mbps in bytes/sec
	b := NewBrutalSender(bps)
	b.SetRTTStatsProvider(fakeRTT{rtt: 100 * time.Millisecond})

	cwnd := b.GetCongestionWindow()
	// Expected ~ bps * 0.1s * 2 = 2.5 MB.
	want := congestion.ByteCount(float64(bps) * 0.1 * cwndMultiplier)
	if cwnd < want*9/10 || cwnd > want*11/10 {
		t.Fatalf("cwnd %d not within 10%% of expected %d", cwnd, want)
	}

	// A higher bandwidth must produce a proportionally larger window.
	b2 := NewBrutalSender(bps * 4)
	b2.SetRTTStatsProvider(fakeRTT{rtt: 100 * time.Millisecond})
	if b2.GetCongestionWindow() <= cwnd {
		t.Fatal("higher bandwidth did not increase the congestion window")
	}
}

// TestBrutalLossCompensation checks that as observed loss rises, the effective
// send rate rises (ackRate falls) so goodput holds near the target - the core of
// Brutal - and that the ack rate is clamped so it can't blow up unboundedly.
func TestBrutalLossCompensation(t *testing.T) {
	b := NewBrutalSender(1_000_000)
	b.SetRTTStatsProvider(fakeRTT{rtt: 50 * time.Millisecond})

	now := monotime.Now()
	// Feed a second's worth of samples with ~20% loss (above the 0.8 floor).
	acked := make([]congestion.AckedPacketInfo, 80)
	lost := make([]congestion.LostPacketInfo, 20)
	b.OnCongestionEventEx(0, now, acked, lost)
	if b.ackRate > 0.81 || b.ackRate < 0.79 {
		t.Fatalf("ackRate %.3f; expected ~0.80 for 20%% loss", b.ackRate)
	}

	// Extreme loss must clamp at minAckRate, not go lower (bounds the send-rate
	// multiplier at 1/0.8).
	b2 := NewBrutalSender(1_000_000)
	b2.SetRTTStatsProvider(fakeRTT{rtt: 50 * time.Millisecond})
	acked2 := make([]congestion.AckedPacketInfo, 10)
	lost2 := make([]congestion.LostPacketInfo, 90)
	b2.OnCongestionEventEx(0, monotime.Now(), acked2, lost2)
	if b2.ackRate < minAckRate-1e-9 {
		t.Fatalf("ackRate %.3f dropped below the clamp %.3f", b2.ackRate, minAckRate)
	}
}

// TestBrutalPacerProducesBudget checks the pacer hands out a send budget over
// time rather than stalling.
func TestBrutalPacerProducesBudget(t *testing.T) {
	b := NewBrutalSender(10_000_000)
	// With no packets sent yet, there is an initial burst budget.
	if !b.HasPacingBudget(monotime.Now()) {
		t.Fatal("expected initial pacing budget")
	}
}
