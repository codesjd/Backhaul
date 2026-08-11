// Package congestion implements a Brutal-style congestion controller for the
// QUIC transport, ported to the exported congestion hook of the
// github.com/sagernet/quic-go fork.
//
// Brutal is what makes Hysteria2 fast on lossy, censored links: instead of
// backing off when it sees packet loss (the way Reno/Cubic/BBR do), it paces the
// sender at a fixed target bandwidth and, as loss rises, sends *proportionally
// harder* so goodput stays near the target. It trades fairness and loss-response
// for throughput on links where loss is induced (by a censor) rather than by
// genuine congestion - exactly the environment this tunnel is built for. It is
// therefore opt-in: enabled only when a target bandwidth (quic_up_mbps) is set.
//
// This is a faithful port of sing-quic's BrutalSender to this fork's exported
// congestion.CongestionControlEx interface (which uses monotime.Time); the pacer
// mirrors quic-go's own leaky-bucket pacer using only exported types.
package congestion

import (
	"math"
	"time"

	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

const (
	pktInfoSlotCount    = 5 // one slot per second sampled
	minSampleCount      = 50
	minAckRate          = 0.8
	cwndMultiplier      = 2
	initMaxDatagramSize = congestion.ByteCount(1252)
)

var _ congestion.CongestionControlEx = (*BrutalSender)(nil)

// BrutalSender paces the sender at a fixed target bandwidth, compensating for
// observed loss so goodput holds near the target.
type BrutalSender struct {
	rttStats        congestion.RTTStatsProvider
	bps             congestion.ByteCount // target bandwidth, bytes/sec
	maxDatagramSize congestion.ByteCount
	pacer           *pacer

	pktInfoSlots [pktInfoSlotCount]pktInfo
	ackRate      float64
}

type pktInfo struct {
	Timestamp int64
	AckCount  uint64
	LossCount uint64
}

// NewBrutalSender builds a Brutal controller targeting bps bytes/second.
func NewBrutalSender(bps uint64) *BrutalSender {
	b := &BrutalSender{
		bps:             congestion.ByteCount(bps),
		maxDatagramSize: initMaxDatagramSize,
		ackRate:         1,
	}
	b.pacer = newPacer(func() uint64 {
		return uint64(float64(b.bps) / b.ackRate)
	})
	return b
}

func (b *BrutalSender) SetRTTStatsProvider(rttStats congestion.RTTStatsProvider) {
	b.rttStats = rttStats
}

func (b *BrutalSender) TimeUntilSend(bytesInFlight congestion.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *BrutalSender) HasPacingBudget(now monotime.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *BrutalSender) CanSend(bytesInFlight congestion.ByteCount) bool {
	return bytesInFlight < b.GetCongestionWindow()
}

func (b *BrutalSender) GetCongestionWindow() congestion.ByteCount {
	rtt := time.Duration(0)
	if b.rttStats != nil {
		rtt = b.rttStats.SmoothedRTT()
	}
	if rtt <= 0 {
		return 10240
	}
	return congestion.ByteCount(float64(b.bps) * rtt.Seconds() * cwndMultiplier / b.ackRate)
}

func (b *BrutalSender) OnPacketSent(sentTime monotime.Time, bytesInFlight congestion.ByteCount,
	packetNumber congestion.PacketNumber, bytes congestion.ByteCount, isRetransmittable bool,
) {
	b.pacer.SentPacket(sentTime, bytes)
}

func (b *BrutalSender) OnPacketAcked(number congestion.PacketNumber, ackedBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount, eventTime monotime.Time,
) {
}

func (b *BrutalSender) OnCongestionEvent(number congestion.PacketNumber, lostBytes congestion.ByteCount,
	priorInFlight congestion.ByteCount,
) {
}

// OnCongestionEventEx samples the per-second ack/loss counts that drive the loss
// compensation. Called by the fork's sent-packet handler in batches.
func (b *BrutalSender) OnCongestionEventEx(priorInFlight congestion.ByteCount, eventTime monotime.Time,
	ackedPackets []congestion.AckedPacketInfo, lostPackets []congestion.LostPacketInfo,
) {
	currentTimestamp := eventTime.ToTime().Unix()
	slot := currentTimestamp % pktInfoSlotCount
	if b.pktInfoSlots[slot].Timestamp == currentTimestamp {
		b.pktInfoSlots[slot].LossCount += uint64(len(lostPackets))
		b.pktInfoSlots[slot].AckCount += uint64(len(ackedPackets))
	} else {
		b.pktInfoSlots[slot].Timestamp = currentTimestamp
		b.pktInfoSlots[slot].AckCount = uint64(len(ackedPackets))
		b.pktInfoSlots[slot].LossCount = uint64(len(lostPackets))
	}
	b.updateAckRate(currentTimestamp)
}

func (b *BrutalSender) OnPacketsLost(leastUnacked congestion.PacketNumber) {}
func (b *BrutalSender) OnAppLimited(bytesInFlight congestion.ByteCount)    {}

func (b *BrutalSender) SetMaxDatagramSize(size congestion.ByteCount) {
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
}

func (b *BrutalSender) updateAckRate(currentTimestamp int64) {
	minTimestamp := currentTimestamp - pktInfoSlotCount
	var ackCount, lossCount uint64
	for _, info := range b.pktInfoSlots {
		if info.Timestamp < minTimestamp {
			continue
		}
		ackCount += info.AckCount
		lossCount += info.LossCount
	}
	if ackCount+lossCount < minSampleCount {
		b.ackRate = 1
		return
	}
	rate := float64(ackCount) / float64(ackCount+lossCount)
	if rate < minAckRate {
		b.ackRate = minAckRate
		return
	}
	b.ackRate = rate
}

func (b *BrutalSender) InSlowStart() bool                    { return false }
func (b *BrutalSender) InRecovery() bool                     { return false }
func (b *BrutalSender) MaybeExitSlowStart()                  {}
func (b *BrutalSender) OnRetransmissionTimeout(retrans bool) {}

// -------- leaky-bucket pacer (exported-types port of quic-go's) --------

const (
	maxBurstSizePackets = 10
	timerGranularity    = time.Millisecond
)

const maxByteCount = congestion.ByteCount(math.MaxInt64)

type pacer struct {
	budgetAtLastSent congestion.ByteCount
	maxDatagramSize  congestion.ByteCount
	lastSentTime     monotime.Time
	getBandwidth     func() uint64 // bytes/sec, already loss-compensated
}

func newPacer(getBandwidth func() uint64) *pacer {
	p := &pacer{maxDatagramSize: initMaxDatagramSize, getBandwidth: getBandwidth}
	p.budgetAtLastSent = p.maxBurstSize()
	return p
}

// adjustedBandwidth adds quic-go's 25% pacing headroom over the target rate.
func (p *pacer) adjustedBandwidth() uint64 { return p.getBandwidth() * 5 / 4 }

func (p *pacer) SentPacket(sendTime monotime.Time, size congestion.ByteCount) {
	budget := p.Budget(sendTime)
	if size >= budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

func (p *pacer) Budget(now monotime.Time) congestion.ByteCount {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}
	var added congestion.ByteCount
	if delta := now.Sub(p.lastSentTime); delta > 0 {
		added = p.timeScaledBandwidth(uint64(delta.Nanoseconds()))
	}
	budget := p.budgetAtLastSent + added
	if added > 0 && budget < p.budgetAtLastSent { // overflow
		budget = maxByteCount
	}
	if mb := p.maxBurstSize(); budget > mb {
		return mb
	}
	return budget
}

func (p *pacer) maxBurstSize() congestion.ByteCount {
	a := p.timeScaledBandwidth(uint64((congestion.MinPacingDelay + timerGranularity).Nanoseconds()))
	b := congestion.ByteCount(maxBurstSizePackets) * p.maxDatagramSize
	if a > b {
		return a
	}
	return b
}

func (p *pacer) timeScaledBandwidth(ns uint64) congestion.ByteCount {
	bw := p.adjustedBandwidth()
	if bw == 0 {
		return 0
	}
	if ns > math.MaxUint64/bw {
		return congestion.ByteCount(maxBurstSizePackets) * p.maxDatagramSize
	}
	return congestion.ByteCount(bw * ns / 1e9)
}

func (p *pacer) TimeUntilSend() monotime.Time {
	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}
	bw := p.adjustedBandwidth()
	if bw == 0 {
		return 0
	}
	diff := 1e9 * uint64(p.maxDatagramSize-p.budgetAtLastSent)
	d := diff / bw
	if diff%bw > 0 {
		d++
	}
	dur := time.Duration(d) * time.Nanosecond
	if dur < congestion.MinPacingDelay {
		dur = congestion.MinPacingDelay
	}
	return p.lastSentTime.Add(dur)
}

func (p *pacer) SetMaxDatagramSize(s congestion.ByteCount) { p.maxDatagramSize = s }
