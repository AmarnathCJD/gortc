// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package groupcall

import (
	"sync"
	"sync/atomic"

	"github.com/amarnathcjd/gortc/webrtc/rtcp"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

type BandwidthEstimate struct {
	BitrateBps   uint64
	FractionLost uint8
	TotalLost    uint32
	Jitter       uint32
}

type bweTracker struct {
	mu     sync.Mutex
	latest BandwidthEstimate
	stop   chan struct{}
	on     atomic.Pointer[func(BandwidthEstimate)]
}

func newBWETracker() *bweTracker {
	return &bweTracker{stop: make(chan struct{})}
}

func (b *bweTracker) setCallback(fn func(BandwidthEstimate)) {
	if fn == nil {
		b.on.Store(nil)
		return
	}
	b.on.Store(&fn)
}

func (b *bweTracker) snapshot() BandwidthEstimate {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.latest
}

func (b *bweTracker) update(est BandwidthEstimate) {
	b.mu.Lock()
	if est.BitrateBps == 0 {
		est.BitrateBps = b.latest.BitrateBps
	}
	b.latest = est
	b.mu.Unlock()
	if fn := b.on.Load(); fn != nil {
		(*fn)(est)
	}
}

func (b *bweTracker) attach(sender *webrtc.RTPSender) {
	if sender == nil {
		return
	}
	go b.readLoop(sender)
}

func (b *bweTracker) readLoop(sender *webrtc.RTPSender) {
	for {
		select {
		case <-b.stop:
			return
		default:
		}
		pkts, _, err := sender.ReadRTCP()
		if err != nil {
			return
		}
		for _, p := range pkts {
			b.consume(p)
		}
	}
}

func (b *bweTracker) consume(p rtcp.Packet) {
	switch m := p.(type) {
	case *rtcp.ReceiverEstimatedMaximumBitrate:
		b.update(BandwidthEstimate{BitrateBps: uint64(m.Bitrate)})
	case *rtcp.ReceiverReport:
		if len(m.Reports) == 0 {
			return
		}
		r := m.Reports[0]
		b.update(BandwidthEstimate{
			FractionLost: r.FractionLost,
			TotalLost:    r.TotalLost,
			Jitter:       r.Jitter,
		})
	}
}
