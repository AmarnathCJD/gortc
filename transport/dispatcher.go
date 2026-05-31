// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package transport

import (
	"sync"
	"time"

	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

type Dispatcher struct {
	audioCh chan *rtp.Packet
	videoCh chan *rtp.Packet
	stop    chan struct{}
	wg      sync.WaitGroup

	audio *webrtc.TrackLocalStaticRTP
	video *webrtc.TrackLocalStaticRTP
}

func NewDispatcher(audio, video *webrtc.TrackLocalStaticRTP) *Dispatcher {
	return &Dispatcher{
		audioCh: make(chan *rtp.Packet, 64),
		videoCh: make(chan *rtp.Packet, 2048),
		stop:    make(chan struct{}),
		audio:   audio,
		video:   video,
	}
}

func (d *Dispatcher) Start() {
	d.wg.Add(1)
	go d.run()
}

func (d *Dispatcher) Stop() {
	close(d.stop)
	d.wg.Wait()
}

func (d *Dispatcher) SendAudio(p *rtp.Packet) {
	select {
	case d.audioCh <- p:
	case <-d.stop:
	}
}

func (d *Dispatcher) SendVideo(p *rtp.Packet) {
	select {
	case d.videoCh <- p:
	case <-d.stop:
	default:
	}
}

func (d *Dispatcher) run() {
	defer d.wg.Done()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()

	const videoByteBudgetPerTick = 48 * 1024

	for {
		select {
		case <-d.stop:
			return
		case <-tick.C:
		}

		for {
			select {
			case p := <-d.audioCh:
				if d.audio != nil {
					_ = d.audio.WriteRTP(p)
				}
				continue
			default:
			}
			break
		}

		for budget := videoByteBudgetPerTick; budget > 0; {
			select {
			case p := <-d.videoCh:
				if d.video != nil {
					_ = d.video.WriteRTP(p)
				}
				budget -= len(p.Payload)
			default:
				budget = 0
			}
		}
	}
}
