// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package transport

import (
	"sync"
	"sync/atomic"
	"time"

	wutil "github.com/amarnathcjd/gortc/webrtc"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

type Dispatcher struct {
	audioCh chan *wutil.RtpPacket
	videoCh chan *wutil.RtpPacket
	stop    chan struct{}
	wg      sync.WaitGroup

	audio *webrtc.TrackLocalStaticRTP
	video *webrtc.TrackLocalStaticRTP

	encMu          sync.RWMutex
	audioPayloadFn func(p *wutil.RtpPacket) error
	videoPayloadFn func(p *wutil.RtpPacket) error

	audioLastTS   atomic.Uint32
	audioPktCount atomic.Uint32
	audioOctets   atomic.Uint32
	videoPktCount atomic.Uint32
	videoOctets   atomic.Uint32
}

func (d *Dispatcher) VideoStats() (packets, octets uint32) {
	return d.videoPktCount.Load(), d.videoOctets.Load()
}

func (d *Dispatcher) AudioStats() (lastTS, packets, octets uint32) {
	return d.audioLastTS.Load(), d.audioPktCount.Load(), d.audioOctets.Load()
}

func (d *Dispatcher) SetAudioTrack(t *webrtc.TrackLocalStaticRTP) {
	d.encMu.Lock()
	d.audio = t
	d.encMu.Unlock()
}

func (d *Dispatcher) SetVideoTrack(t *webrtc.TrackLocalStaticRTP) {
	d.encMu.Lock()
	d.video = t
	d.encMu.Unlock()
}

func (d *Dispatcher) SetAudioPayloadEncoder(fn func(p *wutil.RtpPacket) error) {
	d.encMu.Lock()
	d.audioPayloadFn = fn
	d.encMu.Unlock()
}

func (d *Dispatcher) SetVideoPayloadEncoder(fn func(p *wutil.RtpPacket) error) {
	d.encMu.Lock()
	d.videoPayloadFn = fn
	d.encMu.Unlock()
}

func NewDispatcher(audio, video *webrtc.TrackLocalStaticRTP) *Dispatcher {
	return &Dispatcher{
		audioCh: make(chan *wutil.RtpPacket, 64),
		videoCh: make(chan *wutil.RtpPacket, 2048),
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

func (d *Dispatcher) SendAudio(p *wutil.RtpPacket) {
	select {
	case d.audioCh <- p:
	case <-d.stop:
	}
}

func (d *Dispatcher) SendVideo(p *wutil.RtpPacket) {
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
				d.encMu.RLock()
				audio := d.audio
				fn := d.audioPayloadFn
				d.encMu.RUnlock()
				if audio != nil {
					if fn != nil {
						if err := fn(p); err != nil {
							continue
						}
					}
					d.audioLastTS.Store(p.RtpHeader.Timestamp)
					d.audioPktCount.Add(1)
					d.audioOctets.Add(uint32(len(p.Payload)))
					_ = audio.WriteRTP(p)
				}
				continue
			default:
			}
			break
		}

		for budget := videoByteBudgetPerTick; budget > 0; {
			select {
			case p := <-d.videoCh:
				d.encMu.RLock()
				video := d.video
				fn := d.videoPayloadFn
				d.encMu.RUnlock()
				if video != nil {
					if fn != nil {
						if err := fn(p); err != nil {
							budget = 0
							continue
						}
					}
					_ = video.WriteRTP(p)
					d.videoPktCount.Add(1)
					d.videoOctets.Add(uint32(len(p.Payload)))
				}
				budget -= len(p.Payload)
			default:
				budget = 0
			}
		}
	}
}
