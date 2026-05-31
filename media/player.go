// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

type playControl struct {
	mu      sync.Mutex
	cond    *sync.Cond
	paused  bool
	stopped bool
	elapsed time.Duration
	base    time.Duration

	clockStart  time.Time
	pausedSince time.Time
}

func newPlayControl(base time.Duration) *playControl {
	c := &playControl{base: base, clockStart: time.Now()}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// target returns the wall-clock instant at which a stream should have emitted
// streamDur of media, measured from the shared clock origin. Both the audio and
// video pacers chase this single origin so they never free-run apart. Paused
// time is excluded because clockStart is advanced by the pause duration on resume.
func (c *playControl) target(streamDur time.Duration) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clockStart.Add(streamDur)
}

func (c *playControl) tick(d time.Duration) {
	c.mu.Lock()
	c.elapsed += d
	c.mu.Unlock()
}

func (c *playControl) position() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base + c.elapsed
}

func (c *playControl) gate() bool {
	c.mu.Lock()
	for c.paused && !c.stopped {
		c.cond.Wait()
	}
	stopped := c.stopped
	c.mu.Unlock()
	return !stopped
}

func (c *playControl) pause() {
	c.mu.Lock()
	if !c.paused {
		c.paused = true
		c.pausedSince = time.Now()
	}
	c.mu.Unlock()
}

func (c *playControl) resume() {
	c.mu.Lock()
	if c.paused {
		c.paused = false
		if !c.pausedSince.IsZero() {
			c.clockStart = c.clockStart.Add(time.Since(c.pausedSince))
			c.pausedSince = time.Time{}
		}
	}
	c.mu.Unlock()
	c.cond.Broadcast()
}

func (c *playControl) stop() {
	c.mu.Lock()
	c.stopped = true
	c.mu.Unlock()
	c.cond.Broadcast()
}

func (c *playControl) isStopped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

type Player struct {
	mu       sync.Mutex
	ctrl     *playControl
	cancel   context.CancelFunc
	done     chan error
	send     AVSender
	aSSRC    uint32
	vSSRC    uint32
	src      Source
	duration time.Duration
}

func (p *Player) Pause()  { p.ctrl.pause() }
func (p *Player) Resume() { p.ctrl.resume() }

func (p *Player) Stop() {
	p.ctrl.stop()
	if p.cancel != nil {
		p.cancel()
	}
}

func (p *Player) Paused() bool {
	p.ctrl.mu.Lock()
	defer p.ctrl.mu.Unlock()
	return p.ctrl.paused
}

func (p *Player) Position() time.Duration { return p.ctrl.position() }

func (p *Player) Duration() time.Duration { return p.duration }

func (p *Player) Done() <-chan error { return p.done }

// Seek restarts playback at the given offset from the start. It requires a
// seekable source (FromFile/FromURL); returns ErrNotSeekable otherwise.
func (p *Player) Seek(offset time.Duration) error {
	seekable, ok := p.src.(SeekableSource)
	if !ok {
		return ErrNotSeekable
	}

	p.ctrl.stop()
	if p.cancel != nil {
		p.cancel()
	}
	<-p.done

	if offset < 0 {
		offset = 0
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctrl := newPlayControl(offset)

	p.mu.Lock()
	p.ctrl = ctrl
	p.cancel = cancel
	p.done = make(chan error, 1)
	done := p.done
	p.mu.Unlock()

	streams, err := seekable.OpenAt(ctx, offset)
	if err != nil {
		cancel()
		done <- err
		close(done)
		return err
	}

	go func() {
		done <- runStreams(streams, p.send, p.aSSRC, p.vSSRC, ctrl)
		close(done)
	}()
	return nil
}

func Play(ctx context.Context, send AVSender, audioSSRC, videoSSRC uint32, src Source) *Player {
	ctx, cancel := context.WithCancel(ctx)
	ctrl := newPlayControl(0)
	p := &Player{
		ctrl:     ctrl,
		cancel:   cancel,
		done:     make(chan error, 1),
		send:     send,
		aSSRC:    audioSSRC,
		vSSRC:    videoSSRC,
		src:      src,
		duration: probeDuration(src),
	}

	go func() {
		p.done <- streamControlled(ctx, send, audioSSRC, videoSSRC, src, ctrl)
		close(p.done)
	}()
	return p
}

type rtpCursor struct {
	seq uint16
	ts  uint32
}

var (
	contMu  sync.Mutex
	cursors = map[uint32]*rtpCursor{}
)

func nextCursor(ssrc uint32) *rtpCursor {
	contMu.Lock()
	defer contMu.Unlock()
	c, ok := cursors[ssrc]
	if !ok {
		c = &rtpCursor{seq: uint16(rand.Uint32()), ts: rand.Uint32()}
		cursors[ssrc] = c
	}

	return c
}

func loadCursor(ssrc uint32) (c *rtpCursor, seq uint16, ts uint32) {
	c = nextCursor(ssrc)
	contMu.Lock()
	seq, ts = c.seq, c.ts
	contMu.Unlock()

	return
}

func saveCursor(c *rtpCursor, seq uint16, ts uint32) {
	contMu.Lock()
	c.seq, c.ts = seq, ts
	contMu.Unlock()
}
