// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/amarnathcjd/gortc/webrtc/webrtc"
	wutil "github.com/amarnathcjd/gortc/webrtc"
)

type TrackKind int

const (
	TrackKindUnknown TrackKind = iota
	TrackKindAudio
	TrackKindVideo
)

func (k TrackKind) String() string {
	switch k {
	case TrackKindAudio:
		return "audio"
	case TrackKindVideo:
		return "video"
	default:
		return "unknown"
	}
}

type IncomingTrack struct {
	remote   *webrtc.TrackRemote
	kind     TrackKind
	ssrc     uint32
	mimeType string
	clock    uint32

	mu       sync.Mutex
	recorder recorder
	stopped  bool
}

type recorder interface {
	writePacket(p *wutil.RtpPacket) error
	Close() error
}

func NewIncomingTrack(remote *webrtc.TrackRemote) *IncomingTrack {
	codec := remote.Codec()
	k := TrackKindUnknown
	switch remote.Kind() {
	case webrtc.RTPCodecTypeAudio:
		k = TrackKindAudio
	case webrtc.RTPCodecTypeVideo:
		k = TrackKindVideo
	}
	return &IncomingTrack{
		remote:   remote,
		kind:     k,
		ssrc:     uint32(remote.SSRC()),
		mimeType: codec.MimeType,
		clock:    codec.ClockRate,
	}
}

func (t *IncomingTrack) Kind() TrackKind             { return t.kind }
func (t *IncomingTrack) SSRC() uint32                { return t.ssrc }
func (t *IncomingTrack) Codec() string               { return t.mimeType }
func (t *IncomingTrack) ClockRate() uint32           { return t.clock }
func (t *IncomingTrack) Remote() *webrtc.TrackRemote { return t.remote }

func (t *IncomingTrack) ReadRTP() (*wutil.RtpPacket, error) {
	pkt, _, err := t.remote.ReadRTP()
	return pkt, err
}

func (t *IncomingTrack) Record(w io.WriteCloser) error {
	rec, err := t.newRecorderFor(w)
	if err != nil {
		_ = w.Close()
		return err
	}
	t.mu.Lock()
	if t.recorder != nil {
		t.mu.Unlock()
		_ = rec.Close()
		return errors.New("media: track already recording")
	}
	t.recorder = rec
	t.mu.Unlock()

	go t.recordLoop()
	return nil
}

func (t *IncomingTrack) RecordToFile(path string) error {
	if path == "" {
		return errors.New("media: empty record path")
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("media: create record file: %w", err)
	}
	return t.Record(f)
}

func (t *IncomingTrack) Stop() error {
	t.mu.Lock()
	rec := t.recorder
	t.recorder = nil
	t.stopped = true
	t.mu.Unlock()
	if rec == nil {
		return nil
	}
	return rec.Close()
}

func (t *IncomingTrack) newRecorderFor(w io.WriteCloser) (recorder, error) {
	switch t.mimeType {
	case webrtc.MimeTypeOpus:
		channels := uint8(t.remote.Codec().Channels)
		if channels == 0 {
			channels = 2
		}
		clock := t.clock
		if clock == 0 {
			clock = 48000
		}
		return newOggWriter(w, clock, channels)
	case webrtc.MimeTypeVP8:
		return newIVFWriter(w, "VP80", vp8Codec), nil
	case "video/VP9":
		return newIVFWriter(w, "VP90", vp9Codec), nil
	}
	return nil, fmt.Errorf("media: recording for codec %q not supported", t.mimeType)
}

func (t *IncomingTrack) recordLoop() {
	for {
		pkt, _, err := t.remote.ReadRTP()
		if err != nil {
			break
		}
		t.mu.Lock()
		rec := t.recorder
		t.mu.Unlock()
		if rec == nil {
			break
		}
		if err := rec.writePacket(pkt); err != nil {
			break
		}
	}
	t.mu.Lock()
	rec := t.recorder
	t.recorder = nil
	t.mu.Unlock()
	if rec != nil {
		_ = rec.Close()
	}
}
