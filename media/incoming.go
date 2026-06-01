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
	"strings"
	"sync"

	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
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

// IncomingTrack is a remote RTP track delivered to OnTrack callbacks.
// It exposes raw RTP for the caller and a Record/RecordToFile convenience
// that demuxes Opus into ogg or VP8 into IVF.
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
	writePacket(p *rtp.Packet) error
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

func (t *IncomingTrack) ReadRTP() (*rtp.Packet, error) {
	pkt, _, err := t.remote.ReadRTP()
	return pkt, err
}

// Record starts demuxing the incoming RTP into the given writer. The writer
// is closed when the track ends or Stop is called. The format is chosen from
// the track codec: Opus → ogg, VP8 → IVF.
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

// RecordToFile opens the given file and records the track to it. The
func (t *IncomingTrack) RecordToFile(path string) error {
	if path == "" {
		return errors.New("media: empty record path")
	}
	if ext := strings.ToLower(filepathExt(path)); ext != "" {
		switch t.mimeType {
		case webrtc.MimeTypeOpus:
			if ext != ".ogg" && ext != ".opus" {
				// just a warning tho.
			}
		case webrtc.MimeTypeVP8:
			if ext != ".ivf" {
			}
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("media: create record file: %w", err)
	}
	return t.Record(f)
}

// Stop ends an active recording started by Record/RecordToFile.
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
		return newIVFWriter(w, "VP80"), nil
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

func filepathExt(path string) string {
	for i := len(path) - 1; i >= 0 && path[i] != '/' && path[i] != '\\'; i-- {
		if path[i] == '.' {
			return path[i:]
		}
	}
	return ""
}
