// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/amarnathcjd/gortc/webrtc"
)

const (
	opusPayloadType = 111
	opusClockRate   = 48000
	opusFrameMs     = 20
)

type Sender interface {
	SendAudio(*webrtc.RtpPacket)
}

func StreamOggOpusFile(send Sender, ssrc uint32, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open ogg file: %w", err)
	}
	defer f.Close()
	return StreamOggOpus(send, ssrc, f)
}

func StreamOggOpus(send Sender, ssrc uint32, reader io.Reader) error {
	return streamOggOpus(send, ssrc, reader, nil)
}

func streamOggOpus(send Sender, ssrc uint32, reader io.Reader, ctrl *playControl) error {
	ogg, _, err := webrtc.OggNewWith(reader)
	if err != nil {
		return fmt.Errorf("create ogg reader: %w", err)
	}

	cur, seq, ts := loadCursor(ssrc)
	defer func() { saveCursor(cur, seq, ts) }()
	start := time.Now()

	const samplesPerFrame = opusClockRate * opusFrameMs / 1000 // 960

	var played time.Duration
	var pending []byte

	for {
		if ctrl != nil {
			before := time.Now()
			if !ctrl.gate() {
				return nil
			}
			start = start.Add(time.Since(before))
		}

		packets, _, err := ogg.ParseNextPageSegments()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse ogg page: %w", err)
		}
		if len(packets) == 0 {
			continue
		}

		// Stitch any continuation: a packet whose last segment was 255 bytes
		// resumes on the next page's first packet.
		if pending != nil {
			packets[0] = append(pending, packets[0]...)
			pending = nil
		}
		// If this page's final packet ended on a 255-byte segment it continues
		// onto the next page; defer it.
		if endsContinued(ogg) {
			pending = packets[len(packets)-1]
			packets = packets[:len(packets)-1]
		}

		for _, pkt := range packets {
			if len(pkt) == 0 {
				continue
			}
			if bytes.HasPrefix(pkt, []byte("OpusHead")) || bytes.HasPrefix(pkt, []byte("OpusTags")) {
				continue
			}

			samples := opusPacketSamples(pkt)
			if samples == 0 {
				samples = samplesPerFrame
			}

			rtpPkt := &webrtc.RtpPacket{
				RtpHeader: webrtc.RtpHeader{
					Version:        2,
					PayloadType:    opusPayloadType,
					SequenceNumber: seq,
					Timestamp:      ts,
					SSRC:           ssrc,
					Marker:         false,
				},
				Payload: append([]byte(nil), pkt...),
			}
			send.SendAudio(rtpPkt)

			seq++
			ts += uint32(samples)
			dur := time.Duration(samples) * time.Second / opusClockRate
			played += dur
			if ctrl != nil {
				ctrl.tick(dur)
			}

			var target time.Time
			if ctrl != nil {
				target = ctrl.target(played)
			} else {
				target = start.Add(played)
			}
			if d := time.Until(target); d > 0 {
				time.Sleep(d)
			}
		}
	}
}

// endsContinued reports whether the last segment of the most recent page was
// 255 bytes — meaning its final packet continues on the next page.
func endsContinued(o *webrtc.OggOggReader) bool {
	return o.LastPageLastSegmentSize() == 255
}

// opusPacketSamples returns the duration in 48 kHz samples encoded in the TOC
// byte of an Opus packet (RFC 6716 §3.1). Returns 0 if the packet is too short
// or the duration is unrecognised.
func opusPacketSamples(pkt []byte) uint64 {
	if len(pkt) < 1 {
		return 0
	}
	toc := pkt[0]
	config := toc >> 3
	// Frame durations per config (microseconds), per RFC 6716 Table 2.
	var frameUs uint64
	switch {
	case config <= 11: // SILK and Hybrid
		switch config % 4 {
		case 0:
			frameUs = 10000
		case 1:
			frameUs = 20000
		case 2:
			frameUs = 40000
		case 3:
			frameUs = 60000
		}
	case config <= 15: // Hybrid 10/20 ms
		if config%2 == 0 {
			frameUs = 10000
		} else {
			frameUs = 20000
		}
	default: // CELT 2.5/5/10/20 ms
		switch config % 4 {
		case 0:
			frameUs = 2500
		case 1:
			frameUs = 5000
		case 2:
			frameUs = 10000
		case 3:
			frameUs = 20000
		}
	}
	if frameUs == 0 {
		return 0
	}

	// Frame count from code in lower 2 bits.
	var frames uint64
	switch toc & 0x03 {
	case 0:
		frames = 1
	case 1, 2:
		frames = 2
	case 3:
		if len(pkt) < 2 {
			return 0
		}
		frames = uint64(pkt[1] & 0x3F)
		if frames == 0 {
			return 0
		}
	}
	return frames * frameUs * opusClockRate / 1_000_000
}

func GenerateTestTone(filename string, freqHz int, durationSec int) error {
	cmd := exec.Command("ffmpeg", "-y",
		"-f", "lavfi",
		"-i", fmt.Sprintf("sine=frequency=%d:duration=%d:sample_rate=48000", freqHz, durationSec),
		"-c:a", "libopus",
		"-b:a", "64k",
		"-ar", "48000",
		"-ac", "2",
		"-application", "voip",
		"-frame_duration", "20",
		"-page_duration", "20000",
		filename,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ffmpeg: %w\n%s", err, string(out))
	}
	return nil
}
