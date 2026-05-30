package media

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"github.com/amarnathcjd/gortc/webrtc/webrtc/pkg/media/oggreader"
)

const (
	opusPayloadType = 111
	opusClockRate   = 48000
	opusFrameMs     = 20
)

type Sender interface {
	SendAudio(*rtp.Packet)
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
	ogg, _, err := oggreader.NewWith(reader)
	if err != nil {
		return fmt.Errorf("create ogg reader: %w", err)
	}

	cur, seq, ts := loadCursor(ssrc)
	defer func() { saveCursor(cur, seq, ts) }()
	start := time.Now()
	var idx int64

	for {
		if ctrl != nil {
			before := time.Now()
			if !ctrl.gate() {
				return nil
			}
			start = start.Add(time.Since(before))
		}

		page, _, err := ogg.ParseNextPage()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse ogg page: %w", err)
		}
		if bytes.HasPrefix(page, []byte("OpusHead")) || bytes.HasPrefix(page, []byte("OpusTags")) {
			continue
		}

		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    opusPayloadType,
				SequenceNumber: seq,
				Timestamp:      ts,
				SSRC:           ssrc,
				Marker:         false,
			},
			Payload: append([]byte(nil), page...),
		}
		send.SendAudio(pkt)

		seq++
		ts += opusClockRate * opusFrameMs / 1000
		idx++
		if ctrl != nil {
			ctrl.tick(opusFrameMs * time.Millisecond)
		}
		target := start.Add(time.Duration(idx) * opusFrameMs * time.Millisecond)
		if d := time.Until(target); d > 0 {
			time.Sleep(d)
		}
	}
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
