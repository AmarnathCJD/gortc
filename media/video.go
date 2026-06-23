// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"fmt"
	"io"
	"os"
	"time"

	webrtc "github.com/amarnathcjd/gortc/webrtc"
)

const (
	vp8PayloadType = 100
	vp9PayloadType = 102
	videoClockRate = 90000
)

type videoPayloader interface {
	Payload(mtu uint16, payload []byte) [][]byte
}

type VideoSender interface {
	SendVideo(*webrtc.RtpPacket)
}

func StreamIVFFile(send VideoSender, ssrc uint32, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("open ivf file: %w", err)
	}
	defer f.Close()
	return StreamIVF(send, ssrc, f)
}

func StreamIVF(send VideoSender, ssrc uint32, reader io.Reader) error {
	return streamIVF(send, ssrc, reader, nil)
}

func streamIVF(send VideoSender, ssrc uint32, reader io.Reader, ctrl *playControl) error {
	ivf, header, err := webrtc.IvfNewWith(reader)
	if err != nil {
		return fmt.Errorf("create ivf reader: %w", err)
	}
	if header.TimebaseDenominator == 0 {
		return fmt.Errorf("ivf timebase denominator is zero")
	}
	frameDur := time.Duration(float64(header.TimebaseNumerator) / float64(header.TimebaseDenominator) * float64(time.Second))
	if frameDur <= 0 {
		frameDur = time.Second / 30
	}
	tsStep := uint32(float64(videoClockRate) * frameDur.Seconds())

	cur, seq, ts := loadCursor(ssrc)
	defer func() { saveCursor(cur, seq, ts) }()

	var payloader videoPayloader = &webrtc.VP8Payloader{}
	payloadType := uint8(vp8PayloadType)
	if header.FourCC == "VP90" {
		payloader = &webrtc.VP9Payloader{}
		payloadType = vp9PayloadType
	}
	const mtu = 1200

	start := time.Now()
	var frameIdx int64

	for {
		if ctrl != nil {
			before := time.Now()
			if !ctrl.gate() {
				return nil
			}
			start = start.Add(time.Since(before))
		}

		frame, _, err := ivf.ParseNextFrame()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("parse ivf frame: %w", err)
		}

		payloads := payloader.Payload(mtu, frame)
		muted := ctrl != nil && ctrl.isMuted()
		for i, p := range payloads {
			marker := i == len(payloads)-1
			pkt := &webrtc.RtpPacket{
				RtpHeader: webrtc.RtpHeader{
					Version:        2,
					PayloadType:    payloadType,
					SequenceNumber: seq,
					Timestamp:      ts,
					SSRC:           ssrc,
					Marker:         marker,
				},
				Payload: p,
			}
			if !muted {
				send.SendVideo(pkt)
			}
			seq++
		}

		ts += tsStep
		frameIdx++
		played := time.Duration(frameIdx) * frameDur
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
