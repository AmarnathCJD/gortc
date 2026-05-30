package media

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"github.com/amarnathcjd/gortc/webrtc/rtp/codecs"
	"github.com/amarnathcjd/gortc/webrtc/webrtc/pkg/media/ivfreader"
)

const (
	vp8PayloadType = 100
	vp8ClockRate   = 90000
)

type VideoSender interface {
	SendVideo(*rtp.Packet)
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
	ivf, header, err := ivfreader.NewWith(reader)
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
	tsStep := uint32(float64(vp8ClockRate) * frameDur.Seconds())

	cur, seq, ts := loadCursor(ssrc)
	defer func() { saveCursor(cur, seq, ts) }()
	payloader := &codecs.VP8Payloader{}
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
		for i, p := range payloads {
			marker := i == len(payloads)-1
			pkt := &rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					PayloadType:    vp8PayloadType,
					SequenceNumber: seq,
					Timestamp:      ts,
					SSRC:           ssrc,
					Marker:         marker,
				},
				Payload: p,
			}
			send.SendVideo(pkt)
			seq++
		}

		ts += tsStep
		frameIdx++
		target := start.Add(time.Duration(frameIdx) * frameDur)
		if d := time.Until(target); d > 0 {
			time.Sleep(d)
		}
	}
}
