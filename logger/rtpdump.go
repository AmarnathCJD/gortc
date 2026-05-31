// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package logger

import (
	"sync/atomic"

	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/rtp"
)

// RTPDump logs outgoing packets at debug level.
type RTPDump struct {
	Log *Logger
}

func (f *RTPDump) NewInterceptor(string) (interceptor.Interceptor, error) {
	log := f.Log
	if log == nil {
		log = Disabled()
	}

	return &rtpDump{log: log}, nil
}

type rtpDump struct {
	interceptor.NoOp
	log *Logger
	n   atomic.Uint64
}

func (d *rtpDump) BindLocalStream(info *interceptor.StreamInfo, w interceptor.RTPWriter) interceptor.RTPWriter {
	d.log.Debugf("bind ssrc=%d pt=%d mime=%s clock=%d", info.SSRC, info.PayloadType, info.MimeType, info.ClockRate)

	return interceptor.RTPWriterFunc(func(h *rtp.Header, payload []byte, a interceptor.Attributes) (int, error) {
		if n := d.n.Add(1); n <= 20 || n%100 == 0 {
			d.log.Debugf("tx #%d ssrc=%d pt=%d seq=%d ts=%d marker=%t len=%d", n, h.SSRC, h.PayloadType, h.SequenceNumber, h.Timestamp, h.Marker, len(payload))
		}

		return w.Write(h, payload, a)
	})
}

func (d *rtpDump) UnbindLocalStream(info *interceptor.StreamInfo) {
	d.log.Debugf("unbind ssrc=%d total=%d", info.SSRC, d.n.Load())
}
