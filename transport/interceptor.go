package transport

import (
	"strings"
	"sync"
	"time"

	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"github.com/amarnathcjd/gortc/webrtc/sdp"
)

// AudioLevelInterceptorFactory stamps the ssrc-audio-level (RFC 6464) and
// abs-send-time extensions on every outgoing audio packet. Telegram's SFU
// treats streams without audio-level as silence and refuses to forward them,
// and the base stack does not stamp these automatically.
type AudioLevelInterceptorFactory struct{}

func (f *AudioLevelInterceptorFactory) NewInterceptor(id string) (interceptor.Interceptor, error) {
	return &audioLevelInterceptor{streams: make(map[uint32]*audioLevelStream)}, nil
}

type audioLevelStream struct {
	audioLevelID  uint8
	absSendTimeID uint8
	hasAudioLevel bool
	hasAbsSend    bool
}

type audioLevelInterceptor struct {
	interceptor.NoOp
	mu      sync.RWMutex
	streams map[uint32]*audioLevelStream
}

func (a *audioLevelInterceptor) BindLocalStream(info *interceptor.StreamInfo, writer interceptor.RTPWriter) interceptor.RTPWriter {
	s := &audioLevelStream{}
	for _, ext := range info.RTPHeaderExtensions {
		switch ext.URI {
		case sdp.AudioLevelURI:
			s.audioLevelID = uint8(ext.ID)
			s.hasAudioLevel = true
		case sdp.ABSSendTimeURI:
			s.absSendTimeID = uint8(ext.ID)
			s.hasAbsSend = true
		}
	}

	a.mu.Lock()
	a.streams[info.SSRC] = s
	a.mu.Unlock()

	return interceptor.RTPWriterFunc(func(header *rtp.Header, payload []byte, attrs interceptor.Attributes) (int, error) {
		if s.hasAudioLevel {
			// Voice-activity bit (0x80) | level in -dBov (0..127); fixed at -20 dBov.
			_ = header.SetExtension(s.audioLevelID, []byte{0x80 | 20})
		}
		if s.hasAbsSend {
			// abs-send-time: 24-bit fixed-point seconds since epoch * 2^18, big-endian.
			now := time.Now()
			abs := (uint64(now.Unix())<<18 | uint64(now.Nanosecond())*uint64(1<<18)/uint64(1e9)) & 0x00FFFFFF
			_ = header.SetExtension(s.absSendTimeID, []byte{byte(abs >> 16), byte(abs >> 8), byte(abs)})
		}

		return writer.Write(header, payload, attrs)
	})
}

func (a *audioLevelInterceptor) UnbindLocalStream(info *interceptor.StreamInfo) {
	a.mu.Lock()
	delete(a.streams, info.SSRC)
	a.mu.Unlock()
}

// MarkerClearInterceptorFactory clears the RTP marker bit on outgoing audio.
// The packetizer marks every single-payload Opus packet, but per RFC 7587 the
// marker should only be set on the first packet after silence; an always-set
// marker triggers jitter-buffer resync at the SFU and degrades audio.
type MarkerClearInterceptorFactory struct{}

func (f *MarkerClearInterceptorFactory) NewInterceptor(id string) (interceptor.Interceptor, error) {
	return &markerClearInterceptor{}, nil
}

type markerClearInterceptor struct {
	interceptor.NoOp
}

func (m *markerClearInterceptor) BindLocalStream(info *interceptor.StreamInfo, writer interceptor.RTPWriter) interceptor.RTPWriter {
	if !strings.HasPrefix(info.MimeType, "audio/") {
		return writer
	}

	return interceptor.RTPWriterFunc(func(header *rtp.Header, payload []byte, attrs interceptor.Attributes) (int, error) {
		header.Marker = false

		return writer.Write(header, payload, attrs)
	})
}
