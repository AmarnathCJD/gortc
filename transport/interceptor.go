// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package transport

import (
	"strings"
	"sync"
	"time"

	"github.com/amarnathcjd/gortc/webrtc/interceptor"

	"github.com/amarnathcjd/gortc/webrtc"
	"github.com/amarnathcjd/gortc/webrtc/sdp"
)

type AudioLevelInterceptorFactory struct{}

func (f *AudioLevelInterceptorFactory) NewInterceptor(id string) (interceptor.Interceptor, error) {
	return &audioLevelInterceptor{streams: make(map[uint32]*audioLevelStream)}, nil
}

type audioLevelStream struct {
	audioLevelID  uint8
	absSendTimeID uint8
	transportCCID uint8
	hasAudioLevel bool
	hasAbsSend    bool
	hasTransportCC bool
	twccSeq       uint16
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
		case sdp.TransportCCURI:
			s.transportCCID = uint8(ext.ID)
			s.hasTransportCC = true
		}
	}

	a.mu.Lock()
	a.streams[info.SSRC] = s
	a.mu.Unlock()
	return interceptor.RTPWriterFunc(func(header *webrtc.RtpHeader, payload []byte, attrs interceptor.Attributes) (int, error) {
		if s.hasAudioLevel {
			_ = header.SetExtension(s.audioLevelID, []byte{0x80 | 20})
		}
		if s.hasAbsSend {
			now := time.Now()
			abs := (uint64(now.Unix())<<18 | uint64(now.Nanosecond())*uint64(1<<18)/uint64(1e9)) & 0x00FFFFFF
			_ = header.SetExtension(s.absSendTimeID, []byte{byte(abs >> 16), byte(abs >> 8), byte(abs)})
		}
		if s.hasTransportCC {
			s.twccSeq++
			_ = header.SetExtension(s.transportCCID, []byte{byte(s.twccSeq >> 8), byte(s.twccSeq)})
		}
		return writer.Write(header, payload, attrs)
	})
}

func (a *audioLevelInterceptor) UnbindLocalStream(info *interceptor.StreamInfo) {
	a.mu.Lock()
	delete(a.streams, info.SSRC)
	a.mu.Unlock()
}

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
	return interceptor.RTPWriterFunc(func(header *webrtc.RtpHeader, payload []byte, attrs interceptor.Attributes) (int, error) {
		header.Marker = false
		return writer.Write(header, payload, attrs)
	})
}
