// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package transport

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

var (
	icePortRangeMu   sync.Mutex
	icePortRangeRand [2]uint16
)

func nextICEPortRange() (uint16, uint16) {
	icePortRangeMu.Lock()
	defer icePortRangeMu.Unlock()
	const windowSize = 4096
	const base = 49152
	const ceiling = 65535
	var seed [2]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return 0, 0
	}
	offset := uint16(binary.BigEndian.Uint16(seed[:])) % (ceiling - base - windowSize)
	lo := base + offset
	hi := lo + windowSize
	if hi > ceiling {
		hi = ceiling
	}
	if lo == icePortRangeRand[0] {
		lo += 17
		hi = lo + windowSize
		if hi > ceiling {
			hi = ceiling
		}
	}
	icePortRangeRand = [2]uint16{lo, hi}
	return lo, hi
}

func AudioCodecCapability() webrtc.RTPCodecCapability {
	return webrtc.RTPCodecCapability{
		MimeType:     webrtc.MimeTypeOpus,
		ClockRate:    48000,
		Channels:     2,
		SDPFmtpLine:  "minptime=10;useinbandfec=1;stereo=1;sprop-stereo=1;maxaveragebitrate=510000",
		RTCPFeedback: []webrtc.RTCPFeedback{{Type: "transport-cc"}},
	}
}

const MimeTypeVP9 = "video/VP9"

func VideoCodecCapability() webrtc.RTPCodecCapability {
	return VideoCodecCapabilityFor(webrtc.MimeTypeVP8)
}

func VideoCodecCapabilityFor(mime string) webrtc.RTPCodecCapability {
	fmtp := ""
	if mime == MimeTypeVP9 {
		fmtp = "profile-id=0"
	}
	return webrtc.RTPCodecCapability{
		MimeType:    mime,
		ClockRate:   90000,
		SDPFmtpLine: fmtp,
		RTCPFeedback: []webrtc.RTCPFeedback{
			{Type: "goog-remb"},
			{Type: "transport-cc"},
			{Type: "ccm", Parameter: "fir"},
			{Type: "nack"},
			{Type: "nack", Parameter: "pli"},
		},
	}
}

func BuildMediaEngine() (*webrtc.MediaEngine, error) {
	m := &webrtc.MediaEngine{}

	if err := m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: AudioCodecCapability(),
		PayloadType:        111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return nil, fmt.Errorf("register opus codec: %w", err)
	}

	if err := m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: VideoCodecCapability(),
		PayloadType:        100,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, fmt.Errorf("register vp8 codec: %w", err)
	}

	if err := m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: VideoCodecCapabilityFor(MimeTypeVP9),
		PayloadType:        102,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, fmt.Errorf("register vp9 codec: %w", err)
	}

	audioExtensions := []string{
		"urn:ietf:params:rtp-hdrext:ssrc-audio-level",
		"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
		"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
	}
	for _, uri := range audioExtensions {
		if err := m.RegisterHeaderExtension(
			webrtc.RTPHeaderExtensionCapability{URI: uri},
			webrtc.RTPCodecTypeAudio,
		); err != nil {
			return nil, fmt.Errorf("register audio header extension %s: %w", uri, err)
		}
	}

	videoExtensions := []string{
		"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
		"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
		"urn:3gpp:video-orientation",
	}
	for _, uri := range videoExtensions {
		if err := m.RegisterHeaderExtension(
			webrtc.RTPHeaderExtensionCapability{URI: uri},
			webrtc.RTPCodecTypeVideo,
		); err != nil {
			return nil, fmt.Errorf("register video header extension %s: %w", uri, err)
		}
	}
	return m, nil
}

func BuildInterceptorRegistry(m *webrtc.MediaEngine, log *Logger) (*interceptor.Registry, error) {
	i := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		return nil, fmt.Errorf("register interceptors: %w", err)
	}
	i.Add(&RTPDump{Log: log.With("subsystem", "rtp-dump")})
	i.Add(&MarkerClearInterceptorFactory{})
	i.Add(&AudioLevelInterceptorFactory{})
	return i, nil
}

func BuildSettingEngine() webrtc.SettingEngine {
	return BuildSettingEngineWithPorts(0, 0)
}

func BuildSettingEngineWithPorts(portMin, portMax uint16) webrtc.SettingEngine {
	se := webrtc.SettingEngine{}
	se.SetICETimeouts(
		15*time.Second,
		25*time.Second,
		8*time.Second,
	)
	se.SetSTUNGatherTimeout(8 * time.Second)
	se.SetSrflxAcceptanceMinWait(0)
	se.SetHandleUndeclaredSSRCWithoutAnswer(true)
	se.SetICEMaxBindingRequests(20)
	if portMin > 0 && portMax > 0 && portMax > portMin {
		_ = se.SetEphemeralUDPPortRange(portMin, portMax)
	}
	se.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
		webrtc.NetworkTypeUDP6,
	})
	se.SetInterfaceFilter(func(name string) bool {
		lower := strings.ToLower(name)
		for _, skip := range []string{
			"vethernet", "vmware", "virtualbox", "vbox", "hyper-v",
			"loopback", "teredo", "isatap", "tap-",
			"docker", "wsl", "tailscale", "zerotier", "openvpn",
		} {
			if strings.Contains(lower, skip) {
				return false
			}
		}
		return true
	})

	if runtime.GOOS == "windows" {
		icsNet := &net.IPNet{IP: net.IPv4(192, 168, 137, 0), Mask: net.CIDRMask(24, 32)}
		se.SetIPFilter(func(ip net.IP) bool {
			return !icsNet.Contains(ip)
		})
	}
	return se
}

func ExtractSDPParams(sdp string) (ufrag, pwd, fingerprint, hash string) {
	return extractSDPParams(sdp)
}

func ExtractAudioVideoSSRCs(sdp string) (audio, video uint32) {
	return extractAudioVideoSSRCs(sdp)
}
