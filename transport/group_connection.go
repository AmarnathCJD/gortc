// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package transport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amarnathcjd/gortc/logger"
	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

type SsrcGroup struct {
	Semantics string  `json:"semantics"`
	Sources   []int32 `json:"sources"`
}

type JoinPayload struct {
	Ufrag        string        `json:"ufrag"`
	Pwd          string        `json:"pwd"`
	Fingerprints []Fingerprint `json:"fingerprints"`
	Ssrc         int32         `json:"ssrc"`
	SsrcGroups   []SsrcGroup   `json:"ssrc-groups"`
}

type Fingerprint struct {
	Hash        string `json:"hash"`
	Setup       string `json:"setup"`
	Fingerprint string `json:"fingerprint"`
}

type Candidate struct {
	Foundation string `json:"foundation"`
	Component  string `json:"component"`
	Protocol   string `json:"protocol"`
	Priority   string `json:"priority"`
	IP         string `json:"ip"`
	Port       string `json:"port"`
	Type       string `json:"type"`
	Generation string `json:"generation"`
	Network    string `json:"network"`
}

type TransportInfo struct {
	Ufrag        string        `json:"ufrag"`
	Pwd          string        `json:"pwd"`
	Fingerprints []Fingerprint `json:"fingerprints"`
	Candidates   []Candidate   `json:"candidates"`
}

type FeedbackType struct {
	Type    string `json:"type"`
	Subtype string `json:"subtype,omitempty"`
}

type FlexibleParams map[string]interface{}

func (fp *FlexibleParams) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" || string(data) == "[]" {
		*fp = nil
		return nil
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		*fp = nil
		return nil
	}
	*fp = m
	return nil
}

type PayloadType struct {
	ID            int            `json:"id"`
	Name          string         `json:"name"`
	Clockrate     int            `json:"clockrate"`
	Channels      int            `json:"channels,omitempty"`
	Parameters    FlexibleParams `json:"parameters,omitempty"`
	FeedbackTypes []FeedbackType `json:"rtcp-fbs,omitempty"`
}

type RTPExtension struct {
	ID  int    `json:"id"`
	URI string `json:"uri"`
}

type MediaDescription struct {
	PayloadTypes  []PayloadType  `json:"payload-types"`
	RTPExtensions []RTPExtension `json:"rtp-hdrexts"`
}

type ServerResponse struct {
	Transport TransportInfo     `json:"transport"`
	Audio     *MediaDescription `json:"audio,omitempty"`
	Video     *MediaDescription `json:"video,omitempty"`
	RTMP      *json.RawMessage  `json:"rtmp,omitempty"`
	Stream    *json.RawMessage  `json:"stream,omitempty"`
}

type GroupConnection struct {
	mu sync.Mutex

	pc                *webrtc.PeerConnection
	outgoingAudioSsrc uint32
	outgoingVideoSsrc uint32
	videoSsrcGroups   []SsrcGroup

	audioTrack *webrtc.TrackLocalStaticRTP
	videoTrack *webrtc.TrackLocalStaticRTP
	dispatcher *Dispatcher

	onConnected    func()
	onDisconnected func()
	onStateChange  func(string)
	state          string

	log *logger.Logger
}

func (gc *GroupConnection) Dispatcher() *Dispatcher {
	return gc.dispatcher
}

func NewGroupConnection(log *logger.Logger) *GroupConnection {
	if log == nil {
		log = logger.Disabled()
	}
	return &GroupConnection{log: log}
}

func (gc *GroupConnection) generateSsrcs() {
	buf := make([]byte, 4)
	rand.Read(buf)
	gc.outgoingAudioSsrc = binary.BigEndian.Uint32(buf) & 0x7fffffff
	if gc.outgoingAudioSsrc == 0 {
		gc.outgoingAudioSsrc = 1
	}
	gc.outgoingVideoSsrc = gc.outgoingAudioSsrc + 1

	numLayers := 3
	var simSsrcs []int32
	var fidGroups []SsrcGroup

	for i := 0; i < numLayers; i++ {
		ssrc := gc.outgoingVideoSsrc + uint32(i*2)
		fidSsrc := gc.outgoingVideoSsrc + uint32(i*2+1)
		simSsrcs = append(simSsrcs, int32(ssrc))
		fidGroups = append(fidGroups, SsrcGroup{
			Semantics: "FID",
			Sources:   []int32{int32(ssrc), int32(fidSsrc)},
		})
	}

	if len(simSsrcs) > 1 {
		gc.videoSsrcGroups = append(gc.videoSsrcGroups, SsrcGroup{
			Semantics: "SIM",
			Sources:   simSsrcs,
		})
	}
	gc.videoSsrcGroups = append(gc.videoSsrcGroups, fidGroups...)
}

func (gc *GroupConnection) Open() error {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	gc.generateSsrcs()

	m := &webrtc.MediaEngine{}
	// Opus fmtp must advertise stereo=1;sprop-stereo=1 (RFC 7587 §7.1); without
	// it receivers downmix to mono, producing "underwater"/metallic audio.
	if err := m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     webrtc.MimeTypeOpus,
			ClockRate:    48000,
			Channels:     2,
			SDPFmtpLine:  "minptime=10;useinbandfec=1;stereo=1;sprop-stereo=1;maxaveragebitrate=510000",
			RTCPFeedback: []webrtc.RTCPFeedback{{Type: "transport-cc"}},
		},
		PayloadType: 111,
	}, webrtc.RTPCodecTypeAudio); err != nil {
		return fmt.Errorf("register opus codec: %w", err)
	}

	// RTP header extensions the SFU expects. Without ssrc-audio-level the SFU
	// treats every frame as silence and never forwards downlink audio (pcap
	// diff: baseline emits 0x90/X=1 with a BEDE block, we'd emit 0x80/X=0).
	audioExtensions := []string{
		"urn:ietf:params:rtp-hdrext:ssrc-audio-level",
		"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
		"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
		"urn:ietf:params:rtp-hdrext:sdes:mid",
	}
	for _, uri := range audioExtensions {
		if err := m.RegisterHeaderExtension(
			webrtc.RTPHeaderExtensionCapability{URI: uri},
			webrtc.RTPCodecTypeAudio,
		); err != nil {
			return fmt.Errorf("register audio header extension %s: %w", uri, err)
		}
	}

	if err := m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:    webrtc.MimeTypeVP8,
			ClockRate:   90000,
			SDPFmtpLine: "",
			RTCPFeedback: []webrtc.RTCPFeedback{
				{Type: "goog-remb"},
				{Type: "transport-cc"},
				{Type: "ccm", Parameter: "fir"},
				{Type: "nack"},
				{Type: "nack", Parameter: "pli"},
			},
		},
		PayloadType: 100,
	}, webrtc.RTPCodecTypeVideo); err != nil {
		return fmt.Errorf("register vp8 codec: %w", err)
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
			return fmt.Errorf("register video header extension %s: %w", uri, err)
		}
	}

	i := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		return fmt.Errorf("register interceptors: %w", err)
	}
	// Order matters: the last-added interceptor is outermost (runs first on
	// the way out), so AudioLevel stamps the extension before RTPDump logs it.
	i.Add(&logger.RTPDump{Log: gc.log.With("subsystem", "rtp-dump")})
	i.Add(&MarkerClearInterceptorFactory{})
	i.Add(&AudioLevelInterceptorFactory{})

	se := webrtc.SettingEngine{}
	se.SetICETimeouts(
		30*time.Second,
		60*time.Second,
		2*time.Second,
	)
	se.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
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

	api := webrtc.NewAPI(
		webrtc.WithMediaEngine(m),
		webrtc.WithInterceptorRegistry(i),
		webrtc.WithSettingEngine(se),
	)

	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
			{URLs: []string{"stun:stun1.l.google.com:19302"}},
			{URLs: []string{"stun:stun2.l.google.com:19302"}},
			{URLs: []string{"stun:stun3.l.google.com:19302"}},
			{URLs: []string{"stun:stun4.l.google.com:19302"}},
		},
	})
	if err != nil {
		return fmt.Errorf("create peer connection: %w", err)
	}
	gc.pc = pc

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		gc.log.Infof("connection state: %s", state)
		gc.state = state.String()
		if gc.onStateChange != nil {
			gc.onStateChange(state.String())
		}
		switch state {
		case webrtc.PeerConnectionStateConnected:
			if gc.onConnected != nil {
				gc.onConnected()
			}
		case webrtc.PeerConnectionStateDisconnected,
			webrtc.PeerConnectionStateFailed,
			webrtc.PeerConnectionStateClosed:
			if gc.onDisconnected != nil {
				gc.onDisconnected()
			}
		}
	})

	var iceStuckTimer *time.Timer
	var iceTimerMu sync.Mutex
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		gc.log.Infof("ICE state: %s", state)
		iceTimerMu.Lock()
		defer iceTimerMu.Unlock()
		if iceStuckTimer != nil {
			iceStuckTimer.Stop()
			iceStuckTimer = nil
		}
		if state == webrtc.ICEConnectionStateChecking {
			iceStuckTimer = time.AfterFunc(5*time.Second, func() {
				gc.log.Warnf("ICE stuck in checking for 5s, closing PeerConnection so caller can rejoin")
				_ = pc.Close()
			})
		}
	})

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			gc.log.Debugf("local candidate: %s %s:%d", c.Protocol, c.Address, c.Port)
		}
	})

	return nil
}

func (gc *GroupConnection) GetJoinPayload() (string, error) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	if gc.pc == nil {
		return "", fmt.Errorf("connection not opened, call Open() first")
	}

	offer, err := gc.pc.CreateOffer(nil)
	if err != nil {
		return "", fmt.Errorf("create offer: %w", err)
	}

	gatherComplete := webrtc.GatheringCompletePromise(gc.pc)
	if err := gc.pc.SetLocalDescription(offer); err != nil {
		return "", fmt.Errorf("set local description: %w", err)
	}

	select {
	case <-gatherComplete:
	case <-time.After(5 * time.Second):
		gc.log.Warnf("ICE gathering timed out, proceeding with available candidates")
	}

	localDesc := gc.pc.LocalDescription()
	ufrag, pwd, fingerprint, hash := extractSDPParams(localDesc.SDP)

	audioSSRC, videoSSRC := extractAudioVideoSSRCs(localDesc.SDP)
	if audioSSRC != 0 {
		gc.outgoingAudioSsrc = audioSSRC
		gc.log.Debugf("using audio SSRC from offer: %d", audioSSRC)
	}
	if videoSSRC != 0 {
		gc.outgoingVideoSsrc = videoSSRC
		gc.videoSsrcGroups = gc.videoSsrcGroups[:0]
		gc.videoSsrcGroups = append(gc.videoSsrcGroups, SsrcGroup{
			Semantics: "FID",
			Sources:   []int32{int32(videoSSRC), int32(videoSSRC + 1)},
		})
		gc.log.Debugf("using video SSRC from offer: %d (FID rtx=%d)", videoSSRC, videoSSRC+1)
	}

	payload := JoinPayload{
		Ufrag: ufrag,
		Pwd:   pwd,
		Fingerprints: []Fingerprint{
			{
				Hash:        hash,
				Setup:       "passive",
				Fingerprint: fingerprint,
			},
		},
		Ssrc:       int32(gc.outgoingAudioSsrc),
		SsrcGroups: gc.videoSsrcGroups,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal join payload: %w", err)
	}
	return string(data), nil
}

func (gc *GroupConnection) Connect(responseJSON string) error {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	if gc.pc == nil {
		return fmt.Errorf("connection not initialized, call Open() first")
	}

	var resp ServerResponse
	if err := json.Unmarshal([]byte(responseJSON), &resp); err != nil {
		return fmt.Errorf("parse server response: %w", err)
	}

	answer := buildAnswerSDP(gc.pc.LocalDescription().SDP, resp)
	gc.log.Debugf("setting answer SDP:\n%s", answer)

	if err := gc.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answer,
	}); err != nil {
		return fmt.Errorf("set remote description: %w", err)
	}

	return nil
}

func (gc *GroupConnection) AddAudioTrack() (*webrtc.TrackLocalStaticRTP, error) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{
			MimeType:    webrtc.MimeTypeOpus,
			ClockRate:   48000,
			Channels:    2,
			SDPFmtpLine: "minptime=10;useinbandfec=1;stereo=1;sprop-stereo=1;maxaveragebitrate=510000",
		},
		"audio",
		"gortc-audio",
	)
	if err != nil {
		return nil, fmt.Errorf("create audio track: %w", err)
	}

	if _, err := gc.pc.AddTrack(track); err != nil {
		return nil, fmt.Errorf("add audio track: %w", err)
	}
	gc.audioTrack = track
	gc.tryStartDispatcher()
	return track, nil
}

func (gc *GroupConnection) AddVideoTrack(codecMime string) (*webrtc.TrackLocalStaticRTP, error) {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	if codecMime == "" {
		codecMime = webrtc.MimeTypeVP8
	}

	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{
			MimeType:  codecMime,
			ClockRate: 90000,
		},
		"video",
		"gortc-video",
	)
	if err != nil {
		return nil, fmt.Errorf("create video track: %w", err)
	}

	if _, err := gc.pc.AddTrack(track); err != nil {
		return nil, fmt.Errorf("add video track: %w", err)
	}
	gc.videoTrack = track
	gc.tryStartDispatcher()
	return track, nil
}

func (gc *GroupConnection) tryStartDispatcher() {
	if gc.dispatcher != nil {
		return
	}
	if gc.audioTrack == nil || gc.videoTrack == nil {
		return
	}
	gc.dispatcher = NewDispatcher(gc.audioTrack, gc.videoTrack)
	gc.dispatcher.Start()
}

func (gc *GroupConnection) OnTrack(handler func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver)) {
	gc.pc.OnTrack(handler)
}

func (gc *GroupConnection) OnConnected(handler func()) {
	gc.onConnected = handler
}

func (gc *GroupConnection) OnDisconnected(handler func()) {
	gc.onDisconnected = handler
}

func (gc *GroupConnection) OnStateChange(handler func(string)) {
	gc.onStateChange = handler
}

func (gc *GroupConnection) State() string {
	if gc.state == "" {
		return "new"
	}

	return gc.state
}

func (gc *GroupConnection) Close() error {
	gc.mu.Lock()
	defer gc.mu.Unlock()

	if gc.pc != nil {
		return gc.pc.Close()
	}
	return nil
}

func (gc *GroupConnection) PeerConnection() *webrtc.PeerConnection {
	return gc.pc
}

func (gc *GroupConnection) OutgoingAudioSsrc() uint32 {
	return gc.outgoingAudioSsrc
}

func (gc *GroupConnection) OutgoingVideoSsrc() uint32 {
	return gc.outgoingVideoSsrc
}

func randomICECredential(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		n, _ := rand.Int(rand.Reader, max)
		b[i] = charset[n.Int64()]
	}
	return string(b)
}

func extractSSRC(sdp string) uint32 {
	for _, line := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(line, "a=ssrc:") {
			rest := strings.TrimPrefix(line, "a=ssrc:")
			parts := strings.SplitN(rest, " ", 2)
			if len(parts) >= 1 {
				n, err := strconv.ParseUint(parts[0], 10, 32)
				if err == nil {
					return uint32(n)
				}
			}
		}
	}
	return 0
}

func extractAudioVideoSSRCs(sdp string) (audio, video uint32) {
	section := ""
	seen := map[uint32]bool{}
	for _, line := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(line, "m=audio") {
			section = "audio"
			continue
		}
		if strings.HasPrefix(line, "m=video") {
			section = "video"
			continue
		}
		if !strings.HasPrefix(line, "a=ssrc:") {
			continue
		}
		rest := strings.TrimPrefix(line, "a=ssrc:")
		parts := strings.SplitN(rest, " ", 2)
		if len(parts) < 1 {
			continue
		}
		n, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			continue
		}
		ssrc := uint32(n)
		if seen[ssrc] {
			continue
		}
		seen[ssrc] = true
		switch section {
		case "audio":
			if audio == 0 {
				audio = ssrc
			}
		case "video":
			if video == 0 {
				video = ssrc
			}
		}
	}
	return
}

func extractSDPParams(sdp string) (ufrag, pwd, fingerprint, hash string) {
	for _, line := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(line, "a=ice-ufrag:") {
			ufrag = strings.TrimPrefix(line, "a=ice-ufrag:")
		} else if strings.HasPrefix(line, "a=ice-pwd:") {
			pwd = strings.TrimPrefix(line, "a=ice-pwd:")
		} else if strings.HasPrefix(line, "a=fingerprint:") {
			parts := strings.SplitN(strings.TrimPrefix(line, "a=fingerprint:"), " ", 2)
			if len(parts) == 2 {
				hash = parts[0]
				fingerprint = parts[1]
			}
		}
	}
	return
}

func buildAnswerSDP(localSDP string, resp ServerResponse) string {
	t := resp.Transport
	var lines []string

	bundleMids := "0"
	if resp.Video != nil {
		bundleMids = "0 1"
	}

	lines = append(lines,
		"v=0",
		"o=- 1 2 IN IP4 0.0.0.0",
		"s=-",
		"t=0 0",
		fmt.Sprintf("a=group:BUNDLE %s", bundleMids),
		"a=ice-lite",
	)

	payloadNums := []string{}
	if resp.Audio != nil {
		for _, pt := range resp.Audio.PayloadTypes {
			payloadNums = append(payloadNums, strconv.Itoa(pt.ID))
		}
	}
	if len(payloadNums) == 0 {
		payloadNums = []string{"111", "126"}
	}

	lines = append(lines,
		fmt.Sprintf("m=audio %d RTP/SAVPF %s", findRemotePort(t.Candidates), strings.Join(payloadNums, " ")),
		fmt.Sprintf("c=IN IP4 %s", findRemoteIP(t.Candidates)),
		"a=mid:0",
		fmt.Sprintf("a=ice-ufrag:%s", t.Ufrag),
		fmt.Sprintf("a=ice-pwd:%s", t.Pwd),
	)

	if len(t.Fingerprints) > 0 {
		lines = append(lines,
			fmt.Sprintf("a=fingerprint:%s %s", t.Fingerprints[0].Hash, t.Fingerprints[0].Fingerprint))
	}

	lines = append(lines, "a=setup:active")

	for _, c := range t.Candidates {
		ip := net.ParseIP(c.IP)
		if ip == nil || ip.To4() == nil {
			continue
		}
		lines = append(lines,
			fmt.Sprintf("a=candidate:%s %s %s %s %s %s typ %s generation %s",
				c.Foundation, c.Component, c.Protocol, c.Priority,
				c.IP, c.Port, c.Type, c.Generation))
	}

	if resp.Audio != nil {
		for _, pt := range resp.Audio.PayloadTypes {
			channelStr := ""
			if pt.Channels > 1 {
				channelStr = fmt.Sprintf("/%d", pt.Channels)
			}
			lines = append(lines,
				fmt.Sprintf("a=rtpmap:%d %s/%d%s", pt.ID, pt.Name, pt.Clockrate, channelStr))

			if pt.Name == "opus" {
				lines = append(lines,
					fmt.Sprintf("a=fmtp:%d minptime=10;useinbandfec=1;stereo=1;sprop-stereo=1;maxaveragebitrate=510000", pt.ID))
			} else if len(pt.Parameters) > 0 {
				var params []string
				for k, v := range pt.Parameters {
					params = append(params, fmt.Sprintf("%s=%v", k, v))
				}
				lines = append(lines,
					fmt.Sprintf("a=fmtp:%d %s", pt.ID, strings.Join(params, ";")))
			}

			for _, fb := range pt.FeedbackTypes {
				fbLine := fmt.Sprintf("a=rtcp-fb:%d %s", pt.ID, fb.Type)
				if fb.Subtype != "" {
					fbLine += " " + fb.Subtype
				}
				lines = append(lines, fbLine)
			}
		}

		for _, ext := range resp.Audio.RTPExtensions {
			lines = append(lines, fmt.Sprintf("a=extmap:%d %s", ext.ID, ext.URI))
		}
	}

	lines = append(lines,
		"a=rtcp-mux",
		"a=sendrecv",
	)

	if resp.Video != nil {
		videoPayloadNums := []string{}
		for _, pt := range resp.Video.PayloadTypes {
			videoPayloadNums = append(videoPayloadNums, strconv.Itoa(pt.ID))
		}

		lines = append(lines,
			fmt.Sprintf("m=video %d RTP/SAVPF %s", findRemotePort(t.Candidates), strings.Join(videoPayloadNums, " ")),
			fmt.Sprintf("c=IN IP4 %s", findRemoteIP(t.Candidates)),
			"a=mid:1",
			fmt.Sprintf("a=ice-ufrag:%s", t.Ufrag),
			fmt.Sprintf("a=ice-pwd:%s", t.Pwd),
		)

		if len(t.Fingerprints) > 0 {
			lines = append(lines,
				fmt.Sprintf("a=fingerprint:%s %s", t.Fingerprints[0].Hash, t.Fingerprints[0].Fingerprint))
		}

		lines = append(lines, "a=setup:active")

		for _, pt := range resp.Video.PayloadTypes {
			// Telegram sometimes reports the VP8 clockrate as 9000; the correct
			// value is 90000 (RFC 7741). Normalize, else SetRemoteDescription
			// fails with "codec is not supported by remote".
			if pt.Clockrate == 9000 {
				pt.Clockrate = 90000
			}
			channelStr := ""
			if pt.Channels > 1 {
				channelStr = fmt.Sprintf("/%d", pt.Channels)
			}
			lines = append(lines,
				fmt.Sprintf("a=rtpmap:%d %s/%d%s", pt.ID, pt.Name, pt.Clockrate, channelStr))

			if len(pt.Parameters) > 0 {
				var params []string
				for k, v := range pt.Parameters {
					// Telegram sometimes nests the whole fmtp blob under a "fmtp"
					// key; pass it through verbatim to avoid "a=fmtp:100 fmtp=...".
					if k == "fmtp" {
						params = append(params, fmt.Sprintf("%v", v))
						continue
					}
					params = append(params, fmt.Sprintf("%s=%v", k, v))
				}
				lines = append(lines,
					fmt.Sprintf("a=fmtp:%d %s", pt.ID, strings.Join(params, ";")))
			}

			for _, fb := range pt.FeedbackTypes {
				fbLine := fmt.Sprintf("a=rtcp-fb:%d %s", pt.ID, fb.Type)
				if fb.Subtype != "" {
					fbLine += " " + fb.Subtype
				}
				lines = append(lines, fbLine)
			}
		}

		// Drop audio-only URIs Telegram sometimes lists under video (e.g.
		// ssrc-audio-level) and dedupe by ID, which it occasionally repeats.
		seenVideoExt := map[int]bool{}
		for _, ext := range resp.Video.RTPExtensions {
			if ext.URI == "urn:ietf:params:rtp-hdrext:ssrc-audio-level" {
				continue
			}
			if seenVideoExt[ext.ID] {
				continue
			}
			seenVideoExt[ext.ID] = true
			lines = append(lines, fmt.Sprintf("a=extmap:%d %s", ext.ID, ext.URI))
		}

		lines = append(lines,
			"a=rtcp-mux",
			"a=sendrecv",
		)
	}

	lines = append(lines, "")

	return strings.Join(lines, "\r\n")
}

func findRemoteIP(candidates []Candidate) string {
	for _, c := range candidates {
		ip := net.ParseIP(c.IP)
		if ip != nil && ip.To4() != nil {
			return c.IP
		}
	}
	return "0.0.0.0"
}

func findRemotePort(candidates []Candidate) int {
	for _, c := range candidates {
		ip := net.ParseIP(c.IP)
		if ip != nil && ip.To4() != nil {
			p, _ := strconv.Atoi(c.Port)
			return p
		}
	}
	return 1
}
