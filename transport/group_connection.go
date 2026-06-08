// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	wutil "github.com/amarnathcjd/gortc/webrtc"
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

	audioTrack  *webrtc.TrackLocalStaticRTP
	videoTrack  *webrtc.TrackLocalStaticRTP
	audioSender *webrtc.RTPSender
	videoSender *webrtc.RTPSender
	dispatcher  *Dispatcher

	onConnected    func()
	onDisconnected func()
	onStateChange  func(string)
	onICEFailed    func()
	iceFailedOnce  sync.Once
	state          string

	srflxReady chan struct{}
	srflxOnce  sync.Once

	log *Logger
}

func (gc *GroupConnection) Dispatcher() *Dispatcher {
	return gc.dispatcher
}

func NewGroupConnection(log *Logger) *GroupConnection {
	if log == nil {
		log = DisabledLogger()
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
	if gc.outgoingVideoSsrc > 0x7ffffff0 {
		gc.outgoingVideoSsrc = 2
	}

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
	gc.srflxReady = make(chan struct{})
	gc.srflxOnce = sync.Once{}

	m, err := BuildMediaEngine()
	if err != nil {
		return err
	}

	i, err := BuildInterceptorRegistry(m, gc.log)
	if err != nil {
		return err
	}

	se := BuildSettingEngine()

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
			{URLs: []string{"stun:stun.cloudflare.com:3478"}},
			{URLs: []string{"stun:global.stun.twilio.com:3478"}},
		},
	})
	if err != nil {
		return fmt.Errorf("create peer connection: %w", err)
	}
	gc.pc = pc

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		gc.log.Debugf("[ice-debug] connection state: %s", state)
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

	pc.OnSignalingStateChange(func(state webrtc.SignalingState) {
		gc.log.Debugf("[ice-debug] signaling state: %s", state)
	})

	pc.OnICEGatheringStateChange(func(state webrtc.ICEGatheringState) {
		gc.log.Debugf("[ice-debug] ICE gathering state: %s", state)
	})

	var iceStuckTimer *time.Timer
	var iceTimerMu sync.Mutex
	var statsPollStop chan struct{}
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		gc.log.Debugf("[ice-debug] ICE connection state: %s", state)
		iceTimerMu.Lock()
		defer iceTimerMu.Unlock()
		if iceStuckTimer != nil {
			iceStuckTimer.Stop()
			iceStuckTimer = nil
		}
		if statsPollStop != nil {
			close(statsPollStop)
			statsPollStop = nil
		}
		if state == webrtc.ICEConnectionStateChecking {
			stop := make(chan struct{})
			statsPollStop = stop
			go gc.pollICEStats(pc, stop)

			iceStuckTimer = time.AfterFunc(12*time.Second, func() {
				gc.log.Warnf("[ice] stuck in checking for 12s; Telegram edge server unreachable — signalling rejoin")
				gc.fireICEFailed()
			})
		}
		if state == webrtc.ICEConnectionStateFailed {
			gc.fireICEFailed()
		}
	})

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			gc.log.Debugf("[ice-debug] local candidate gathering complete")
			return
		}
		gc.log.Debugf("[ice-debug] local candidate: typ=%s proto=%s %s:%d",
			c.Typ, c.Protocol, c.Address, c.Port)
		if c.Typ == webrtc.ICECandidateTypeSrflx {
			gc.srflxOnce.Do(func() {
				if gc.srflxReady != nil {
					close(gc.srflxReady)
				}
			})
		}
	})
	return nil
}

func (gc *GroupConnection) pollICEStats(pc *webrtc.PeerConnection, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		pairs, failed, anyResp := 0, 0, false
		var reqSent, respRecv uint64
		for _, s := range pc.GetStats() {
			cp, ok := s.(webrtc.ICECandidatePairStats)
			if !ok {
				continue
			}
			pairs++
			reqSent += cp.RequestsSent
			respRecv += cp.ResponsesReceived
			if cp.ResponsesReceived > 0 {
				anyResp = true
			}
			if cp.State == webrtc.StatsICECandidatePairStateFailed {
				failed++
			}
		}
		if pairs == 0 {
			gc.log.Debugf("[ice] no candidate pairs yet (remote candidates may be unreachable)")
			continue
		}
		gc.log.Debugf("[ice] pairs=%d failed=%d req_sent=%d resp_recv=%d", pairs, failed, reqSent, respRecv)
		if failed == pairs && !anyResp {
			gc.log.Warnf("[ice] all %d candidate pairs failed, no STUN responses from Telegram (edge server unreachable from this NAT)", pairs)
		}
	}
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

	srflxReady := gc.srflxReady
	gatherComplete := webrtc.GatheringCompletePromise(gc.pc)
	if err := gc.pc.SetLocalDescription(offer); err != nil {
		return "", fmt.Errorf("set local description: %w", err)
	}

	const offerWaitTimeout = 10 * time.Second
	select {
	case <-srflxReady:
		gc.log.Debugf("[ice-debug] srflx candidate ready, sending offer")
	case <-time.After(offerWaitTimeout):
		select {
		case <-srflxReady:
			gc.log.Debugf("[ice-debug] srflx candidate ready, sending offer")
		default:
			gc.log.Warnf("no server-reflexive (STUN) candidate gathered in %s; sending a host-only offer that likely cannot reach Telegram (check network/STUN reachability)", offerWaitTimeout)
		}
	}
	select {
	case <-gatherComplete:
	default:
	}

	localDesc := gc.pc.LocalDescription()
	ufrag, pwd, fingerprint, hash := extractSDPParams(localDesc.SDP)

	if gc.audioSender != nil {
		if enc := gc.audioSender.GetParameters().Encodings; len(enc) > 0 && enc[0].SSRC != 0 {
			bound := uint32(enc[0].SSRC)
			if bound != gc.outgoingAudioSsrc {
				gc.log.Warnf("audio SSRC drift: generated=%d bound=%d — advertising bound value", gc.outgoingAudioSsrc, bound)
			}
			gc.outgoingAudioSsrc = bound
		}
	}
	gc.log.Debugf("advertising audio SSRC=%d (matches wire)", gc.outgoingAudioSsrc)

	if gc.videoSender != nil {
		if enc := gc.videoSender.GetParameters().Encodings; len(enc) > 0 && enc[0].SSRC != 0 {
			videoSSRC := uint32(enc[0].SSRC)
			gc.outgoingVideoSsrc = videoSSRC
			gc.videoSsrcGroups = gc.videoSsrcGroups[:0]
			gc.videoSsrcGroups = append(gc.videoSsrcGroups, SsrcGroup{
				Semantics: "FID",
				Sources:   []int32{int32(videoSSRC), int32(videoSSRC + 1)},
			})
			gc.log.Debugf("advertising video SSRC=%d (FID rtx=%d)", videoSSRC, videoSSRC+1)
		}
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

	cands := resp.Transport.Candidates
	usable := 0
	for _, c := range cands {
		ip := net.ParseIP(c.IP)
		ok := ip != nil && ip.To4() != nil
		if ok {
			usable++
		}
		gc.log.Debugf("[ice-debug] remote candidate: typ=%s proto=%s %s:%s prio=%s usable_ipv4=%t",
			c.Type, c.Protocol, c.IP, c.Port, c.Priority, ok)
	}
	gc.log.Debugf("[ice-debug] remote candidates: %d total, %d usable IPv4; ufrag=%q pwd_len=%d fingerprints=%d",
		len(cands), usable, resp.Transport.Ufrag, len(resp.Transport.Pwd), len(resp.Transport.Fingerprints))
	if usable == 0 {
		gc.log.Warnf("Telegram returned no usable IPv4 candidate (%d total); cannot connect", len(cands))
	}

	answer := buildAnswerSDP(resp)
	gc.log.Debugf("setting answer SDP:\n%s", answer)

	if st := gc.pc.SignalingState(); st != webrtc.SignalingStateHaveLocalOffer {
		return fmt.Errorf("%w: signaling state is %s, expected have-local-offer (peer connection may have been reset between offer and answer)", errSignalingNotReady, st)
	}

	if err := gc.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answer,
	}); err != nil {
		return fmt.Errorf("set remote description: %w", err)
	}
	return nil
}

var errSignalingNotReady = errors.New("signaling-not-ready")

func IsSignalingNotReady(err error) bool { return errors.Is(err, errSignalingNotReady) }

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

	transceiver, err := gc.pc.AddTransceiverFromTrack(track, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendrecv,
		SendEncodings: []webrtc.RTPEncodingParameters{
			{RTPCodingParameters: webrtc.RTPCodingParameters{SSRC: webrtc.SSRC(gc.outgoingAudioSsrc)}},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("add audio track: %w", err)
	}
	gc.audioTrack = track
	gc.audioSender = transceiver.Sender()
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

	sender, err := gc.pc.AddTrack(track)
	if err != nil {
		return nil, fmt.Errorf("add video track: %w", err)
	}
	gc.videoTrack = track
	gc.videoSender = sender
	gc.tryStartDispatcher()
	return track, nil
}

func (gc *GroupConnection) VideoSender() *webrtc.RTPSender { return gc.videoSender }
func (gc *GroupConnection) AudioSender() *webrtc.RTPSender { return gc.audioSender }

func (gc *GroupConnection) tryStartDispatcher() {
	if gc.dispatcher != nil {
		return
	}
	if gc.audioTrack == nil && gc.videoTrack == nil {
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

func (gc *GroupConnection) OnICEFailed(handler func()) {
	gc.onICEFailed = handler
}

func (gc *GroupConnection) fireICEFailed() {
	gc.iceFailedOnce.Do(func() {
		if gc.onICEFailed != nil {
			go gc.onICEFailed()
		}
	})
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

func (gc *GroupConnection) StartAudioRTCP() {
	go func() {
		sendSR := func() bool {
			gc.mu.Lock()
			pc := gc.pc
			d := gc.dispatcher
			ssrc := gc.outgoingAudioSsrc
			gc.mu.Unlock()
			if pc == nil || d == nil {
				return false
			}
			if pc.ConnectionState() == webrtc.PeerConnectionStateClosed ||
				pc.ConnectionState() == webrtc.PeerConnectionStateFailed {
				return false
			}
			lastTS, pkts, octets := d.AudioStats()
			if pkts == 0 {
				return true
			}
			sr := &wutil.RtcpSenderReport{
				SSRC:        ssrc,
				NTPTime:     wutil.NowNTP(),
				RTPTime:     lastTS,
				PacketCount: pkts,
				OctetCount:  octets,
			}
			if err := pc.WriteRTCP([]wutil.RtcpPacket{sr}); err != nil {
				gc.log.Debugf("[rtcp] write SR: %v", err)
			}
			return true
		}
		for range 5 {
			if !sendSR() {
				return
			}
			time.Sleep(200 * time.Millisecond)
		}

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if !sendSR() {
				return
			}
		}
	}()
}

func (gc *GroupConnection) OutgoingVideoSsrc() uint32 {
	return gc.outgoingVideoSsrc
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

func buildAnswerSDP(resp ServerResponse) string {
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

type Logger struct {
	sl *slog.Logger
}

type LogOption func(*logConfig)

type logConfig struct {
	level   slog.Level
	out     io.Writer
	handler slog.Handler
}

func WithLogLevel(l slog.Level) LogOption {
	return func(c *logConfig) { c.level = l }
}

func WithLogOutput(w io.Writer) LogOption {
	return func(c *logConfig) { c.out = w }
}

func WithLogHandler(h slog.Handler) LogOption {
	return func(c *logConfig) { c.handler = h }
}

func NewLogger(opts ...LogOption) *Logger {
	c := &logConfig{level: slog.LevelWarn, out: os.Stderr}
	for _, o := range opts {
		o(c)
	}
	h := c.handler
	if h == nil {
		h = slog.NewTextHandler(c.out, &slog.HandlerOptions{Level: c.level})
	}
	return &Logger{sl: slog.New(h)}
}

func LoggerFrom(sl *slog.Logger) *Logger {
	if sl == nil {
		return DisabledLogger()
	}
	return &Logger{sl: sl}
}

func DisabledLogger() *Logger {
	h := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1})
	return &Logger{sl: slog.New(h)}
}

func (l *Logger) With(args ...any) *Logger {
	return &Logger{sl: l.sl.With(args...)}
}

func (l *Logger) Debugf(format string, args ...any) { l.logf(slog.LevelDebug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.logf(slog.LevelInfo, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.logf(slog.LevelWarn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.logf(slog.LevelError, format, args...) }

func (l *Logger) logf(level slog.Level, format string, args ...any) {
	if l == nil || l.sl == nil || !l.sl.Enabled(context.Background(), level) {
		return
	}
	l.sl.Log(context.Background(), level, fmt.Sprintf(format, args...))
}
