// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package phonecall

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/amarnathcjd/gortc/transport"
	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"

	"github.com/amarnathcjd/gogram/telegram"
)

type connection struct {
	mu sync.Mutex

	api          *webrtc.API
	gatherer     *webrtc.ICEGatherer
	iceTransport *webrtc.ICETransport
	dtls         *webrtc.DTLSTransport
	cert         webrtc.Certificate

	audioTrack  *webrtc.TrackLocalStaticRTP
	videoTrack  *webrtc.TrackLocalStaticRTP
	audioSender *webrtc.RTPSender
	videoSender *webrtc.RTPSender
	dispatcher  *transport.Dispatcher

	audioSSRC uint32
	videoSSRC uint32

	isOutgoing bool

	emit             func(msg []byte)
	negotiation      *negotiator
	iceStarted       bool
	remoteReady      bool
	dtlsStarted      bool
	negotiationReady bool
	channelsCreated  bool
	pendingRemoteIC  []iceCandidate

	iceConnected    bool
	dtlsConnected   bool
	firedConnect    bool
	firedDisconnect bool

	onConnected    func()
	onDisconnected func()
	onStateChange  func(string)
	onTrack        func(*webrtc.TrackRemote, *webrtc.RTPReceiver)
	state          string

	log *transport.Logger
}

func newConnection(isOutgoing bool, log *transport.Logger) *connection {
	if log == nil {
		log = transport.DisabledLogger()
	}
	return &connection{isOutgoing: isOutgoing, log: log}
}

func (c *connection) open(conns []telegram.PhoneConnection) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	m, err := transport.BuildMediaEngine()
	if err != nil {
		return err
	}
	i := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, i); err != nil {
		return fmt.Errorf("register interceptors: %w", err)
	}
	se := transport.BuildSettingEngine()

	c.api = webrtc.NewAPI(
		webrtc.WithMediaEngine(m),
		webrtc.WithInterceptorRegistry(i),
		webrtc.WithSettingEngine(se),
	)

	gatherer, err := c.api.NewICEGatherer(webrtc.ICEGatherOptions{
		ICEServers: iceServersFrom(conns),
	})
	if err != nil {
		return fmt.Errorf("new ice gatherer: %w", err)
	}
	c.gatherer = gatherer

	c.iceTransport = c.api.NewICETransport(gatherer)

	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	cert, err := webrtc.GenerateCertificate(sk)
	if err != nil {
		return fmt.Errorf("generate certificate: %w", err)
	}
	c.cert = *cert

	dtls, err := c.api.NewDTLSTransport(c.iceTransport, []webrtc.Certificate{c.cert})
	if err != nil {
		return fmt.Errorf("new dtls transport: %w", err)
	}
	c.dtls = dtls

	c.gatherer.OnLocalCandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			c.log.Debugf("[p2p] local candidate gathering complete")
			return
		}
		c.log.Debugf("[p2p] local candidate: typ=%s proto=%s %s:%d",
			cand.Typ, cand.Protocol, cand.Address, cand.Port)
		c.sendCandidate(cand)
	})

	c.iceTransport.OnConnectionStateChange(func(state webrtc.ICETransportState) {
		c.log.Debugf("[p2p] ICE connection state: %s", state)
		c.mu.Lock()
		c.iceConnected = state == webrtc.ICETransportStateConnected ||
			state == webrtc.ICETransportStateCompleted
		c.mu.Unlock()
		c.updateAggregateState()
		if state == webrtc.ICETransportStateFailed ||
			state == webrtc.ICETransportStateClosed {
			c.fireDisconnected()
		}
	})

	c.dtls.OnStateChange(func(state webrtc.DTLSTransportState) {
		c.log.Debugf("[p2p] DTLS state: %s", state)
		c.mu.Lock()
		c.dtlsConnected = state == webrtc.DTLSTransportStateConnected
		c.mu.Unlock()
		c.updateAggregateState()
		if state == webrtc.DTLSTransportStateFailed ||
			state == webrtc.DTLSTransportStateClosed {
			c.fireDisconnected()
		}
	})

	c.negotiation = newNegotiator(c.isOutgoing)
	c.addTracksLocked()

	if err := c.gatherer.Gather(); err != nil {
		return fmt.Errorf("gather: %w", err)
	}
	return nil
}

func (c *connection) addTracksLocked() {
	c.audioSSRC = randomSSRC()
	c.videoSSRC = c.audioSSRC + 1

	audio, _ := webrtc.NewTrackLocalStaticRTP(
		transport.AudioCodecCapability(), "audio", "gortc-audio")
	video, _ := webrtc.NewTrackLocalStaticRTP(
		transport.VideoCodecCapability(), "video", "gortc-video")
	c.audioTrack = audio
	c.videoTrack = video
	c.dispatcher = transport.NewDispatcher(audio, video)
}

func (c *connection) start() error {
	if c.isOutgoing {
		return c.sendInitialSetup("actpass")
	}
	return nil
}

func (c *connection) sendInitialSetup(setup string) error {
	iceParams, err := c.gatherer.GetLocalParameters()
	if err != nil {
		return fmt.Errorf("local ice params: %w", err)
	}
	dtlsParams, err := c.dtls.GetLocalParameters()
	if err != nil {
		return fmt.Errorf("local dtls params: %w", err)
	}
	var fp signalingFingerprint
	if len(dtlsParams.Fingerprints) > 0 {
		fp = signalingFingerprint{
			Hash:        dtlsParams.Fingerprints[0].Algorithm,
			Fingerprint: dtlsParams.Fingerprints[0].Value,
			Setup:       setup,
		}
	}
	msg := initialSetup{
		Type:         typeInitialSetup,
		Ufrag:        iceParams.UsernameFragment,
		Pwd:          iceParams.Password,
		Fingerprints: []signalingFingerprint{fp},
	}
	data, err := encodeSignaling(msg)
	if err != nil {
		return fmt.Errorf("encode initial setup: %w", err)
	}
	c.emit(data)
	return nil
}

func (c *connection) onSignal(data []byte) error {
	typ, err := decodeSignalingType(data)
	if err != nil {
		return err
	}
	switch typ {
	case typeInitialSetup:
		return c.handleInitialSetup(data)
	case typeCandidates:
		return c.handleCandidates(data)
	case typeNegotiateChannels:
		return c.handleNegotiate(data)
	case typeMediaState:
		return nil
	default:
		c.log.Debugf("[p2p] ignoring signaling type %q", typ)
		return nil
	}
}

func (c *connection) handleInitialSetup(data []byte) error {
	var msg initialSetup
	if err := jsonUnmarshal(data, &msg); err != nil {
		return fmt.Errorf("decode initial setup: %w", err)
	}

	c.mu.Lock()
	if c.iceStarted {
		c.mu.Unlock()
		return nil
	}
	c.iceStarted = true

	setup := peerSetup(&msg)
	role := dtlsRoleFor(setup, c.isOutgoing)
	c.log.Debugf("[p2p] remote InitialSetup: ufrag=%s setup=%s -> remote dtls role=%v", msg.Ufrag, setup, role)

	iceRole := webrtc.ICERoleControlled
	if c.isOutgoing {
		iceRole = webrtc.ICERoleControlling
	}
	remoteICE := webrtc.ICEParameters{UsernameFragment: msg.Ufrag, Password: msg.Pwd}

	var fps []webrtc.DTLSFingerprint
	if len(msg.Fingerprints) > 0 {
		fps = append(fps, webrtc.DTLSFingerprint{
			Algorithm: msg.Fingerprints[0].Hash,
			Value:     msg.Fingerprints[0].Fingerprint,
		})
	}

	c.remoteReady = true
	for _, ic := range c.pendingRemoteIC {
		c.addRemoteCandidateLocked(ic)
	}
	c.pendingRemoteIC = nil
	c.mu.Unlock()

	go func() {
		if err := c.iceTransport.Start(c.gatherer, remoteICE, &iceRole); err != nil {
			c.log.Warnf("[p2p] ice start: %v", err)
			return
		}
		c.log.Debugf("[p2p] ICE transport started (connected)")
		if err := c.dtls.Start(webrtc.DTLSParameters{Role: role, Fingerprints: fps}); err != nil {
			c.log.Warnf("[p2p] dtls start: %v", err)
			return
		}
		c.onDTLSStarted()
	}()

	if !c.isOutgoing {
		if err := c.sendInitialSetup("passive"); err != nil {
			return err
		}
	}
	return nil
}

func (c *connection) onDTLSStarted() {
	c.log.Debugf("[p2p] DTLS started")
	c.mu.Lock()
	c.dtlsStarted = true
	offer := c.negotiation.localOffer(c.audioSSRC, c.videoSSRC)
	c.mu.Unlock()
	if offer != nil {
		c.sendNegotiate(offer)
	}
	c.maybeCreateChannels()
}

func (c *connection) handleCandidates(data []byte) error {
	var msg candidatesMsg
	if err := jsonUnmarshal(data, &msg); err != nil {
		return fmt.Errorf("decode candidates: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ic := range msg.Candidates {
		if !c.remoteReady {
			c.pendingRemoteIC = append(c.pendingRemoteIC, ic)
			continue
		}
		c.addRemoteCandidateLocked(ic)
	}
	return nil
}

func (c *connection) addRemoteCandidateLocked(ic iceCandidate) {
	if candidateAddrIsHostname(ic.SdpString) {
		return
	}
	cand, err := webrtc.NewICECandidateFromSDP(ic.SdpString)
	if err != nil {
		c.log.Debugf("[p2p] parse remote candidate: %v", err)
		return
	}
	if err := c.iceTransport.AddRemoteCandidate(cand); err != nil {
		c.log.Debugf("[p2p] add remote candidate failed: %v", err)
	}
}

func (c *connection) handleNegotiate(data []byte) error {
	var msg negotiateChannels
	if err := jsonUnmarshal(data, &msg); err != nil {
		return fmt.Errorf("decode negotiate: %w", err)
	}
	c.mu.Lock()
	if c.negotiationReady {
		c.mu.Unlock()
		return nil
	}
	reply, ready := c.negotiation.onRemote(&msg, c.audioSSRC, c.videoSSRC)
	if ready {
		c.negotiationReady = true
	}
	c.mu.Unlock()
	if reply != nil {
		c.sendNegotiate(reply)
	}
	if ready {
		c.maybeCreateChannels()
	}
	return nil
}

func (c *connection) sendNegotiate(msg *negotiateChannels) {
	data, err := encodeSignaling(msg)
	if err != nil {
		c.log.Debugf("[p2p] encode negotiate: %v", err)
		return
	}
	c.log.Debugf("[p2p] -> NegotiateChannels exchangeId=%s contents=%d", msg.ExchangeID, len(msg.Contents))
	c.emit(data)
}

func (c *connection) maybeCreateChannels() {
	c.mu.Lock()
	if c.channelsCreated || !c.dtlsStarted || !c.negotiationReady {
		c.mu.Unlock()
		return
	}
	c.channelsCreated = true
	peerAudioSSRC := c.negotiation.peerAudioSSRC()
	c.mu.Unlock()

	c.log.Debugf("[p2p] creating media channels (our audio ssrc=%d, peer audio ssrc=%d)", c.audioSSRC, peerAudioSSRC)

	sender, err := c.api.NewRTPSender(c.audioTrack, c.dtls)
	if err != nil {
		c.log.Warnf("[p2p] new audio sender: %v", err)
		return
	}
	if err := sender.Send(webrtc.RTPSendParameters{
		Encodings: []webrtc.RTPEncodingParameters{
			{RTPCodingParameters: webrtc.RTPCodingParameters{SSRC: webrtc.SSRC(c.audioSSRC), PayloadType: 111}},
		},
	}); err != nil {
		c.log.Warnf("[p2p] audio sender send: %v", err)
		return
	}
	c.mu.Lock()
	c.audioSender = sender
	c.mu.Unlock()
	go drainSenderRTCP(sender)

	if peerAudioSSRC != 0 {
		receiver, err := c.api.NewRTPReceiver(webrtc.RTPCodecTypeAudio, c.dtls)
		if err != nil {
			c.log.Warnf("[p2p] new audio receiver: %v", err)
		} else if err := receiver.Receive(webrtc.RTPReceiveParameters{
			Encodings: []webrtc.RTPDecodingParameters{
				{RTPCodingParameters: webrtc.RTPCodingParameters{SSRC: webrtc.SSRC(peerAudioSSRC)}},
			},
		}); err != nil {
			c.log.Warnf("[p2p] audio receiver receive: %v", err)
		} else {
			go drainReceiverRTCP(receiver)
			if c.onTrack != nil {
				c.onTrack(receiver.Track(), receiver)
			}
		}
	}

	vsender, err := c.api.NewRTPSender(c.videoTrack, c.dtls)
	if err != nil {
		c.log.Warnf("[p2p] new video sender: %v", err)
	} else if err := vsender.Send(webrtc.RTPSendParameters{
		Encodings: []webrtc.RTPEncodingParameters{
			{RTPCodingParameters: webrtc.RTPCodingParameters{SSRC: webrtc.SSRC(c.videoSSRC), PayloadType: 100}},
		},
	}); err != nil {
		c.log.Warnf("[p2p] video sender send: %v", err)
	} else {
		c.mu.Lock()
		c.videoSender = vsender
		c.mu.Unlock()
		go drainSenderRTCP(vsender)
	}

	peerVideoSSRC := c.negotiation.peerVideoSSRC()
	if peerVideoSSRC != 0 {
		vreceiver, err := c.api.NewRTPReceiver(webrtc.RTPCodecTypeVideo, c.dtls)
		if err != nil {
			c.log.Warnf("[p2p] new video receiver: %v", err)
		} else if err := vreceiver.Receive(webrtc.RTPReceiveParameters{
			Encodings: []webrtc.RTPDecodingParameters{
				{RTPCodingParameters: webrtc.RTPCodingParameters{SSRC: webrtc.SSRC(peerVideoSSRC)}},
			},
		}); err != nil {
			c.log.Warnf("[p2p] video receiver receive: %v", err)
		} else {
			go drainReceiverRTCP(vreceiver)
			if c.onTrack != nil {
				c.onTrack(vreceiver.Track(), vreceiver)
			}
		}
	}

	c.dispatcher.Start()
	c.sendMediaState()
}

func drainSenderRTCP(s *webrtc.RTPSender) {
	for {
		if _, _, err := s.ReadRTCP(); err != nil {
			return
		}
	}
}

func drainReceiverRTCP(r *webrtc.RTPReceiver) {
	for {
		if _, _, err := r.ReadRTCP(); err != nil {
			return
		}
	}
}

func (c *connection) sendMediaState() {
	msg := mediaState{
		Type:            typeMediaState,
		Muted:           false,
		LowBattery:      false,
		VideoState:      "active",
		VideoRotation:   0,
		ScreencastState: "inactive",
	}
	data, err := encodeSignaling(msg)
	if err != nil {
		c.log.Debugf("[p2p] encode media state: %v", err)
		return
	}
	c.log.Debugf("[p2p] -> MediaState videoState=active")
	c.emit(data)
}

func (c *connection) sendCandidate(cand *webrtc.ICECandidate) {
	line := cand.ToJSON().Candidate
	if line == "" {
		return
	}
	msg := candidatesMsg{
		Type:       typeCandidates,
		Candidates: []iceCandidate{{SdpString: line}},
	}
	data, err := encodeSignaling(msg)
	if err != nil {
		c.log.Debugf("[p2p] encode candidate: %v", err)
		return
	}
	c.emit(data)
}

func (c *connection) updateAggregateState() {
	c.mu.Lock()
	connected := c.iceConnected && c.dtlsConnected && !c.firedConnect
	if connected {
		c.firedConnect = true
		c.state = "connected"
	}
	fn := c.onConnected
	sc := c.onStateChange
	c.mu.Unlock()

	if connected {
		if sc != nil {
			sc("connected")
		}
		if fn != nil {
			fn()
		}
	}
}

func (c *connection) fireDisconnected() {
	c.mu.Lock()
	if c.firedDisconnect {
		c.mu.Unlock()
		return
	}
	c.firedDisconnect = true
	fn := c.onDisconnected
	c.state = "closed"
	c.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (c *connection) Dispatcher() *transport.Dispatcher { return c.dispatcher }

func (c *connection) AudioSSRC() uint32 { return c.audioSSRC }

func (c *connection) VideoSSRC() uint32 { return c.videoSSRC }

func (c *connection) State() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == "" {
		return "new"
	}
	return c.state
}

func (c *connection) close() error {
	c.mu.Lock()
	dispatcher := c.dispatcher
	dtls := c.dtls
	ice := c.iceTransport
	gatherer := c.gatherer
	c.mu.Unlock()

	if dispatcher != nil {
		dispatcher.Stop()
	}
	if dtls != nil {
		_ = dtls.Stop()
	}
	if ice != nil {
		_ = ice.Stop()
	}
	if gatherer != nil {
		_ = gatherer.Close()
	}
	return nil
}

func dtlsRoleFor(peerSetup string, isOutgoing bool) webrtc.DTLSRole {
	switch peerSetup {
	case "active":
		return webrtc.DTLSRoleClient
	case "passive":
		return webrtc.DTLSRoleServer
	default:
		if isOutgoing {
			return webrtc.DTLSRoleServer
		}
		return webrtc.DTLSRoleClient
	}
}

func peerSetup(msg *initialSetup) string {
	if len(msg.Fingerprints) > 0 && msg.Fingerprints[0].Setup != "" {
		return msg.Fingerprints[0].Setup
	}
	return "actpass"
}

func candidateAddrIsHostname(sdpString string) bool {
	fields := strings.Fields(strings.TrimPrefix(sdpString, "a="))
	if len(fields) < 5 {
		return false
	}
	return net.ParseIP(fields[4]) == nil
}

func randomSSRC() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	ssrc := uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	ssrc &= 0x7fffffff
	if ssrc == 0 {
		ssrc = 1
	}
	return ssrc
}

func iceServersFrom(conns []telegram.PhoneConnection) []webrtc.ICEServer {
	var servers []webrtc.ICEServer
	for _, conn := range conns {
		w, ok := conn.(*telegram.PhoneConnectionWebrtc)
		if !ok {
			continue
		}
		hosts := []string{}
		if w.Ip != "" {
			hosts = append(hosts, w.Ip)
		}
		if w.Ipv6 != "" {
			hosts = append(hosts, "["+w.Ipv6+"]")
		}
		for _, host := range hosts {
			addr := host + ":" + strconv.Itoa(int(w.Port))
			if w.Turn {
				servers = append(servers, webrtc.ICEServer{
					URLs:       []string{"turn:" + addr + "?transport=udp"},
					Username:   w.Username,
					Credential: w.Password,
				})
			}
			if w.Stun {
				servers = append(servers, webrtc.ICEServer{
					URLs: []string{"stun:" + addr},
				})
			}
		}
	}
	servers = append(servers,
		webrtc.ICEServer{URLs: []string{"stun:stun.l.google.com:19302"}},
		webrtc.ICEServer{URLs: []string{"stun:stun1.l.google.com:19302"}},
	)
	return servers
}
