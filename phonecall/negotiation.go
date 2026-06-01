// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package phonecall

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
)

const (
	typeInitialSetup = "InitialSetup"
	typeCandidates   = "Candidates"
	typeMediaState   = "MediaState"
)

type signalingFingerprint struct {
	Hash        string `json:"hash"`
	Setup       string `json:"setup"`
	Fingerprint string `json:"fingerprint"`
}

type signalingFeedback struct {
	Type    string `json:"type"`
	Subtype string `json:"subtype"`
}

type signalingPayloadType struct {
	ID            int                 `json:"id"`
	Name          string              `json:"name"`
	Clockrate     int                 `json:"clockrate"`
	Channels      int                 `json:"channels,omitempty"`
	FeedbackTypes []signalingFeedback `json:"feedbackTypes,omitempty"`
	Parameters    map[string]string   `json:"parameters,omitempty"`
}

type signalingSsrcGroup struct {
	Semantics string   `json:"semantics"`
	Ssrcs     []string `json:"ssrcs"`
}

type signalingExtension struct {
	ID  int    `json:"id"`
	URI string `json:"uri"`
}

type signalingMediaContent struct {
	Ssrc          string                 `json:"ssrc"`
	SsrcGroups    []signalingSsrcGroup   `json:"ssrcGroups,omitempty"`
	PayloadTypes  []signalingPayloadType `json:"payloadTypes"`
	RtpExtensions []signalingExtension   `json:"rtpExtensions,omitempty"`
}

type initialSetup struct {
	Type         string                 `json:"@type"`
	Ufrag        string                 `json:"ufrag"`
	Pwd          string                 `json:"pwd"`
	Renomination bool                   `json:"renomination"`
	Fingerprints []signalingFingerprint `json:"fingerprints"`
	Audio        *signalingMediaContent `json:"audio,omitempty"`
	Video        *signalingMediaContent `json:"video,omitempty"`
}

type iceCandidate struct {
	SdpString string `json:"sdpString"`
}

type candidatesMsg struct {
	Type       string         `json:"@type"`
	Candidates []iceCandidate `json:"candidates"`
}

type mediaState struct {
	Type            string `json:"@type"`
	Muted           bool   `json:"muted"`
	LowBattery      bool   `json:"lowBattery"`
	VideoState      string `json:"videoState"`
	VideoRotation   int    `json:"videoRotation"`
	ScreencastState string `json:"screencastState"`
}

type signalingEnvelope struct {
	Type string `json:"@type"`
}

const typeNegotiateChannels = "NegotiateChannels"

type negotiateContent struct {
	Type          string                 `json:"type"`
	Ssrc          string                 `json:"ssrc"`
	SsrcGroups    []signalingSsrcGroup   `json:"ssrcGroups,omitempty"`
	PayloadTypes  []signalingPayloadType `json:"payloadTypes"`
	RtpExtensions []signalingExtension   `json:"rtpExtensions,omitempty"`
}

type negotiateChannels struct {
	Type       string             `json:"@type"`
	ExchangeID string             `json:"exchangeId"`
	Contents   []negotiateContent `json:"contents"`
}

type negotiator struct {
	isOutgoing bool

	localExchangeID string
	offered         bool
	answered        bool

	peerAudio uint32
	peerVideo uint32
}

func newNegotiator(isOutgoing bool) *negotiator {
	return &negotiator{isOutgoing: isOutgoing}
}

func (n *negotiator) peerAudioSSRC() uint32 { return n.peerAudio }

func (n *negotiator) peerVideoSSRC() uint32 { return n.peerVideo }

func (n *negotiator) localOffer(audioSSRC, videoSSRC uint32) *negotiateChannels {
	if n.offered {
		return nil
	}
	n.offered = true
	n.localExchangeID = randomExchangeID()
	return &negotiateChannels{
		Type:       typeNegotiateChannels,
		ExchangeID: n.localExchangeID,
		Contents:   []negotiateContent{audioContent(audioSSRC), videoContent(videoSSRC)},
	}
}

func (n *negotiator) onRemote(msg *negotiateChannels, audioSSRC, videoSSRC uint32) (reply *negotiateChannels, ready bool) {
	n.captureSSRCs(msg)

	if n.offered && msg.ExchangeID == n.localExchangeID {
		n.answered = true
		return nil, true
	}

	answer := &negotiateChannels{
		Type:       typeNegotiateChannels,
		ExchangeID: msg.ExchangeID,
		Contents:   []negotiateContent{audioContent(audioSSRC), videoContent(videoSSRC)},
	}
	return answer, true
}

func (n *negotiator) captureSSRCs(msg *negotiateChannels) {
	for _, content := range msg.Contents {
		ssrc := parseSSRC(content.Ssrc)
		if ssrc == 0 {
			continue
		}
		switch content.Type {
		case "audio":
			if n.peerAudio == 0 {
				n.peerAudio = ssrc
			}
		case "video":
			if n.peerVideo == 0 {
				n.peerVideo = ssrc
			}
		}
	}
}

func decodeSignalingType(data []byte) (string, error) {
	var env signalingEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return "", fmt.Errorf("decode signaling envelope: %w", err)
	}
	if env.Type == "" {
		return "", fmt.Errorf("signaling message missing @type")
	}
	return env.Type, nil
}

func encodeSignaling(v any) ([]byte, error) {
	return json.Marshal(v)
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}


func audioContent(ssrc uint32) negotiateContent {
	return negotiateContent{
		Type: "audio",
		Ssrc: strconv.FormatUint(uint64(ssrc), 10),
		PayloadTypes: []signalingPayloadType{
			{
				ID: 111, Name: "opus", Clockrate: 48000, Channels: 2,
				FeedbackTypes: []signalingFeedback{{Type: "transport-cc"}},
				Parameters: map[string]string{
					"minptime": "10", "useinbandfec": "1",
				},
			},
		},
		RtpExtensions: []signalingExtension{
			{ID: 2, URI: "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"},
			{ID: 3, URI: "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"},
		},
	}
}

func videoContent(ssrc uint32) negotiateContent {
	return negotiateContent{
		Type: "video",
		Ssrc: strconv.FormatUint(uint64(ssrc), 10),
		SsrcGroups: []signalingSsrcGroup{
			{Semantics: "FID", Ssrcs: []string{
				strconv.FormatUint(uint64(ssrc), 10),
				strconv.FormatUint(uint64(ssrc+1), 10),
			}},
		},
		PayloadTypes: []signalingPayloadType{
			{
				ID: 100, Name: "VP8", Clockrate: 90000,
				FeedbackTypes: []signalingFeedback{
					{Type: "goog-remb"}, {Type: "transport-cc"},
					{Type: "ccm", Subtype: "fir"},
					{Type: "nack"}, {Type: "nack", Subtype: "pli"},
				},
			},
		},
		RtpExtensions: []signalingExtension{
			{ID: 2, URI: "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"},
			{ID: 3, URI: "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"},
		},
	}
}

func parseSSRC(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

func randomExchangeID() string {
	var buf [4]byte
	rand.Read(buf[:])
	id := binary.BigEndian.Uint32(buf[:]) & 0x7fffffff
	if id == 0 {
		id = 1
	}
	return strconv.FormatUint(uint64(id), 10)
}
