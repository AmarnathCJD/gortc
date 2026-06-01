// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package phonecall

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/amarnathcjd/gortc/webrtc/webrtc"

	"github.com/amarnathcjd/gogram/telegram"
)

type IncomingCall struct {
	pc  *PhoneCall
	req *telegram.PhoneCallRequested
}

func (ic *IncomingCall) UserID() int64 { return ic.req.AdminID }

func (ic *IncomingCall) Video() bool { return ic.req.Video }

func (ic *IncomingCall) Reject() error {
	pc := ic.pc
	pc.mu.Lock()
	pc.call = &telegram.InputPhoneCall{ID: ic.req.ID, AccessHash: ic.req.AccessHash}
	pc.mu.Unlock()
	return pc.discard(&telegram.PhoneCallDiscardReasonBusy{})
}

func (ic *IncomingCall) Accept(ctx context.Context) error {
	pc := ic.pc
	pc.resetForNewCall()

	if p := ic.req.Protocol; p != nil {
		pc.log.Debugf("[p2p] caller protocol: min_layer=%d max_layer=%d udp_p2p=%v udp_reflector=%v versions=%v",
			p.MinLayer, p.MaxLayer, p.UdpP2P, p.UdpReflector, p.LibraryVersions)
	}

	dh, err := getDH(pc.client)
	if err != nil {
		return err
	}
	b, gB, err := dh.genGB()
	if err != nil {
		return err
	}

	call := &telegram.InputPhoneCall{ID: ic.req.ID, AccessHash: ic.req.AccessHash}

	pc.mu.Lock()
	pc.dh = dh
	pc.secret = b
	pc.gAHash = ic.req.GAHash
	pc.isCaller = false
	pc.call = call
	pc.mu.Unlock()

	proto := acceptProtocol(ic.req.Protocol)
	pc.log.Debugf("[p2p] accepting with protocol: min_layer=%d max_layer=%d versions=%v",
		proto.MinLayer, proto.MaxLayer, proto.LibraryVersions)
	if _, err := pc.client.PhoneAcceptCall(call, gB, proto); err != nil {
		return fmt.Errorf("accept call: %w", err)
	}

	var obj *telegram.PhoneCallObj
	select {
	case obj = <-pc.confirmed:
	case d := <-pc.discarded:
		return discardError(d)
	case <-ctx.Done():
		return ctx.Err()
	}

	if err := verifyCommitment(obj.GAOrB, ic.req.GAHash); err != nil {
		return err
	}
	key, _, err := dh.computeKey(obj.GAOrB, b)
	if err != nil {
		return err
	}

	pc.mu.Lock()
	pc.call = &telegram.InputPhoneCall{ID: obj.ID, AccessHash: obj.AccessHash}
	pc.mu.Unlock()

	return pc.startCall(ctx, key, false, obj.Connections)
}

func (pc *PhoneCall) OnTrack(fn func(TrackKind)) { pc.onTrack = fn }

func randomID() int32 {
	var buf [4]byte
	rand.Read(buf[:])
	return int32(binary.LittleEndian.Uint32(buf[:]) & 0x7fffffff)
}

func trackKindOf(t *webrtc.TrackRemote) TrackKind {
	if t.Kind() == webrtc.RTPCodecTypeVideo {
		return TrackVideo
	}
	return TrackAudio
}
