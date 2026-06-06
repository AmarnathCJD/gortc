// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package confcall

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/confcall/e2e"
	"github.com/amarnathcjd/gortc/media"
	"github.com/amarnathcjd/gortc/transport"
	wutil "github.com/amarnathcjd/gortc/webrtc"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

// Create creates a new conference call. If joinImmediately is true, the
// caller also joins as the founder and the returned slug can be shared
// with peers.
func (cc *ConferenceCall) Create(ctx context.Context, joinImmediately bool) (string, error) {
	cc.installHandlers()

	if err := cc.ensureSigner(); err != nil {
		return "", err
	}
	me, err := cc.client.GetMe()
	if err != nil {
		return "", fmt.Errorf("get me: %w", err)
	}
	cc.selfUID = me.ID
	chain := e2e.NewChain(cc.signer)
	chain.SetSelfUserID(cc.selfUID)
	zero, err := e2e.BuildZeroBlock(cc.signer, me.ID)
	if err != nil {
		return "", fmt.Errorf("build zero block: %w", err)
	}
	if err := chain.ApplyBlock(zero); err != nil {
		return "", fmt.Errorf("apply zero block: %w", err)
	}
	cc.chain = chain
	cc.cipher = e2e.NewPacketCipher(chain, cc.signer)
	cc.verify = e2e.NewVerificationChain(cc.signer, me.ID)
	// Kick off the first verification round against the zero block.
	if err := cc.startVerificationRound(); err != nil {
		cc.log.Warnf("[conf] start verification round: %v", err)
	}

	// CONFCALL_NOOP_BLOCK=1 sends a deliberately-invalid noop-only block to
	// distinguish parser issues (server -504) from validation issues (400
	// BLOCK_INVALID). Useful while debugging createConferenceCall failures.
	blockSource := zero
	if os.Getenv("CONFCALL_NOOP_BLOCK") == "1" {
		noop, err := e2e.BuildNoopBlock(cc.signer)
		if err != nil {
			return "", fmt.Errorf("build noop block: %w", err)
		}
		blockSource = noop
	}
	encoded, err := e2e.EncodeBlock(blockSource)
	if err != nil {
		return "", fmt.Errorf("encode zero block: %w", err)
	}

	// public_key/block/params are flags.3 fields — only sent when join is set.
	// muted/video_stopped match TDLib defaults for a fresh join with no AV yet.
	params := &telegram.PhoneCreateConferenceCallParams{
		Muted:        true,
		VideoStopped: true,
		Join:         joinImmediately,
		RandomID:     randomID(),
	}
	if joinImmediately {
		params.Block = encoded
		setInt256(&params.PublicKey, cc.pubKey)
		conn := transport.NewGroupConnection(cc.log.With("subsystem", "transport"))
		cc.conn = conn
		if err := conn.Open(); err != nil {
			return "", fmt.Errorf("open conn: %w", err)
		}
		if err := cc.prepareLocalMedia(); err != nil {
			return "", err
		}
		joinPayload, err := conn.GetJoinPayload()
		if err != nil {
			return "", fmt.Errorf("get join payload: %w", err)
		}
		params.Params = &telegram.DataJson{Data: joinPayload}
	}

	updates, err := cc.client.PhoneCreateConferenceCall(params)
	if err != nil {
		return "", fmt.Errorf("phone.createConferenceCall: %w", err)
	}

	slug, callObj, err := extractConferenceFromUpdates(updates)
	if err != nil {
		return "", err
	}
	cc.slug = slug
	cc.call = callObj

	// The first verification round was kicked off before the call
	// existed, so its outbound commit hasn't been shipped yet. Flush
	// now that we have a callObj.
	cc.flushOutboundBroadcasts()

	if joinImmediately {
		if err := cc.attachMediaFromUpdates(updates); err != nil {
			return slug, fmt.Errorf("attach media: %w", err)
		}
	}
	return slug, nil
}

// Join joins an existing conference call by its public slug.
func (cc *ConferenceCall) Join(ctx context.Context, slug string) error {
	cc.installHandlers()
	if err := cc.ensureSigner(); err != nil {
		return err
	}
	cc.slug = slug

	me, err := cc.client.GetMe()
	if err != nil {
		return fmt.Errorf("get me: %w", err)
	}
	cc.selfUID = me.ID
	chain := e2e.NewChain(cc.signer)
	chain.SetSelfUserID(cc.selfUID)
	cc.chain = chain
	cc.cipher = e2e.NewPacketCipher(chain, cc.signer)
	cc.verify = e2e.NewVerificationChain(cc.signer, me.ID)

	conn := transport.NewGroupConnection(cc.log.With("subsystem", "transport"))
	cc.conn = conn
	if err := conn.Open(); err != nil {
		return fmt.Errorf("open conn: %w", err)
	}
	if err := cc.prepareLocalMedia(); err != nil {
		return err
	}
	joinPayload, err := conn.GetJoinPayload()
	if err != nil {
		return fmt.Errorf("get join payload: %w", err)
	}
	updates, err := cc.client.PhoneJoinGroupCall(&telegram.PhoneJoinGroupCallParams{
		Call:   &telegram.InputGroupCallSlug{Slug: slug},
		JoinAs: &telegram.InputPeerUser{UserID: me.ID, AccessHash: me.AccessHash},
		Params: &telegram.DataJson{Data: joinPayload},
	})
	if err != nil {
		return fmt.Errorf("phone.joinGroupCall: %w", err)
	}
	if err := cc.attachMediaFromUpdates(updates); err != nil {
		return fmt.Errorf("attach media: %w", err)
	}
	return nil
}

// JoinFromInvite joins via an incoming MessageActionConferenceCall message.
func (cc *ConferenceCall) JoinFromInvite(ctx context.Context, msgID int32) error {
	cc.installHandlers()
	if err := cc.ensureSigner(); err != nil {
		return err
	}
	me, err := cc.client.GetMe()
	if err != nil {
		return fmt.Errorf("get me: %w", err)
	}
	cc.selfUID = me.ID
	chain := e2e.NewChain(cc.signer)
	chain.SetSelfUserID(cc.selfUID)
	cc.chain = chain
	cc.cipher = e2e.NewPacketCipher(chain, cc.signer)

	conn := transport.NewGroupConnection(cc.log.With("subsystem", "transport"))
	cc.conn = conn
	if err := conn.Open(); err != nil {
		return fmt.Errorf("open conn: %w", err)
	}
	if err := cc.prepareLocalMedia(); err != nil {
		return err
	}
	joinPayload, err := conn.GetJoinPayload()
	if err != nil {
		return fmt.Errorf("get join payload: %w", err)
	}
	updates, err := cc.client.PhoneJoinGroupCall(&telegram.PhoneJoinGroupCallParams{
		Call:   &telegram.InputGroupCallInviteMessage{MsgID: msgID},
		JoinAs: &telegram.InputPeerUser{UserID: me.ID, AccessHash: me.AccessHash},
		Params: &telegram.DataJson{Data: joinPayload},
	})
	if err != nil {
		return fmt.Errorf("phone.joinGroupCall (invite): %w", err)
	}
	return cc.attachMediaFromUpdates(updates)
}

// Invite sends a ring to the specified user.
func (cc *ConferenceCall) Invite(ctx context.Context, userID any, video bool) error {
	cc.mu.Lock()
	call := cc.call
	cc.mu.Unlock()
	if call == nil {
		return errors.New("confcall: not in a call")
	}
	user, err := cc.client.GetSendableUser(userID)
	if err != nil {
		return fmt.Errorf("resolve user: %w", err)
	}
	_, err = cc.client.PhoneInviteConferenceCallParticipant(video, call, user)
	return err
}

// Decline declines an incoming MessageActionConferenceCall by message id.
func (cc *ConferenceCall) Decline(_ context.Context, msgID int32) error {
	_, err := cc.client.PhoneDeclineConferenceCallInvite(msgID)
	return err
}

// Leave self-removes from the call.
func (cc *ConferenceCall) Leave(ctx context.Context) error {
	cc.mu.Lock()
	call := cc.call
	conn := cc.conn
	cc.call = nil
	cc.conn = nil
	cc.mu.Unlock()

	var firstErr error
	if call != nil {
		me, err := cc.client.GetMe()
		if err == nil {
			block, _ := cc.buildLeaveBlock(me.ID)
			_, err = cc.client.PhoneDeleteConferenceCallParticipants(&telegram.PhoneDeleteConferenceCallParticipantsParams{
				OnlyLeft: true,
				Call:     call,
				Ids:      []int64{me.ID},
				Block:    block,
			})
			if err != nil {
				firstErr = err
			}
		}
	}
	if conn != nil {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (cc *ConferenceCall) buildLeaveBlock(uid int64) ([]byte, error) {
	// A real leave block updates the GroupState minus self. For the
	// stub, emit an empty noop — Telegram accepts any well-formed block.
	state := cc.chain.Snapshot()
	keep := make([]e2e.GroupParticipant, 0, len(state.Participants))
	for _, p := range state.Participants {
		if p.UserID == uid {
			continue
		}
		var pk [32]byte
		copy(pk[:], p.PublicKey)
		keep = append(keep, e2e.GroupParticipant{
			UserID:      p.UserID,
			PublicKey:   pk,
			AddUsers:    p.AddUsers,
			RemoveUsers: p.RemoveUsers,
			Version:     p.Version,
		})
	}
	block := &e2e.Block{
		Height:        state.Height + 1,
		PrevBlockHash: state.LastBlockHash,
		Changes:       []e2e.Change{&e2e.ChangeSetGroupState{GroupState: e2e.GroupState{Participants: keep}}},
	}
	signedBody, err := e2e.EncodeBlockForSignature(block)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(cc.signer, signedBody)
	copy(block.Signature[:], sig)
	return e2e.EncodeBlock(block)
}

// Stream sends a media source into the call, blocking until it ends or ctx is cancelled.
func (cc *ConferenceCall) Stream(ctx context.Context, src media.Source) error {
	if cc.conn == nil {
		return errors.New("confcall: not in a call")
	}
	err := media.Stream(ctx, cc.conn.Dispatcher(), cc.conn.OutgoingAudioSsrc(), cc.conn.OutgoingVideoSsrc(), src)
	if cc.OnStreamEnded != nil {
		cc.OnStreamEnded(err)
	}
	return err
}

// Play starts a media source and returns a controllable Player.
func (cc *ConferenceCall) Play(ctx context.Context, src media.Source) *media.Player {
	p := media.Play(ctx, cc.conn.Dispatcher(), cc.conn.OutgoingAudioSsrc(), cc.conn.OutgoingVideoSsrc(), src)
	if cc.OnStreamEnded != nil {
		go func() { cc.OnStreamEnded(<-p.Done()) }()
	}
	return p
}

// ── helpers ────────────────────────────────────────────────────────────

func (cc *ConferenceCall) ensureSigner() error {
	if cc.signer != nil {
		return nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ed25519 gen: %w", err)
	}
	cc.signer = priv
	cc.pubKey = pub
	return nil
}

func (cc *ConferenceCall) prepareLocalMedia() error {
	cc.conn.OnConnected(func() {
		if cc.OnConnected != nil {
			cc.OnConnected()
		}
	})
	cc.conn.OnDisconnected(func() {
		if cc.OnDisconnected != nil {
			cc.OnDisconnected()
		}
	})
	cc.conn.OnStateChange(func(s string) {
		if cc.OnStateChange != nil {
			cc.OnStateChange(s)
		}
	})
	if _, err := cc.conn.AddAudioTrack(); err != nil {
		return fmt.Errorf("add audio track: %w", err)
	}
	if _, err := cc.conn.AddVideoTrack(""); err != nil {
		return fmt.Errorf("add video track: %w", err)
	}
	cc.attachCipherToDispatcher()
	cc.conn.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if cc.OnTrack != nil {
			cc.OnTrack(media.NewIncomingTrack(track))
		}
	})
	return nil
}

func (cc *ConferenceCall) attachMediaFromUpdates(updates telegram.Updates) error {
	resp, err := extractConnectionParams(updates)
	if err != nil {
		return err
	}
	return cc.conn.Connect(resp)
}

func (cc *ConferenceCall) attachCipherToDispatcher() {
	if cc.cipher == nil || cc.conn == nil {
		return
	}
	d := cc.conn.Dispatcher()
	if d == nil {
		return
	}

	d.SetAudioPayloadEncoder(func(p *wutil.RtpPacket) error {
		buf := make([]byte, 0, len(p.Payload)+2)
		buf = append(buf, p.Payload...)
		buf = append(buf, 0x01, 0x00)
		enc, err := cc.cipher.EncryptPacket(0, buf, 0)
		if err != nil {
			return err
		}
		p.Payload = enc
		return nil
	})
	d.SetVideoPayloadEncoder(func(p *wutil.RtpPacket) error {
		enc, err := cc.cipher.EncryptPacket(0, p.Payload, 0)
		if err != nil {
			return err
		}
		p.Payload = enc
		return nil
	})
}

func extractConnectionParams(updates telegram.Updates) (string, error) {
	obj, ok := updates.(*telegram.UpdatesObj)
	if !ok {
		return "", fmt.Errorf("unexpected updates type %T", updates)
	}
	for _, u := range obj.Updates {
		if conn, ok := u.(*telegram.UpdateGroupCallConnection); ok && conn.Params != nil {
			return conn.Params.Data, nil
		}
	}
	return "", errors.New("no UpdateGroupCallConnection in response")
}

func extractConferenceFromUpdates(updates telegram.Updates) (string, *telegram.InputGroupCallObj, error) {
	obj, ok := updates.(*telegram.UpdatesObj)
	if !ok {
		return "", nil, fmt.Errorf("unexpected updates type %T", updates)
	}
	for _, u := range obj.Updates {
		gc, ok := u.(*telegram.UpdateGroupCall)
		if !ok {
			continue
		}
		call, ok := gc.Call.(*telegram.GroupCallObj)
		if !ok {
			continue
		}
		input := &telegram.InputGroupCallObj{ID: call.ID, AccessHash: call.AccessHash}
		return call.InviteLink, input, nil
	}
	return "", nil, errors.New("confcall: no UpdateGroupCall in updates")
}

func randomID() int32 {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return int32(binary.LittleEndian.Uint32(buf[:]) & 0x7fffffff)
}

// setInt256 writes a big-endian byte value into a gogram **tl.Int256
// field. tl.Int256 is an internal struct{*big.Int} that gogram does not
// re-export, so we allocate it via reflection on the field's element type.
func setInt256(dst any, value []byte) {
	v := reflect.ValueOf(dst).Elem() // *tl.Int256
	if v.Kind() != reflect.Pointer {
		return
	}
	elemType := v.Type().Elem() // tl.Int256
	if elemType.Kind() != reflect.Struct || elemType.NumField() != 1 {
		return
	}
	inner := elemType.Field(0).Type
	if inner.Kind() != reflect.Pointer || inner.Elem() != reflect.TypeOf(big.Int{}) {
		return
	}
	newVal := reflect.New(elemType)         // *tl.Int256
	newVal.Elem().Field(0).Set(reflect.ValueOf(new(big.Int).SetBytes(value)))
	v.Set(newVal)
}
