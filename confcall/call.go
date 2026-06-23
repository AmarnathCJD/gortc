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
	"sort"
	"time"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/confcall/e2e"
	"github.com/amarnathcjd/gortc/media"
	"github.com/amarnathcjd/gortc/transport"
	wutil "github.com/amarnathcjd/gortc/webrtc"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

// Create creates a new conference call. If joinImmediately is true, the
// caller joins as the founder and the returned slug can be shared.
func (cc *ConferenceCall) Create(ctx context.Context, joinImmediately bool) (string, error) {
	cc.installHandlers()
	if err := cc.ensureSigner(); err != nil {
		return "", err
	}
	me, err := cc.initSession()
	if err != nil {
		return "", err
	}
	zero, err := e2e.BuildZeroBlock(cc.signer, me.ID)
	if err != nil {
		return "", fmt.Errorf("build zero block: %w", err)
	}
	if err := cc.chain.ApplyBlock(zero); err != nil {
		return "", fmt.Errorf("apply zero block: %w", err)
	}
	encoded, err := e2e.EncodeBlock(zero)
	if err != nil {
		return "", fmt.Errorf("encode zero block: %w", err)
	}

	params := &telegram.PhoneCreateConferenceCallParams{
		VideoStopped: true,
		Join:         joinImmediately,
		RandomID:     randomID(),
	}
	if joinImmediately {
		params.Block = encoded
		setInt256(&params.PublicKey, cc.pubKey)
		joinPayload, err := cc.openTransport()
		if err != nil {
			return "", err
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
	cc.applyUpdates(updates)

	if joinImmediately {
		if err := cc.unmuteSelf(); err != nil {
			cc.log.Warnf("[conf] unmute self: %v", err)
		}
		if err := cc.attachMediaFromUpdates(updates); err != nil {
			return slug, fmt.Errorf("attach media: %w", err)
		}
		cc.fetchParticipantSources()
	}
	return slug, nil
}

// Join joins an existing conference call by its public slug.
func (cc *ConferenceCall) Join(ctx context.Context, slug string) error {
	cc.slug = slug
	if err := cc.joinExisting(ctx, &telegram.InputGroupCallSlug{Slug: slug}, "slug"); err != nil {
		return err
	}
	cc.fetchParticipantSources()
	return nil
}

// JoinFromInvite joins via an incoming MessageActionConferenceCall message.
func (cc *ConferenceCall) JoinFromInvite(ctx context.Context, msgID int32) error {
	return cc.joinExisting(ctx, &telegram.InputGroupCallInviteMessage{MsgID: msgID}, "invite")
}

// joinExisting is the shared shape of Join and JoinFromInvite: set up the
// session, fetch the latest chain state, submit a self-add block, wait for the
// server echo, attach media, and kick verification.
func (cc *ConferenceCall) joinExisting(ctx context.Context, callInput telegram.InputGroupCall, label string) error {
	cc.installHandlers()
	if err := cc.ensureSigner(); err != nil {
		return err
	}
	me, err := cc.initSession()
	if err != nil {
		return err
	}
	joinPayload, err := cc.openTransport()
	if err != nil {
		return err
	}
	_, encodedBlock, err := cc.buildJoinBlock(callInput)
	if err != nil {
		return fmt.Errorf("build join block: %w", err)
	}
	beforeHeight := cc.chain.Height()
	params := &telegram.PhoneJoinGroupCallParams{
		Call:   callInput,
		JoinAs: &telegram.InputPeerUser{UserID: me.ID, AccessHash: me.AccessHash},
		Block:  encodedBlock,
		Params: &telegram.DataJson{Data: joinPayload},
	}
	setInt256(&params.PublicKey, cc.pubKey)
	updates, err := cc.client.PhoneJoinGroupCall(params)
	if err != nil {
		return fmt.Errorf("phone.joinGroupCall (%s): %w", label, err)
	}
	call, err := extractInputGroupCallFromUpdates(updates)
	if err != nil {
		return err
	}
	cc.call = call
	cc.applyUpdates(updates)
	if err := cc.waitForServerBlock(ctx, callInput, beforeHeight+1); err != nil {
		cc.log.Warnf("[conf] wait for server join block (%s): %v", label, err)
	}
	if err := cc.unmuteSelf(); err != nil {
		cc.log.Warnf("[conf] unmute self: %v", err)
	}
	if err := cc.attachMediaFromUpdates(updates); err != nil {
		return fmt.Errorf("attach media: %w", err)
	}
	cc.kickVerification()
	return nil
}

// initSession resolves self user, then sets up chain/cipher/verify. Returns
// the resolved user record.
func (cc *ConferenceCall) initSession() (*telegram.UserObj, error) {
	me, err := cc.client.GetMe()
	if err != nil {
		return nil, fmt.Errorf("get me: %w", err)
	}
	cc.selfUID = me.ID
	chain := e2e.NewChain(cc.signer)
	chain.SetSelfUserID(cc.selfUID)
	cc.chain = chain
	cc.cipher = e2e.NewPacketCipher(chain, cc.signer)
	cc.verify = e2e.NewVerificationChain(cc.signer, me.ID)
	return me, nil
}

// openTransport opens the GroupConnection, prepares local media tracks, and
// returns the WebRTC join payload (offer SDP wrapped in tdesktop's JSON shape).
func (cc *ConferenceCall) openTransport() (string, error) {
	conn := transport.NewGroupConnection(cc.log.With("subsystem", "transport"))
	cc.conn = conn
	if err := conn.Open(); err != nil {
		return "", fmt.Errorf("open conn: %w", err)
	}
	if err := cc.prepareLocalMedia(); err != nil {
		return "", err
	}
	payload, err := conn.GetJoinPayload()
	if err != nil {
		return "", fmt.Errorf("get join payload: %w", err)
	}
	return payload, nil
}

// kickVerification starts a commit-reveal round.
func (cc *ConferenceCall) kickVerification() {
	if err := cc.startVerificationRound(); err != nil {
		cc.log.Warnf("[conf] start verification round: %v", err)
	}
	cc.flushOutboundBroadcasts()
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

// Kick removes users from the call and broadcasts the resulting block.
func (cc *ConferenceCall) Kick(ctx context.Context, userIDs []int64) error {
	cc.mu.Lock()
	call := cc.call
	cc.mu.Unlock()
	if call == nil {
		return errors.New("confcall: not in a call")
	}
	state := cc.chain.Snapshot()
	kickSet := make(map[int64]struct{}, len(userIDs))
	for _, id := range userIDs {
		kickSet[id] = struct{}{}
	}
	keep := make([]e2e.GroupParticipant, 0, len(state.Participants))
	for _, p := range state.Participants {
		if _, ok := kickSet[p.UserID]; ok {
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
	if err := e2e.SignBlock(cc.signer, block); err != nil {
		return fmt.Errorf("sign block: %w", err)
	}
	encoded, err := e2e.EncodeBlock(block)
	if err != nil {
		return fmt.Errorf("encode block: %w", err)
	}
	if err := cc.chain.ApplyBlock(block); err != nil {
		return fmt.Errorf("apply local: %w", err)
	}
	_, err = cc.client.PhoneDeleteConferenceCallParticipants(&telegram.PhoneDeleteConferenceCallParticipantsParams{
		Kick:  true,
		Call:  call,
		Ids:   userIDs,
		Block: encoded,
	})
	return err
}

// RotateKey emits a fresh shared-key block. Run after any membership change.
func (cc *ConferenceCall) RotateKey(ctx context.Context) error {
	cc.mu.Lock()
	call := cc.call
	cc.mu.Unlock()
	if call == nil {
		return errors.New("confcall: not in a call")
	}
	state := cc.chain.Snapshot()
	parts := make([]e2e.GroupParticipant, 0, len(state.Participants))
	for _, p := range state.Participants {
		var pk [32]byte
		copy(pk[:], p.PublicKey)
		parts = append(parts, e2e.GroupParticipant{
			UserID:      p.UserID,
			PublicKey:   pk,
			AddUsers:    p.AddUsers,
			RemoveUsers: p.RemoveUsers,
			Version:     p.Version,
		})
	}
	sharedKey, err := e2e.BuildSharedKey(parts)
	if err != nil {
		return fmt.Errorf("build shared key: %w", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], cc.pubKey)
	block := &e2e.Block{
		Height:        state.Height + 1,
		PrevBlockHash: state.LastBlockHash,
		Changes: []e2e.Change{
			&e2e.ChangeSetGroupState{GroupState: e2e.GroupState{Participants: parts, ExternalPermissions: 3}},
			&e2e.ChangeSetSharedKey{SharedKey: sharedKey},
		},
		StateProof:         e2e.StateProof{KVHash: e2e.EmptyKVHash()},
		SignaturePublicKey: &pubArr,
	}
	if err := e2e.SignBlock(cc.signer, block); err != nil {
		return fmt.Errorf("sign block: %w", err)
	}
	encoded, err := e2e.EncodeBlock(block)
	if err != nil {
		return fmt.Errorf("encode block: %w", err)
	}

	beforeHeight := cc.chain.Height()
	updates, err := cc.client.PhoneSendConferenceCallBroadcast(call, encoded)
	if err != nil {
		return err
	}
	cc.applyUpdates(updates)
	if werr := cc.waitForServerBlock(context.Background(), call, beforeHeight+1); werr != nil {
		cc.log.Warnf("[conf] rotate-key wait: %v", werr)
	}
	return nil
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

func (cc *ConferenceCall) buildLeaveBlock(uid int64) ([]byte, error) {
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
	if err := e2e.SignBlock(cc.signer, block); err != nil {
		return nil, err
	}
	return e2e.EncodeBlockForServer(block)
}

func (cc *ConferenceCall) ensureSigner() error {
	if cc.signer != nil {
		return nil
	}
	var path string
	if home, err := os.UserHomeDir(); err == nil {
		path = home + "/.gortc_confcall_ed25519"
	}
	if path != "" {
		if seed, err := os.ReadFile(path); err == nil && len(seed) == ed25519.SeedSize {
			priv := ed25519.NewKeyFromSeed(seed)
			cc.signer = priv
			cc.pubKey = priv.Public().(ed25519.PublicKey)
			return nil
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("ed25519 gen: %w", err)
	}
	cc.signer = priv
	cc.pubKey = pub
	if path != "" {
		if err := os.WriteFile(path, priv.Seed(), 0600); err != nil {
			cc.log.Warnf("[conf] persist identity: %v", err)
		}
	}
	return nil
}

func (cc *ConferenceCall) prepareLocalMedia() error {
	cc.conn.OnConnected(func() {
		cc.conn.StartAudioRTCP()
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
	cc.conn.OnICEFailed(func() {
		if cc.OnICEFailed != nil {
			cc.OnICEFailed()
		}
	})
	if _, err := cc.conn.AddAudioTrack(); err != nil {
		return fmt.Errorf("add audio track: %w", err)
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
	var audioErrLogged bool
	d.SetAudioPayloadEncoder(func(p *wutil.RtpPacket) error {
		buf := make([]byte, 0, len(p.Payload)+2)
		buf = append(buf, p.Payload...)
		buf = append(buf, 0x01, 0x9f)
		enc, err := cc.cipher.EncryptPacket(0, buf, 0)
		if err != nil {
			if !audioErrLogged {
				cc.log.Warnf("[conf] audio encrypt: %v", err)
				audioErrLogged = true
			}
			return err
		}
		p.Payload = enc
		return nil
	})
}

func (cc *ConferenceCall) waitForServerBlock(ctx context.Context, call telegram.InputGroupCall, wantHeight int32) error {
	ready := func() bool {
		return cc.chain.Height() >= wantHeight && len(cc.chain.ActiveEpochs()) > 0
	}
	if ready() {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		updates, err := cc.client.PhoneGetGroupCallChainBlocks(call, 0, cc.chain.Height(), 10)
		if err != nil {
			return err
		}
		for _, b := range extractChainBlocks(updates) {
			block, derr := e2e.DecodeBlock(b)
			if derr != nil {
				continue
			}
			if block.Height <= cc.chain.Height() {
				continue
			}
			_ = cc.chain.ApplyBlock(block)
		}
		if ready() {
			return nil
		}
		select {
		case <-waitCtx.Done():
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("timed out waiting for chain height %d (have %d)", wantHeight, cc.chain.Height())
		case <-ticker.C:
		}
	}
}

func (cc *ConferenceCall) buildJoinBlock(call telegram.InputGroupCall) (*e2e.Block, []byte, error) {
	if err := cc.fetchLatestMainChain(call); err != nil {
		return nil, nil, fmt.Errorf("fetch latest chain: %w", err)
	}
	state := cc.chain.Snapshot()
	if len(state.Participants) == 0 {
		return nil, nil, errors.New("confcall: fetched empty chain state")
	}
	block, err := e2e.BuildSelfAddBlock(cc.signer, state, cc.selfUID)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := e2e.EncodeBlock(block)
	if err != nil {
		return nil, nil, err
	}
	return block, encoded, nil
}

func (cc *ConferenceCall) fetchLatestMainChain(call telegram.InputGroupCall) error {
	updates, err := cc.client.PhoneGetGroupCallChainBlocks(call, 0, -1, 32)
	if err != nil {
		return err
	}
	raw := extractChainBlocks(updates)
	if len(raw) == 0 {
		return errors.New("confcall: server returned no chain blocks")
	}
	parsed := make([]*e2e.Block, 0, len(raw))
	for _, b := range raw {
		if block, derr := e2e.DecodeBlock(b); derr == nil {
			parsed = append(parsed, block)
		}
	}
	if len(parsed) == 0 {
		return errors.New("confcall: failed to decode any chain blocks")
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].Height > parsed[j].Height })
	hasGroupState := func(b *e2e.Block) bool {
		for _, ch := range b.Changes {
			if _, ok := ch.(*e2e.ChangeSetGroupState); ok {
				return true
			}
		}
		return false
	}
	var chosen *e2e.Block
	for _, b := range parsed {
		if hasGroupState(b) {
			chosen = b
			break
		}
	}
	if chosen == nil {
		chosen = parsed[0]
		cc.log.Warnf("[conf] no recent block carries GroupState; bootstrapping from h=%d", chosen.Height)
	}
	return cc.chain.BootstrapFromBlock(chosen)
}

func extractChainBlocks(updates telegram.Updates) [][]byte {
	obj, ok := updates.(*telegram.UpdatesObj)
	if !ok {
		return nil
	}
	var out [][]byte
	for _, u := range obj.Updates {
		if cb, ok := u.(*telegram.UpdateGroupCallChainBlocks); ok {
			out = append(out, cb.Blocks...)
		}
	}
	return out
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
		return call.InviteLink, &telegram.InputGroupCallObj{ID: call.ID, AccessHash: call.AccessHash}, nil
	}
	return "", nil, errors.New("confcall: no UpdateGroupCall in updates")
}

func extractInputGroupCallFromUpdates(updates telegram.Updates) (*telegram.InputGroupCallObj, error) {
	_, call, err := extractConferenceFromUpdates(updates)
	return call, err
}

func (cc *ConferenceCall) unmuteSelf() error {
	cc.mu.Lock()
	call := cc.call
	cc.mu.Unlock()
	if call == nil {
		return errors.New("confcall: not in a call")
	}
	_, err := cc.client.PhoneEditGroupCallParticipant(&telegram.PhoneEditGroupCallParticipantParams{
		Call:        call,
		Participant: &telegram.InputPeerSelf{},
		Muted:       false,
	})
	return err
}

func randomID() int32 {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return int32(binary.LittleEndian.Uint32(buf[:]) & 0x7fffffff)
}

func setInt256(dst any, value []byte) {
	v := reflect.ValueOf(dst).Elem()
	if v.Kind() != reflect.Pointer {
		return
	}
	elemType := v.Type().Elem()
	if elemType.Kind() != reflect.Struct || elemType.NumField() != 1 {
		return
	}
	inner := elemType.Field(0).Type
	if inner.Kind() != reflect.Pointer || inner.Elem() != reflect.TypeOf(big.Int{}) {
		return
	}
	newVal := reflect.New(elemType)
	newVal.Elem().Field(0).Set(reflect.ValueOf(new(big.Int).SetBytes(value)))
	v.Set(newVal)
}
