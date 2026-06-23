// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package confcall

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/confcall/e2e"
)

func (cc *ConferenceCall) installHandlers() {
	cc.handlersOnce.Do(func() {
		cc.client.OnRaw(&telegram.UpdateNewMessage{}, func(u telegram.Update, _ *telegram.Client) error {
			upd, ok := u.(*telegram.UpdateNewMessage)
			if !ok {
				return nil
			}
			msg, ok := upd.Message.(*telegram.MessageService)
			if !ok {
				return nil
			}
			act, ok := msg.Action.(*telegram.MessageActionConferenceCall)
			if !ok {
				return nil
			}
			if act.Missed || act.Active {
				return nil
			}
			if cc.OnIncomingConferenceCall != nil {
				cc.OnIncomingConferenceCall(&IncomingConferenceCall{
					cc:     cc,
					msgID:  msg.ID,
					callID: act.CallID,
					video:  act.Video,
				})
			}
			return nil
		})

		cc.client.OnRaw(&telegram.UpdateGroupCallChainBlocks{}, func(u telegram.Update, _ *telegram.Client) error {
			if upd, ok := u.(*telegram.UpdateGroupCallChainBlocks); ok {
				cc.applyIncomingChainUpdate(upd)
			}
			return nil
		})

		cc.client.OnRaw(&telegram.UpdateGroupCallParticipants{}, func(u telegram.Update, _ *telegram.Client) error {
			if upd, ok := u.(*telegram.UpdateGroupCallParticipants); ok {
				cc.recordParticipantSources(upd.Participants)
			}
			return nil
		})
	})
}

// recordParticipantSources updates the SSRC->user_id mapping needed to look
// up the sender's public key for incoming audio.
func (cc *ConferenceCall) recordParticipantSources(parts []*telegram.GroupCallParticipant) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.sourceToUID == nil {
		cc.sourceToUID = make(map[int32]int64)
	}
	for _, p := range parts {
		if uid := peerUserID(p.Peer); uid != 0 && p.Source != 0 {
			cc.sourceToUID[p.Source] = uid
		}
	}
}

// fetchParticipantSources pulls the participant list from the server. Push
// UpdateGroupCallParticipants are unreliable for self right after join.
func (cc *ConferenceCall) fetchParticipantSources() {
	cc.mu.Lock()
	call := cc.call
	cc.mu.Unlock()
	if call == nil {
		return
	}
	resp, err := cc.client.PhoneGetGroupCall(call, 100)
	if err != nil {
		cc.log.Warnf("[conf] getGroupCall: %v", err)
		return
	}
	cc.recordParticipantSources(resp.Participants)
}

func peerUserID(p telegram.Peer) int64 {
	switch v := p.(type) {
	case *telegram.PeerUser:
		return v.UserID
	case *telegram.PeerChat:
		return v.ChatID
	case *telegram.PeerChannel:
		return v.ChannelID
	default:
		return 0
	}
}

func (cc *ConferenceCall) applyUpdates(updates telegram.Updates) {
	switch u := updates.(type) {
	case *telegram.UpdatesObj:
		for _, upd := range u.Updates {
			cc.applyUpdate(upd)
		}
	case *telegram.UpdatesCombined:
		for _, upd := range u.Updates {
			cc.applyUpdate(upd)
		}
	case *telegram.UpdateShort:
		cc.applyUpdate(u.Update)
	}
}

func (cc *ConferenceCall) applyUpdate(upd telegram.Update) {
	switch v := upd.(type) {
	case *telegram.UpdateGroupCallChainBlocks:
		cc.applyIncomingChainUpdate(v)
	case *telegram.UpdateGroupCallParticipants:
		cc.recordParticipantSources(v.Participants)
	}
}

func (cc *ConferenceCall) applyIncomingChainUpdate(upd *telegram.UpdateGroupCallChainBlocks) {
	cc.applyIncomingBlocks(upd.Blocks)
}

func (cc *ConferenceCall) applyIncomingBlocks(blocks [][]byte) {
	if cc.chain == nil {
		return
	}
	chainAdvanced := false
	for _, raw := range blocks {
		// updateGroupCallChainBlocks muxes chain blocks AND verification
		// broadcasts (NonceCommit/NonceReveal). Route each by magic.
		if e2e.IsNonceCommit(raw) || e2e.IsNonceReveal(raw) {
			if cc.verify == nil {
				continue
			}
			if err := cc.verify.ReceiveBroadcast(raw); err != nil {
				cc.log.Warnf("[conf] apply broadcast: %v", err)
			} else if hash := cc.verify.EmojiHash(); len(hash) > 0 {
				emojis := e2e.EmojisFromHash(hash)
				key := fmt.Sprint(emojis)
				if key != cc.lastEmojis {
					cc.lastEmojis = key
					if cc.OnEmojiReady != nil {
						cc.OnEmojiReady(emojis)
					}
				}
			}
			// Flush immediately: processing a commit may have produced our
			// reveal. Deferring until end-of-batch can let a chain advance
			// reset the round and drop the unsent reveal.
			cc.flushOutboundBroadcasts()
			continue
		}
		block, err := e2e.DecodeBlock(raw)
		if err != nil {
			cc.log.Warnf("[conf] decode block: %v", err)
			continue
		}
		if err := cc.chain.ApplyBlock(block); err != nil {
			cc.log.Warnf("[conf] apply block: %v", err)
			continue
		}
		if skErr := cc.chain.LastSharedKeyErr(); skErr != nil {
			cc.log.Warnf("[conf] shared-key recover (h=%d): %v", cc.chain.Height(), skErr)
			cc.reestablishKeyIfExcluded()
		}
		chainAdvanced = true
		if cc.OnBlockApplied != nil {
			cc.OnBlockApplied(int(cc.chain.Height()))
		}
	}
	if chainAdvanced {
		if err := cc.startVerificationRound(); err != nil {
			cc.log.Warnf("[conf] start verification round: %v", err)
		}
	}
	cc.flushOutboundBroadcasts()
}

// reestablishKeyIfExcluded re-keys when we're in the current GroupState but
// the latest shared key wasn't encrypted for us (peer rekeyed from a stale
// view during the join handoff). Without this we stay one epoch behind
// forever. Rate-limited to one rekey per chain height.
func (cc *ConferenceCall) reestablishKeyIfExcluded() {
	cc.mu.Lock()
	call := cc.call
	last := cc.lastReestablishHeight
	cc.mu.Unlock()
	if call == nil || cc.chain == nil {
		return
	}
	state := cc.chain.Snapshot()
	inState := false
	for _, p := range state.Participants {
		if p.UserID == cc.selfUID {
			inState = true
			break
		}
	}
	if !inState || last == state.Height {
		return
	}
	cc.mu.Lock()
	cc.lastReestablishHeight = state.Height
	cc.mu.Unlock()

	block, err := e2e.BuildSelfAddBlock(cc.signer, state, cc.selfUID)
	if err != nil {
		cc.log.Warnf("[conf] reestablish key build: %v", err)
		return
	}
	encoded, err := e2e.EncodeBlock(block)
	if err != nil {
		cc.log.Warnf("[conf] reestablish key encode: %v", err)
		return
	}
	beforeHeight := cc.chain.Height()
	updates, err := cc.client.PhoneSendConferenceCallBroadcast(call, encoded)
	if err != nil {
		cc.log.Warnf("[conf] reestablish key send: %v", err)
		return
	}
	cc.applyUpdates(updates)
	if werr := cc.waitForServerBlock(context.Background(), call, beforeHeight+1); werr != nil {
		cc.log.Warnf("[conf] reestablish key wait: %v", werr)
	}
}

// startVerificationRound seeds a new commit-reveal round using the main
// chain's current snapshot.
func (cc *ConferenceCall) startVerificationRound() error {
	if cc.verify == nil || cc.chain == nil {
		return nil
	}
	state := cc.chain.Snapshot()
	parts := make([]e2e.Participant, 0, len(state.Participants))
	for _, p := range state.Participants {
		pk := make(ed25519.PublicKey, 32)
		copy(pk, p.PublicKey)
		parts = append(parts, e2e.Participant{UserID: p.UserID, PublicKey: pk})
	}
	return cc.verify.NewMainBlock(state.Height, state.LastBlockHash, parts)
}

// flushOutboundBroadcasts ships every pending broadcast from the verification
// chain. Re-entrant: PhoneSendConferenceCallBroadcast → applyUpdates →
// applyIncomingBlocks → flushOutboundBroadcasts. A nested call no-ops so the
// outer loop can finish draining without losing messages.
func (cc *ConferenceCall) flushOutboundBroadcasts() {
	if cc.verify == nil {
		return
	}
	cc.mu.Lock()
	call := cc.call
	flushing := cc.flushingBroadcasts
	cc.mu.Unlock()
	if flushing {
		return
	}
	msgs := cc.verify.PullOutbound()
	if len(msgs) == 0 {
		return
	}
	if call == nil {
		cc.verify.RequeueOutbound(msgs)
		return
	}
	cc.mu.Lock()
	cc.flushingBroadcasts = true
	cc.mu.Unlock()
	defer func() {
		cc.mu.Lock()
		cc.flushingBroadcasts = false
		cc.mu.Unlock()
	}()

	for len(msgs) > 0 {
		for _, m := range msgs {
			updates, err := cc.client.PhoneSendConferenceCallBroadcast(call, m)
			if err != nil {
				cc.log.Warnf("[conf] sendConferenceCallBroadcast: %v", err)
			} else {
				cc.applyUpdates(updates)
			}
		}
		msgs = cc.verify.PullOutbound()
	}
}
