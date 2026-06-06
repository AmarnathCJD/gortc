// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package confcall

import (
	"crypto/ed25519"

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
			cc.log.Debugf("[conf] incoming conference call: id=%d active=%v missed=%v video=%v",
				act.CallID, act.Active, act.Missed, act.Video)
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
			upd, ok := u.(*telegram.UpdateGroupCallChainBlocks)
			if !ok {
				return nil
			}
			cc.applyIncomingBlocks(upd.Blocks)
			return nil
		})
	})
}

func (cc *ConferenceCall) applyIncomingBlocks(blocks [][]byte) {
	if cc.chain == nil {
		return
	}
	chainAdvanced := false
	for _, raw := range blocks {
		// updateGroupCallChainBlocks carries TWO message types muxed
		// together: chain blocks (e2e.chain.block) AND verification
		// broadcasts (groupBroadcastNonceCommit / NonceReveal). Route
		// each by magic.
		if e2e.IsNonceCommit(raw) || e2e.IsNonceReveal(raw) {
			if cc.verify == nil {
				continue
			}
			if err := cc.verify.ReceiveBroadcast(raw); err != nil {
				cc.log.Warnf("[conf] apply broadcast: %v", err)
			}
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
			cc.log.Warnf("[conf] shared-key recover (block h=%d): %v", cc.chain.Height(), skErr)
		}
		chainAdvanced = true
		if cc.OnBlockApplied != nil {
			cc.OnBlockApplied(int(cc.chain.Height()))
		}
		if cc.OnEmojiReady != nil {
			if em := cc.chain.EmojiFingerprint(); len(em) > 0 {
				cc.OnEmojiReady(em)
			}
		}
	}
	if chainAdvanced {
		if err := cc.startVerificationRound(); err != nil {
			cc.log.Warnf("[conf] start verification round: %v", err)
		}
	}
	cc.flushOutboundBroadcasts()
}

// startVerificationRound seeds a new commit-reveal round on the
// verification chain using the main chain's current snapshot, then
// flushes any outbound messages it produces.
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
	if err := cc.verify.NewMainBlock(state.Height, state.LastBlockHash, parts); err != nil {
		return err
	}
	return nil
}

// flushOutboundBroadcasts ships every pending broadcast message from
// the verification chain through phone.sendConferenceCallBroadcast.
func (cc *ConferenceCall) flushOutboundBroadcasts() {
	if cc.verify == nil {
		return
	}
	msgs := cc.verify.PullOutbound()
	if len(msgs) == 0 {
		return
	}
	cc.mu.Lock()
	call := cc.call
	cc.mu.Unlock()
	if call == nil {
		cc.log.Debugf("[conf] %d outbound broadcasts pending but call not ready", len(msgs))
		return
	}
	for _, m := range msgs {
		if _, err := cc.client.PhoneSendConferenceCallBroadcast(call, m); err != nil {
			cc.log.Warnf("[conf] sendConferenceCallBroadcast: %v", err)
		} else {
			cc.log.Debugf("[conf] sent broadcast (%d bytes)", len(m))
		}
	}
}
