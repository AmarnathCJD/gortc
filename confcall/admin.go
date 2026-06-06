// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package confcall

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/confcall/e2e"
)

// Kick removes the given user ids from the call and broadcasts the
// resulting GroupState block. The local key state is invalidated by the
// SetGroupState; a follow-up RotateKey is required before media can
// resume (the official client does this automatically).
func (cc *ConferenceCall) Kick(ctx context.Context, userIDs []int64) error {
	cc.mu.Lock()
	call := cc.call
	cc.mu.Unlock()
	if call == nil {
		return errors.New("confcall: not in a call")
	}
	state := cc.chain.Snapshot()
	keep := make([]e2e.GroupParticipant, 0, len(state.Participants))
	kickSet := make(map[int64]struct{}, len(userIDs))
	for _, id := range userIDs {
		kickSet[id] = struct{}{}
	}
	for _, p := range state.Participants {
		if _, ok := kickSet[p.UserID]; !ok {
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
	}
	block := &e2e.Block{
		Height:        state.Height + 1,
		PrevBlockHash: state.LastBlockHash,
		Changes:       []e2e.Change{&e2e.ChangeSetGroupState{GroupState: e2e.GroupState{Participants: keep}}},
	}
	signedBody, err := e2e.EncodeBlockForSignature(block)
	if err != nil {
		return fmt.Errorf("encode block: %w", err)
	}
	sig := ed25519.Sign(cc.signer, signedBody)
	copy(block.Signature[:], sig)
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

// RotateKey establishes a new shared key by emitting a fresh
// ChangeSetSharedKey block. Should follow any change to participant
// membership.
func (cc *ConferenceCall) RotateKey(ctx context.Context) error {
	cc.mu.Lock()
	call := cc.call
	cc.mu.Unlock()
	if call == nil {
		return errors.New("confcall: not in a call")
	}
	var ek [32]byte
	if _, err := rand.Read(ek[:]); err != nil {
		return fmt.Errorf("rand key: %w", err)
	}
	state := cc.chain.Snapshot()
	block := &e2e.Block{
		Height:        state.Height + 1,
		PrevBlockHash: state.LastBlockHash,
		Changes: []e2e.Change{&e2e.ChangeSetSharedKey{SharedKey: e2e.SharedKeyTL{
			EphemeralKey: ek,
		}}},
	}
	signedBody, err := e2e.EncodeBlockForSignature(block)
	if err != nil {
		return fmt.Errorf("encode block: %w", err)
	}
	sig := ed25519.Sign(cc.signer, signedBody)
	copy(block.Signature[:], sig)
	encoded, err := e2e.EncodeBlock(block)
	if err != nil {
		return fmt.Errorf("encode block: %w", err)
	}
	if err := cc.chain.ApplyBlock(block); err != nil {
		return fmt.Errorf("apply local: %w", err)
	}
	_, err = cc.client.PhoneSendConferenceCallBroadcast(call, encoded)
	return err
}
