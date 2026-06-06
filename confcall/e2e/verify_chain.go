// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package e2e

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"sync"
)

// VerifyState represents the current phase of the emoji-fingerprint
// commit-reveal dance. It mirrors tdlib's CallVerificationChain::State.
type VerifyState int

const (
	VerifyIdle    VerifyState = iota // no broadcast in progress
	VerifyCommit                     // collecting nonce-hashes from participants
	VerifyReveal                     // collecting nonces; about to compute emoji
	VerifyEnd                        // emoji hash finalized
)

func (v VerifyState) String() string {
	switch v {
	case VerifyIdle:
		return "idle"
	case VerifyCommit:
		return "commit"
	case VerifyReveal:
		return "reveal"
	case VerifyEnd:
		return "end"
	}
	return fmt.Sprintf("verify(%d)", v)
}

// VerificationChain tracks one round of the emoji-fingerprint
// commit-reveal protocol. Each chain advance (a new groupState that
// changes the participant set or shared key) starts a new round.
type VerificationChain struct {
	mu sync.Mutex

	self     ed25519.PrivateKey
	selfUID  int64
	selfPub  ed25519.PublicKey
	selfDone bool // whether we've already sent reveal this round

	height        int32
	lastBlockHash [32]byte
	participants  map[int64]ed25519.PublicKey // keyed by user_id

	state VerifyState

	mySecretNonce [32]byte
	committed     map[int64][32]byte // user_id → nonce_hash
	revealed      map[int64][32]byte // user_id → nonce

	emojiHash []byte // 64 bytes once VerifyEnd is reached

	// outbound is filled by NewMainBlock and ReceiveBroadcast; the
	// caller drains it via PullOutbound() and ships each message
	// through phone.sendConferenceCallBroadcast.
	outbound [][]byte
}

// NewVerificationChain returns an empty chain. Bind it to the local
// signing identity once via SetSelf, then drive it with NewMainBlock /
// ReceiveBroadcast.
func NewVerificationChain(self ed25519.PrivateKey, selfUID int64) *VerificationChain {
	pub, _ := self.Public().(ed25519.PublicKey)
	return &VerificationChain{
		self:    self,
		selfUID: selfUID,
		selfPub: pub,
		state:   VerifyIdle,
	}
}

// State returns the current verification phase.
func (v *VerificationChain) State() VerifyState {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.state
}

// EmojiHash returns the 64-byte HMAC-SHA512 once VerifyEnd is reached.
func (v *VerificationChain) EmojiHash() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.emojiHash == nil {
		return nil
	}
	out := make([]byte, len(v.emojiHash))
	copy(out, v.emojiHash)
	return out
}

// PullOutbound drains pending outbound broadcast messages. Each entry
// is a serialized e2e.chain.GroupBroadcast (with magic CRC prefix and
// ed25519 signature already attached) ready to be wrapped in
// phone.sendConferenceCallBroadcast.
func (v *VerificationChain) PullOutbound() [][]byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := v.outbound
	v.outbound = nil
	return out
}

// NewMainBlock is called when the chain (the GroupState-bearing chain)
// has accepted a new block. It seeds a fresh commit round using the
// new block hash + participant set.
func (v *VerificationChain) NewMainBlock(height int32, lastBlockHash [32]byte, participants []Participant) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.state = VerifyCommit
	v.height = height
	v.lastBlockHash = lastBlockHash
	v.committed = make(map[int64][32]byte)
	v.revealed = make(map[int64][32]byte)
	v.emojiHash = nil
	v.selfDone = false

	parts := make(map[int64]ed25519.PublicKey, len(participants))
	for _, p := range participants {
		pk := make(ed25519.PublicKey, 32)
		copy(pk, p.PublicKey)
		parts[p.UserID] = pk
	}
	v.participants = parts

	// We can't drive the round if we aren't a known participant yet.
	if _, ok := v.participants[v.selfUID]; !ok {
		return nil
	}

	commit, nonce, err := BuildNonceCommit(v.self, v.selfUID, v.height, v.lastBlockHash)
	if err != nil {
		return err
	}
	v.mySecretNonce = nonce
	v.outbound = append(v.outbound, EncodeNonceCommit(commit))
	// Apply our own commit locally too, so the count is consistent.
	v.committed[v.selfUID] = commit.NonceHash
	v.maybeAdvanceToReveal()
	return nil
}

// ReceiveBroadcast processes an inbound serialized GroupBroadcast
// message. It validates signature + state, and may queue our own
// reveal once everyone has committed.
func (v *VerificationChain) ReceiveBroadcast(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.state == VerifyIdle || v.state == VerifyEnd {
		return nil
	}
	switch {
	case IsNonceCommit(data):
		return v.applyCommit(data)
	case IsNonceReveal(data):
		return v.applyReveal(data)
	}
	return fmt.Errorf("e2e: unknown broadcast magic=%#x", BroadcastMagic(data))
}

func (v *VerificationChain) applyCommit(data []byte) error {
	if v.state != VerifyCommit {
		return fmt.Errorf("e2e: nonce_commit in wrong state %s", v.state)
	}
	c, err := DecodeNonceCommit(data)
	if err != nil {
		return err
	}
	if c.ChainHeight != v.height {
		return fmt.Errorf("e2e: commit height %d != current %d", c.ChainHeight, v.height)
	}
	pub, ok := v.participants[c.UserID]
	if !ok {
		return fmt.Errorf("e2e: unknown participant %d", c.UserID)
	}
	if _, dup := v.committed[c.UserID]; dup {
		return nil
	}
	if !VerifyNonceCommit(pub, c) {
		return fmt.Errorf("e2e: bad commit signature for %d", c.UserID)
	}
	v.committed[c.UserID] = c.NonceHash
	v.maybeAdvanceToReveal()
	return nil
}

func (v *VerificationChain) maybeAdvanceToReveal() {
	if v.state != VerifyCommit {
		return
	}
	if len(v.committed) != len(v.participants) {
		return
	}
	v.state = VerifyReveal
	if v.selfDone {
		return
	}
	if _, ok := v.participants[v.selfUID]; !ok {
		return
	}
	r := BuildNonceReveal(v.self, v.selfUID, v.height, v.lastBlockHash, v.mySecretNonce)
	v.outbound = append(v.outbound, EncodeNonceReveal(r))
	v.revealed[v.selfUID] = r.Nonce
	v.selfDone = true
	v.maybeFinalize()
}

func (v *VerificationChain) applyReveal(data []byte) error {
	if v.state != VerifyReveal {
		return fmt.Errorf("e2e: nonce_reveal in wrong state %s", v.state)
	}
	r, err := DecodeNonceReveal(data)
	if err != nil {
		return err
	}
	if r.ChainHeight != v.height {
		return fmt.Errorf("e2e: reveal height %d != current %d", r.ChainHeight, v.height)
	}
	pub, ok := v.participants[r.UserID]
	if !ok {
		return fmt.Errorf("e2e: unknown participant %d", r.UserID)
	}
	expected, ok := v.committed[r.UserID]
	if !ok {
		return fmt.Errorf("e2e: reveal without prior commit for %d", r.UserID)
	}
	if _, dup := v.revealed[r.UserID]; dup {
		return nil
	}
	if !VerifyNonceReveal(pub, r, expected) {
		return fmt.Errorf("e2e: bad reveal for %d", r.UserID)
	}
	v.revealed[r.UserID] = r.Nonce
	v.maybeFinalize()
	return nil
}

func (v *VerificationChain) maybeFinalize() {
	if v.state != VerifyReveal {
		return
	}
	if len(v.revealed) != len(v.participants) {
		return
	}
	// Sort nonces lexicographically and concatenate, then HMAC-SHA512
	// with chain_hash as key. Per tdlib Call.cpp line ~242.
	nonces := make([][]byte, 0, len(v.revealed))
	for _, n := range v.revealed {
		buf := make([]byte, 32)
		copy(buf, n[:])
		nonces = append(nonces, buf)
	}
	sort.Slice(nonces, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if nonces[i][k] != nonces[j][k] {
				return nonces[i][k] < nonces[j][k]
			}
		}
		return false
	})
	full := make([]byte, 0, 32*len(nonces))
	for _, n := range nonces {
		full = append(full, n...)
	}
	v.emojiHash = hmacSHA512(v.lastBlockHash[:], full)
	v.state = VerifyEnd
}
