// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
)

// VerifyState is the current phase of the emoji-fingerprint commit-reveal
type VerifyState int

const (
	VerifyIdle VerifyState = iota
	VerifyCommit
	VerifyReveal
	VerifyEnd
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

// VerificationChain tracks one round of the commit-reveal protocol.
type VerificationChain struct {
	mu sync.Mutex

	self     ed25519.PrivateKey
	selfUID  int64
	selfPub  ed25519.PublicKey
	selfDone bool

	height        int32
	lastBlockHash [32]byte
	participants  map[int64]ed25519.PublicKey

	state VerifyState

	mySecretNonce [32]byte
	committed     map[int64][32]byte
	revealed      map[int64][32]byte

	emojiHash []byte

	delayed [][]byte
	outbound [][]byte
}

func NewVerificationChain(self ed25519.PrivateKey, selfUID int64) *VerificationChain {
	pub, _ := self.Public().(ed25519.PublicKey)
	return &VerificationChain{
		self:    self,
		selfUID: selfUID,
		selfPub: pub,
		state:   VerifyIdle,
	}
}

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

// PullOutbound drains pending broadcast messages.
func (v *VerificationChain) PullOutbound() [][]byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := v.outbound
	v.outbound = nil
	return out
}

// RequeueOutbound puts drained messages back on the queue for later delivery.
func (v *VerificationChain) RequeueOutbound(msgs [][]byte) {
	if len(msgs) == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.outbound = append(msgs, v.outbound...)
}

// NewMainBlock seeds a fresh commit round when the main chain accepts a new block.
func (v *VerificationChain) NewMainBlock(height int32, lastBlockHash [32]byte, participants []Participant) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.height == height && v.lastBlockHash == lastBlockHash && v.state != VerifyIdle {
		v.replayDelayed()
		return nil
	}

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

	if _, ok := v.participants[v.selfUID]; !ok {
		return nil
	}

	commit, nonce, err := BuildNonceCommit(v.self, v.selfUID, v.height, v.lastBlockHash)
	if err != nil {
		return err
	}
	v.mySecretNonce = nonce
	v.outbound = append(v.outbound, EncodeNonceCommit(commit))
	v.committed[v.selfUID] = commit.NonceHash
	v.maybeAdvanceToReveal()
	v.replayDelayed()
	return nil
}

func (v *VerificationChain) replayDelayed() {
	if len(v.delayed) == 0 {
		return
	}
	pending := v.delayed
	v.delayed = nil
	for _, d := range pending {
		_ = v.receiveLocked(d)
	}
}

// ReceiveBroadcast processes an inbound serialized GroupBroadcast.
func (v *VerificationChain) ReceiveBroadcast(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.receiveLocked(data)
}

func broadcastHeight(data []byte) (int32, bool) {
	if IsNonceCommit(data) {
		if c, err := DecodeNonceCommit(data); err == nil {
			return c.ChainHeight, true
		}
	}
	if IsNonceReveal(data) {
		if r, err := DecodeNonceReveal(data); err == nil {
			return r.ChainHeight, true
		}
	}
	return 0, false
}

func (v *VerificationChain) receiveLocked(data []byte) error {
	if h, ok := broadcastHeight(data); ok {
		if v.state == VerifyIdle {
			v.delayed = append(v.delayed, data)
			return nil
		}
		if h < v.height {
			return nil
		}
		if h > v.height {
			v.delayed = append(v.delayed, data)
			return nil
		}
	}
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
	v.emojiHash = hmacSHA512(full, v.lastBlockHash[:])
	v.state = VerifyEnd
}

// NonceCommit corresponds to:
//
//	e2e.chain.groupBroadcastNonceCommit#d1512ae7
//	  signature:int512 user_id:int64 chain_height:int32
//	  chain_hash:int256 nonce_hash:int256
type NonceCommit struct {
	Signature   [64]byte
	UserID      int64
	ChainHeight int32
	ChainHash   [32]byte
	NonceHash   [32]byte
}

// NonceReveal corresponds to:
//
//	e2e.chain.groupBroadcastNonceReveal#83f4f9d8
//	  signature:int512 user_id:int64 chain_height:int32
//	  chain_hash:int256 nonce:int256
type NonceReveal struct {
	Signature   [64]byte
	UserID      int64
	ChainHeight int32
	ChainHash   [32]byte
	Nonce       [32]byte
}

// EncodeNonceCommit serializes the commit message in the wire form for
// phone.sendConferenceCallBroadcast.
func EncodeNonceCommit(c *NonceCommit) []byte {
	var buf bytes.Buffer
	writeU32(&buf, crcGroupBroadcastNonceCommit)
	buf.Write(c.Signature[:])
	writeI64(&buf, c.UserID)
	writeI32(&buf, c.ChainHeight)
	buf.Write(c.ChainHash[:])
	buf.Write(c.NonceHash[:])
	return buf.Bytes()
}

// EncodeNonceReveal serializes the reveal message in the wire form for
// phone.sendConferenceCallBroadcast.
func EncodeNonceReveal(r *NonceReveal) []byte {
	var buf bytes.Buffer
	writeU32(&buf, crcGroupBroadcastNonceReveal)
	buf.Write(r.Signature[:])
	writeI64(&buf, r.UserID)
	writeI32(&buf, r.ChainHeight)
	buf.Write(r.ChainHash[:])
	buf.Write(r.Nonce[:])
	return buf.Bytes()
}

func DecodeNonceCommit(data []byte) (*NonceCommit, error) {
	r := &reader{b: data}
	mag := r.readU32()
	if mag != crcGroupBroadcastNonceCommit && mag != crcGroupBroadcastNonceCommit+1 {
		return nil, fmt.Errorf("e2e: not a NonceCommit (magic=%#x)", mag)
	}
	c := &NonceCommit{}
	r.readFull(c.Signature[:])
	c.UserID = r.readI64()
	c.ChainHeight = r.readI32()
	r.readFull(c.ChainHash[:])
	r.readFull(c.NonceHash[:])
	if r.err != nil {
		return nil, r.err
	}
	return c, nil
}

func DecodeNonceReveal(data []byte) (*NonceReveal, error) {
	r := &reader{b: data}
	mag := r.readU32()
	if mag != crcGroupBroadcastNonceReveal && mag != crcGroupBroadcastNonceReveal+1 {
		return nil, fmt.Errorf("e2e: not a NonceReveal (magic=%#x)", mag)
	}
	rv := &NonceReveal{}
	r.readFull(rv.Signature[:])
	rv.UserID = r.readI64()
	rv.ChainHeight = r.readI32()
	r.readFull(rv.ChainHash[:])
	r.readFull(rv.Nonce[:])
	if r.err != nil {
		return nil, r.err
	}
	return rv, nil
}

func BroadcastMagic(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}

func IsNonceCommit(data []byte) bool {
	mag := BroadcastMagic(data)
	return mag == crcGroupBroadcastNonceCommit || mag == crcGroupBroadcastNonceCommit+1
}

func IsNonceReveal(data []byte) bool {
	mag := BroadcastMagic(data)
	return mag == crcGroupBroadcastNonceReveal || mag == crcGroupBroadcastNonceReveal+1
}

func BuildNonceCommit(priv ed25519.PrivateKey, userID int64, chainHeight int32, chainHash [32]byte) (*NonceCommit, [32]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nonce, fmt.Errorf("e2e: rand: %w", err)
	}
	c := &NonceCommit{
		UserID:      userID,
		ChainHeight: chainHeight,
		ChainHash:   chainHash,
		NonceHash:   sha256.Sum256(nonce[:]),
	}
	signed := EncodeNonceCommit(c)
	sig := ed25519.Sign(priv, signed)
	copy(c.Signature[:], sig)
	return c, nonce, nil
}

func BuildNonceReveal(priv ed25519.PrivateKey, userID int64, chainHeight int32, chainHash, nonce [32]byte) *NonceReveal {
	r := &NonceReveal{
		UserID:      userID,
		ChainHeight: chainHeight,
		ChainHash:   chainHash,
		Nonce:       nonce,
	}
	signed := EncodeNonceReveal(r)
	sig := ed25519.Sign(priv, signed)
	copy(r.Signature[:], sig)
	return r
}

func VerifyNonceCommit(pub ed25519.PublicKey, c *NonceCommit) bool {
	cp := *c
	cp.Signature = [64]byte{}
	signed := EncodeNonceCommit(&cp)
	return ed25519.Verify(pub, signed, c.Signature[:])
}

func VerifyNonceReveal(pub ed25519.PublicKey, r *NonceReveal, expectedHash [32]byte) bool {
	if sha256.Sum256(r.Nonce[:]) != expectedHash {
		return false
	}
	cp := *r
	cp.Signature = [64]byte{}
	signed := EncodeNonceReveal(&cp)
	return ed25519.Verify(pub, signed, r.Signature[:])
}
