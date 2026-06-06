// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
)

// Participant is a flat view of GroupParticipant for external callers.
type Participant struct {
	UserID      int64
	PublicKey   ed25519.PublicKey
	AddUsers    bool
	RemoveUsers bool
	Version     int32
}

func (p Participant) toTL() GroupParticipant {
	gp := GroupParticipant{
		UserID:      p.UserID,
		AddUsers:    p.AddUsers,
		RemoveUsers: p.RemoveUsers,
		Version:     p.Version,
	}
	copy(gp.PublicKey[:], p.PublicKey)
	return gp
}

// State is a snapshot of the chain at a given height.
type State struct {
	Height         int32
	LastBlockHash  [32]byte
	Participants   []Participant
	HasSharedKey   bool
	GroupSharedKey [32]byte
	ActiveEpochs   int
}

// EpochKey wraps a single epoch's shared key.
type EpochKey struct {
	BlockHash      [32]byte
	GroupSharedKey [32]byte
}

// Chain validates and tracks the per-call append-only blockchain.
type Chain struct {
	mu sync.RWMutex

	height        int32
	lastBlockHash [32]byte

	founderPubKey ed25519.PublicKey
	participants  map[string]Participant // key: string(publicKey)
	rawSharedKey  [32]byte
	hasShared     bool

	activeEpochs []EpochKey

	self             ed25519.PrivateKey
	selfUserID       int64
	lastSharedKeyErr error
}

func (c *Chain) LastSharedKeyErr() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSharedKeyErr
}

func destHeaderLens(hs [][]byte) []int {
	out := make([]int, len(hs))
	for i, h := range hs {
		out[i] = len(h)
	}
	return out
}

func firstHeader(hs [][]byte, i int) []byte {
	if i < 0 || i >= len(hs) {
		return nil
	}
	return hs[i]
}

func NewChain(self ed25519.PrivateKey) *Chain {
	return &Chain{
		participants: make(map[string]Participant),
		self:         self,
	}
}

func (c *Chain) SetSelfUserID(uid int64) {
	c.mu.Lock()
	c.selfUserID = uid
	c.mu.Unlock()
}

func (c *Chain) Snapshot() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	parts := make([]Participant, 0, len(c.participants))
	for _, p := range c.participants {
		parts = append(parts, p)
	}
	s := State{
		Height:        c.height,
		LastBlockHash: c.lastBlockHash,
		Participants:  parts,
		HasSharedKey:  c.hasShared,
		ActiveEpochs:  len(c.activeEpochs),
	}
	if len(c.activeEpochs) > 0 {
		s.GroupSharedKey = c.activeEpochs[len(c.activeEpochs)-1].GroupSharedKey
	}
	return s
}

func (c *Chain) Height() int32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.height
}

func (c *Chain) CurrentEpoch() (EpochKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.activeEpochs) == 0 {
		return EpochKey{}, false
	}
	return c.activeEpochs[len(c.activeEpochs)-1], true
}

func (c *Chain) ActiveEpochs() []EpochKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]EpochKey(nil), c.activeEpochs...)
}

func (c *Chain) EmojiFingerprint() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.hasShared {
		return nil
	}
	mac := hmacSHA512(c.rawSharedKey[:], c.lastBlockHash[:])
	return emojisFromMAC(mac)
}

// ApplyBlock validates and applies a block to the chain.
func (c *Chain) ApplyBlock(block *Block) error {
	if block == nil {
		return errors.New("e2e: nil block")
	}
	encoded, err := EncodeBlockForHash(block)
	if err != nil {
		return fmt.Errorf("e2e: encode block: %w", err)
	}
	blockHash := sha256.Sum256(encoded)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.height == 0 && block.Height == 0 && c.founderPubKey == nil {
		// zero block — establishes the founder
	} else {
		if block.Height != c.height+1 {
			return fmt.Errorf("e2e: bad height: have %d, got %d", c.height, block.Height)
		}
		if block.PrevBlockHash != c.lastBlockHash {
			return fmt.Errorf("e2e: prev_block_hash mismatch at h=%d", block.Height)
		}
	}

	signedBody, err := EncodeBlockForSignature(block)
	if err != nil {
		return fmt.Errorf("e2e: encode for sig: %w", err)
	}
	if !c.verifySignature(block, signedBody) {
		return errors.New("e2e: bad signature")
	}

	if block.Height == 0 && block.SignaturePublicKey != nil {
		c.founderPubKey = ed25519.PublicKey(block.SignaturePublicKey[:])
	}

	for _, ch := range block.Changes {
		if err := c.applyChange(ch, blockHash); err != nil {
			return fmt.Errorf("e2e: apply change %T: %w", ch, err)
		}
	}

	c.height = block.Height
	c.lastBlockHash = blockHash
	return nil
}

func (c *Chain) verifySignature(block *Block, signedBody []byte) bool {
	if block.SignaturePublicKey != nil {
		return ed25519.Verify(ed25519.PublicKey(block.SignaturePublicKey[:]), signedBody, block.Signature[:])
	}
	if c.founderPubKey != nil {
		if ed25519.Verify(c.founderPubKey, signedBody, block.Signature[:]) {
			return true
		}
	}
	for _, p := range c.participants {
		if ed25519.Verify(p.PublicKey, signedBody, block.Signature[:]) {
			return true
		}
	}
	return false
}

func (c *Chain) applyChange(ch Change, blockHash [32]byte) error {
	switch v := ch.(type) {
	case *ChangeNoop:
		return nil
	case *ChangeSetGroupState:
		newParts := make(map[string]Participant, len(v.GroupState.Participants))
		for _, gp := range v.GroupState.Participants {
			pub := make(ed25519.PublicKey, 32)
			copy(pub, gp.PublicKey[:])
			newParts[string(pub)] = Participant{
				UserID:      gp.UserID,
				PublicKey:   pub,
				AddUsers:    gp.AddUsers,
				RemoveUsers: gp.RemoveUsers,
				Version:     gp.Version,
			}
		}
		c.participants = newParts
		c.hasShared = false
		c.rawSharedKey = [32]byte{}
		c.activeEpochs = nil
		return nil
	case *ChangeSetSharedKey:
		raw, err := c.recoverSharedKey(&v.SharedKey)
		if err != nil {
			sk := &v.SharedKey
			c.lastSharedKeyErr = fmt.Errorf("recover shared key: %w | selfUID=%d destUIDs=%v ek=%x encGSK=%x destHdr0=%x destHdr1=%x",
				err, c.selfUserID, sk.DestUserID,
				sk.EphemeralKey, []byte(sk.EncryptedSharedKey),
				firstHeader(sk.DestHeader, 0), firstHeader(sk.DestHeader, 1))
			return nil
		}
		c.rawSharedKey = raw
		c.hasShared = true
		ek := EpochKey{
			BlockHash:      blockHash,
			GroupSharedKey: DeriveGroupSharedKey(raw, blockHash),
		}
		c.activeEpochs = append(c.activeEpochs, ek)
		return nil
	case *ChangeSetValue:
		return nil
	default:
		return fmt.Errorf("unknown change type %T", v)
	}
}

func (c *Chain) recoverSharedKey(sk *SharedKeyTL) ([32]byte, error) {
	var zero [32]byte
	if c.selfUserID == 0 {
		return zero, errors.New("self user id not set")
	}
	if len(sk.DestUserID) != len(sk.DestHeader) {
		return zero, fmt.Errorf("dest_user_id (%d) and dest_header (%d) length mismatch",
			len(sk.DestUserID), len(sk.DestHeader))
	}
	idx := -1
	for i, uid := range sk.DestUserID {
		if uid == c.selfUserID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return zero, fmt.Errorf("self user id %d not in dest_user_id", c.selfUserID)
	}
	encGSK := []byte(sk.EncryptedSharedKey)
	tryAll := func(ekMode int) ([32]byte, error) {
		if k, err := recoverWithEKMode(c.self, sk.EphemeralKey, sk.DestHeader[idx], encGSK, ekMode); err == nil {
			return k, nil
		}
		for i, h := range sk.DestHeader {
			if i == idx {
				continue
			}
			if k, err := recoverWithEKMode(c.self, sk.EphemeralKey, h, encGSK, ekMode); err == nil {
				return k, nil
			}
		}
		return zero, errors.New("none decrypt")
	}
	if k, err := tryAll(0); err == nil {
		return k, nil
	}
	if k, err := tryAll(1); err == nil {
		return k, nil
	}
	return zero, fmt.Errorf("no dest_header decrypts under self_priv × ek (tried %d × 2 modes)", len(sk.DestHeader))
}

// emptyKVHash is the deterministic hash of an empty Trie node:
// SHA-256 of the 4-byte little-endian TrieNodeType::Empty (= 0).
// Derived per tde2e/td/e2e/Trie.cpp + Trie.h in tdlib/td.
var emptyKVHash = [32]byte{
	0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb,
	0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48,
	0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c,
	0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19,
}

// BuildZeroBlock creates and signs the founder block. Per tdlib's
// tde2e/td/e2e/Call.cpp::create_zero_block, it carries exactly two
// changes in order:
//
//  1. ChangeSetGroupState — group with the founder as the sole
//     participant (add_users + remove_users flags set, version 0,
//     external_permissions = 3).
//  2. ChangeSetSharedKey — an ephemeral pubkey, the AES-encrypted
//     group shared key, and per-recipient header(s).
//
// The state_proof flags are zero (because the block contains both a
// SetGroupState and a SetSharedKey, both fields are omitted from the
// BuildNoopBlock builds a minimal block containing only a changeNoop.
// This is intentionally INVALID per validate_state's "must have SetValue
// or SetGroupState" rule — but it's useful for confirming the server's
// block parser is happy with our basic wire encoding. If we get back
// BLOCK_INVALID (400) the parser succeeded; if we get -504 the parser
// still doesn't like our bytes.
func BuildNoopBlock(priv ed25519.PrivateKey) (*Block, error) {
	pub := priv.Public().(ed25519.PublicKey)
	var pubArr [32]byte
	copy(pubArr[:], pub)

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	block := &Block{
		Height:        0,
		PrevBlockHash: [32]byte{},
		Changes: []Change{
			&ChangeNoop{Nonce: nonce},
		},
		StateProof: StateProof{
			KVHash: emptyKVHash,
		},
		SignaturePublicKey: &pubArr,
	}
	signedBody, err := EncodeBlockForSignature(block)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signedBody)
	copy(block.Signature[:], sig)
	return block, nil
}

// proof — see Blockchain.cpp::build_block). signature_public_key is
// set to the founder's pubkey.
func BuildZeroBlock(priv ed25519.PrivateKey, userID int64) (*Block, error) {
	pub := priv.Public().(ed25519.PublicKey)
	var pubArr [32]byte
	copy(pubArr[:], pub)

	founder := GroupParticipant{
		UserID:      userID,
		PublicKey:   pubArr,
		AddUsers:    true,
		RemoveUsers: true,
		Version:     1,
	}

	sharedKey, err := buildFounderSharedKey(priv, []GroupParticipant{founder})
	if err != nil {
		return nil, err
	}

	block := &Block{
		Height:        0,
		PrevBlockHash: [32]byte{},
		Changes: []Change{
			&ChangeSetGroupState{GroupState: GroupState{
				Participants:        []GroupParticipant{founder},
				ExternalPermissions: 3,
			}},
			&ChangeSetSharedKey{SharedKey: sharedKey},
		},
		StateProof: StateProof{
			KVHash: emptyKVHash,
		},
		SignaturePublicKey: &pubArr,
	}

	signedBody, err := EncodeBlockForSignature(block)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signedBody)
	copy(block.Signature[:], sig)
	return block, nil
}
