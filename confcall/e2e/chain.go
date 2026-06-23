// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

// Package e2e implements the per-call E2E chain and per-packet cipher used
// by Telegram conference calls. See
// https://core.telegram.org/api/end-to-end/group-calls for the spec.
package e2e

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

type Participant struct {
	UserID      int64
	PublicKey   ed25519.PublicKey
	AddUsers    bool
	RemoveUsers bool
	Version     int32
}

type State struct {
	Height         int32
	LastBlockHash  [32]byte
	Participants   []Participant
	HasSharedKey   bool
	GroupSharedKey [32]byte
	ActiveEpochs   int
}

type EpochKey struct {
	BlockHash      [32]byte
	GroupSharedKey [32]byte
}

const maxActiveEpochs = 20

type Chain struct {
	mu sync.RWMutex

	height        int32
	lastBlockHash [32]byte

	founderPubKey ed25519.PublicKey
	participants  map[string]Participant
	rawSharedKey  [32]byte
	hasShared     bool

	activeEpochs []EpochKey

	self             ed25519.PrivateKey
	selfUserID       int64
	lastSharedKeyErr error
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

func (c *Chain) LastSharedKeyErr() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastSharedKeyErr
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

func (c *Chain) ApplyBlockBytes(data []byte) error {
	block, err := DecodeBlock(data)
	if err != nil {
		return err
	}
	return c.applyBlockWithHash(block, sha256.Sum256(data))
}

func (c *Chain) ApplyBlock(block *Block) error {
	if block == nil {
		return errors.New("e2e: nil block")
	}
	encoded, err := EncodeBlockForHash(block)
	if err != nil {
		return fmt.Errorf("e2e: encode block: %w", err)
	}
	return c.applyBlockWithHash(block, sha256.Sum256(encoded))
}

func (c *Chain) BootstrapFromBlock(block *Block) error {
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

	signedBody, err := EncodeBlockForSignature(block)
	if err != nil {
		return fmt.Errorf("e2e: encode for sig: %w", err)
	}
	if block.Height == 0 && block.SignaturePublicKey != nil {
		c.founderPubKey = ed25519.PublicKey(block.SignaturePublicKey[:])
	}
	if !c.verifySignature(block, signedBody) {
		if block.SignaturePublicKey != nil {
			c.founderPubKey = ed25519.PublicKey(block.SignaturePublicKey[:])
			if !ed25519.Verify(c.founderPubKey, signedBody, block.Signature[:]) {
				return errors.New("e2e: bootstrap bad signature")
			}
		} else {
			return errors.New("e2e: bootstrap bad signature")
		}
	}

	c.participants = make(map[string]Participant)
	c.rawSharedKey = [32]byte{}
	c.hasShared = false
	c.activeEpochs = nil
	for _, ch := range block.Changes {
		if err := c.applyChange(ch, blockHash); err != nil {
			return fmt.Errorf("e2e: bootstrap apply change %T: %w", ch, err)
		}
	}
	c.height = block.Height
	c.lastBlockHash = blockHash
	c.refreshEpoch(blockHash)
	return nil
}

func (c *Chain) applyBlockWithHash(block *Block, blockHash [32]byte) error {
	if block == nil {
		return errors.New("e2e: nil block")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.height == 0 && block.Height == 0 && c.founderPubKey == nil {
		// zero block — establishes the founder
	} else if c.height == 0 && block.Height == 0 && c.founderPubKey != nil {
		if blockHash == c.lastBlockHash {
			return nil
		}
		c.height = -1
		c.lastBlockHash = [32]byte{}
		c.founderPubKey = nil
		c.participants = make(map[string]Participant)
		c.rawSharedKey = [32]byte{}
		c.hasShared = false
		c.activeEpochs = nil
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
	c.refreshEpoch(blockHash)
	return nil
}

func (c *Chain) refreshEpoch(tip [32]byte) {
	if !c.hasShared {
		return
	}
	secret := c.rawSharedKey
	if c.groupVersion() >= 1 {
		secret = DeriveGroupSharedKey(c.rawSharedKey, tip)
	}
	ek := EpochKey{BlockHash: tip, GroupSharedKey: secret}
	for i, e := range c.activeEpochs {
		if e.BlockHash == ek.BlockHash {
			c.activeEpochs = append(c.activeEpochs[:i], c.activeEpochs[i+1:]...)
			break
		}
	}
	c.activeEpochs = append(c.activeEpochs, ek)
	if len(c.activeEpochs) > maxActiveEpochs {
		c.activeEpochs = c.activeEpochs[len(c.activeEpochs)-maxActiveEpochs:]
	}
}

// groupVersion returns the minimum participant version, clamped to [0,255].
func (c *Chain) groupVersion() int32 {
	if len(c.participants) == 0 {
		return 0
	}
	first := true
	var v int32
	for _, p := range c.participants {
		if first || p.Version < v {
			v = p.Version
			first = false
		}
	}
	if v < 0 {
		v = 0
	}
	if v > 255 {
		v = 255
	}
	return v
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

func (c *Chain) applyChange(ch Change, _ [32]byte) error {
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
		return nil
	case *ChangeSetSharedKey:
		raw, err := c.recoverSharedKey(&v.SharedKey)
		if err != nil {
			c.lastSharedKeyErr = fmt.Errorf("recover shared key: %w", err)
			if errors.Is(err, errSelfNotInRecipients) {
				return nil
			}
			return c.lastSharedKeyErr
		}
		c.lastSharedKeyErr = nil
		c.rawSharedKey = raw
		c.hasShared = true
		return nil
	case *ChangeSetValue:
		return nil
	default:
		return fmt.Errorf("unknown change type %T", v)
	}
}

var errSelfNotInRecipients = errors.New("self user id not in dest_user_id")

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
		return zero, errSelfNotInRecipients
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

// SHA-256 of the 4-byte little-endian TrieNodeType::Empty (= 0).
var emptyKVHash = [32]byte{
	0xdf, 0x3f, 0x61, 0x98, 0x04, 0xa9, 0x2f, 0xdb,
	0x40, 0x57, 0x19, 0x2d, 0xc4, 0x3d, 0xd7, 0x48,
	0xea, 0x77, 0x8a, 0xdc, 0x52, 0xbc, 0x49, 0x8c,
	0xe8, 0x05, 0x24, 0xc0, 0x14, 0xb8, 0x11, 0x19,
}

func EmptyKVHash() [32]byte { return emptyKVHash }

func SignBlock(priv ed25519.PrivateKey, block *Block) error {
	signedBody, err := EncodeBlockForSignature(block)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, signedBody)
	copy(block.Signature[:], sig)
	return nil
}

func BuildSelfAddBlock(priv ed25519.PrivateKey, state State, userID int64) (*Block, error) {
	pub := priv.Public().(ed25519.PublicKey)
	var pubArr [32]byte
	copy(pubArr[:], pub)

	parts := make([]GroupParticipant, 0, len(state.Participants)+1)
	present := false
	for _, p := range state.Participants {
		var pk [32]byte
		copy(pk[:], p.PublicKey)
		if p.UserID == userID {
			present = true
			pk = pubArr
		}
		parts = append(parts, GroupParticipant{
			UserID:      p.UserID,
			PublicKey:   pk,
			AddUsers:    p.AddUsers,
			RemoveUsers: p.RemoveUsers,
			Version:     p.Version,
		})
	}
	if !present {
		parts = append(parts, GroupParticipant{UserID: userID, PublicKey: pubArr, AddUsers: true, RemoveUsers: true, Version: 1})
	}
	sharedKey, err := BuildSharedKey(parts)
	if err != nil {
		return nil, err
	}
	block := &Block{
		Height:        state.Height + 1,
		PrevBlockHash: state.LastBlockHash,
		Changes: []Change{
			&ChangeSetGroupState{GroupState: GroupState{Participants: parts, ExternalPermissions: 3}},
			&ChangeSetSharedKey{SharedKey: sharedKey},
		},
		StateProof:         StateProof{KVHash: emptyKVHash},
		SignaturePublicKey: &pubArr,
	}
	if err := SignBlock(priv, block); err != nil {
		return nil, err
	}
	return block, nil
}

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
	sharedKey, err := BuildSharedKey([]GroupParticipant{founder})
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
		StateProof:         StateProof{KVHash: emptyKVHash},
		SignaturePublicKey: &pubArr,
	}
	if err := SignBlock(priv, block); err != nil {
		return nil, err
	}
	return block, nil
}

var emojiSet = []string{
	"😉", "😍", "😛", "😭", "😱", "😡", "😎", "😴", "😵", "😈",
	"😬", "😇", "😏", "👮", "👷", "💂", "👶", "👨", "👩", "👴",
	"👵", "😻", "😽", "🙀", "👺", "🙈", "🙉", "🙊", "💀", "👽",
	"💩", "🔥", "💥", "💤", "👂", "👀", "👃", "👅", "👄", "👍",
	"👎", "👌", "👊", "✌", "✋", "👐", "👆", "👇", "👉", "👈",
	"🙏", "👏", "💪", "🚶", "🏃", "💃", "👫", "👪", "👬", "👭",
	"💅", "🎩", "👑", "👒", "👟", "👞", "👠", "👕", "👗", "👖",
	"👙", "👜", "👓", "🎀", "💄", "💛", "💙", "💜", "💚", "💍",
	"💎", "🐶", "🐺", "🐱", "🐭", "🐹", "🐰", "🐸", "🐯", "🐨",
	"🐻", "🐷", "🐮", "🐗", "🐴", "🐑", "🐘", "🐼", "🐧", "🐥",
	"🐔", "🐍", "🐢", "🐛", "🐝", "🐜", "🐞", "🐌", "🐙", "🐚",
	"🐟", "🐬", "🐋", "🐐", "🐊", "🐫", "🍀", "🌹", "🌻", "🍁",
	"🌾", "🍄", "🌵", "🌴", "🌳", "🌞", "🌚", "🌙", "🌎", "🌋",
	"⚡", "☔", "❄", "⛄", "🌀", "🌈", "🌊", "🎓", "🎆", "🎃",
	"👻", "🎅", "🎄", "🎁", "🎈", "🔮", "🎥", "📷", "💿", "💻",
	"☎", "📡", "📺", "📻", "🔉", "🔔", "⏳", "⏰", "⌚", "🔒",
	"🔑", "🔎", "💡", "🔦", "🔌", "🔋", "🚿", "🚽", "🔧", "🔨",
	"🚪", "🚬", "💣", "🔫", "🔪", "💊", "💉", "💰", "💵", "💳",
	"✉", "📫", "📦", "📅", "📁", "✂", "📌", "📎", "✒", "✏",
	"📐", "📚", "🔬", "🔭", "🎨", "🎬", "🎤", "🎧", "🎵", "🎹",
	"🎻", "🎺", "🎸", "👾", "🎮", "🃏", "🎲", "🎯", "🏈", "🏀",
	"⚽", "⚾", "🎾", "🎱", "🏉", "🎳", "🏁", "🏇", "🏆", "🏊",
	"🏄", "☕", "🍼", "🍺", "🍷", "🍴", "🍕", "🍔", "🍟", "🍗",
	"🍱", "🍚", "🍜", "🍡", "🍳", "🍞", "🍩", "🍦", "🎂", "🍰",
	"🍪", "🍫", "🍭", "🍯", "🍎", "🍏", "🍊", "🍋", "🍒", "🍇",
	"🍉", "🍓", "🍑", "🍌", "🍐", "🍍", "🍆", "🍅", "🌽", "🏡",
	"🏥", "🏦", "⛪", "🏰", "⛺", "🏭", "🗻", "🗽", "🎠", "🎡",
	"⛲", "🎢", "🚢", "🚤", "⚓", "🚀", "✈", "🚁", "🚂", "🚋",
	"🚎", "🚌", "🚙", "🚗", "🚕", "🚛", "🚨", "🚔", "🚒", "🚑",
	"🚲", "🚠", "🚜", "🚦", "⚠", "🚧", "⛽", "🎰", "🗿", "🎪",
	"🎭", "🇯🇵", "🇰🇷", "🇩🇪", "🇨🇳", "🇺🇸", "🇫🇷", "🇪🇸", "🇮🇹", "🇷🇺",
	"🇬🇧", "1⃣", "2⃣", "3⃣", "4⃣", "5⃣", "6⃣", "7⃣", "8⃣", "9⃣",
	"0⃣", "🔟", "❗", "❓", "♥", "♦", "💯", "🔗", "🔱", "🔴",
	"🔵", "🔶", "🔷",
}

func EmojisFromHash(mac []byte) []string {
	return emojisFromMAC(mac)
}

func emojisFromMAC(mac []byte) []string {
	out := make([]string, 4)
	for i := range 4 {
		chunk := binary.BigEndian.Uint64(mac[i*8:(i+1)*8]) & 0x7fffffffffffffff
		out[i] = emojiSet[int(chunk%uint64(len(emojiSet)))]
	}
	return out
}
