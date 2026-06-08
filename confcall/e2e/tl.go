// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package e2e

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// CRC32 identifiers from e2e_api.tl. Computed per TL canonical-form
// normalization (angle brackets stripped). The block CRC #639a3db6 is
// the only one quoted explicitly in the schema; the rest are verified
// by the matching method used to derive the block CRC.
const (
	crcBlock                     uint32 = 0x639a3db6
	crcStateProof                uint32 = 0xd6b679e6
	crcGroupParticipant          uint32 = 0x18f3971f
	crcGroupState                uint32 = 0x1ddc7584
	crcSharedKey                 uint32 = 0x8a847e7f
	crcChangeNoop                uint32 = 0xdeb4a41b
	crcChangeSetValue            uint32 = 0xfe0139cc
	crcChangeSetGroupState       uint32 = 0x2cf17146
	crcChangeSetSharedKey        uint32 = 0x987a2158
	crcGroupBroadcastNonceCommit uint32 = 0xd1512ae7
	crcGroupBroadcastNonceReveal uint32 = 0x83f4f9d8
)

// Block is e2e.chain.block#639a3db6
//
//	signature:int512 flags:# prev_block_hash:int256
//	changes:vector<e2e.chain.Change> height:int
//	state_proof:e2e.chain.StateProof
//	signature_public_key:flags.0?int256 = e2e.chain.Block
type Block struct {
	Signature          [64]byte
	PrevBlockHash      [32]byte
	Changes            []Change
	Height             int32
	StateProof         StateProof
	SignaturePublicKey *[32]byte // present only on zero-block (flags.0)
}

// StateProof is e2e.chain.stateProof
//
//	flags:# kv_hash:int256
//	group_state:flags.0?e2e.chain.GroupState
//	shared_key:flags.1?e2e.chain.SharedKey
type StateProof struct {
	KVHash     [32]byte
	GroupState *GroupState
	SharedKey  *SharedKeyTL
}

// GroupState is e2e.chain.groupState
//
//	participants:vector<e2e.chain.GroupParticipant>
//	external_permissions:int
type GroupState struct {
	Participants        []GroupParticipant
	ExternalPermissions int32
}

// GroupParticipant is e2e.chain.groupParticipant
//
//	user_id:long public_key:int256 flags:#
//	add_users:flags.0?true remove_users:flags.1?true
//	version:int
type GroupParticipant struct {
	UserID      int64
	PublicKey   [32]byte
	AddUsers    bool
	RemoveUsers bool
	Version     int32
}

// SharedKeyTL is e2e.chain.sharedKey
//
//	ek:int256 encrypted_shared_key:string
//	dest_user_id:vector<long> dest_header:vector<bytes>
type SharedKeyTL struct {
	EphemeralKey       [32]byte
	EncryptedSharedKey string
	DestUserID         []int64
	DestHeader         [][]byte
}

// Change is e2e.chain.Change (boxed).
type Change interface{ isChange() }

type ChangeNoop struct {
	Nonce [32]byte
}

type ChangeSetValue struct {
	Key   []byte
	Value []byte
}

type ChangeSetGroupState struct {
	GroupState GroupState
}

type ChangeSetSharedKey struct {
	SharedKey SharedKeyTL
}

func (*ChangeNoop) isChange()          {}
func (*ChangeSetValue) isChange()      {}
func (*ChangeSetGroupState) isChange() {}
func (*ChangeSetSharedKey) isChange()  {}

// ── Encode ─────────────────────────────────────────────────────────────

// EncodeBlock serializes a block in the LOCAL wire format. This is the
// form consumed by the chain validator. For sending to Telegram, wrap
// the result with EncodeBlockForServer (which bumps the magic by +1,
// per tde2e/td/e2e/Blockchain.cpp::from_local_to_server).
func EncodeBlock(block *Block) ([]byte, error) {
	var buf bytes.Buffer
	writeU32(&buf, crcBlock)
	buf.Write(block.Signature[:])
	flags := uint32(0)
	if block.SignaturePublicKey != nil {
		flags |= 1 << 0
	}
	writeU32(&buf, flags)
	buf.Write(block.PrevBlockHash[:])
	if err := writeChanges(&buf, block.Changes); err != nil {
		return nil, err
	}
	writeI32(&buf, block.Height)
	if err := writeStateProof(&buf, &block.StateProof); err != nil {
		return nil, err
	}
	if block.SignaturePublicKey != nil {
		buf.Write(block.SignaturePublicKey[:])
	}
	return buf.Bytes(), nil
}

// EncodeBlockForSignature is EncodeBlock with the signature field
// zeroed — the byte string covered by the Ed25519 signature.
func EncodeBlockForSignature(block *Block) ([]byte, error) {
	cp := *block
	cp.Signature = [64]byte{}
	return EncodeBlock(&cp)
}

// EncodeBlockForHash is the byte string fed into SHA256 for the
// block_hash. Same as EncodeBlock (signature included).
func EncodeBlockForHash(block *Block) ([]byte, error) { return EncodeBlock(block) }

// EncodeBlockForServer produces the wire bytes Telegram expects for
// phone.sendConferenceCallBroadcast / phone.createConferenceCall.
// It bumps the leading magic by +1 — see
// tde2e/td/e2e/Blockchain.cpp::from_local_to_server.
func EncodeBlockForServer(block *Block) ([]byte, error) {
	enc, err := EncodeBlock(block)
	if err != nil {
		return nil, err
	}
	if len(enc) < 4 {
		return nil, errors.New("e2e: block too short to patch magic")
	}
	mag := binary.LittleEndian.Uint32(enc[:4])
	binary.LittleEndian.PutUint32(enc[:4], mag+1)
	return enc, nil
}

// writeChanges writes vector<e2e.chain.Change> in TDLib's bare-vector
// format: int32 count followed by elements. NO 0x1cb5c415 vector CRC
// is written — TDLib's tl_helpers.h store<vector<T>> uses store_binary
// for the size and recurses on each element, with no CRC prefix.
func writeChanges(buf *bytes.Buffer, changes []Change) error {
	writeU32(buf, uint32(len(changes)))
	for _, ch := range changes {
		if err := writeChange(buf, ch); err != nil {
			return err
		}
	}
	return nil
}

func writeChange(buf *bytes.Buffer, ch Change) error {
	switch v := ch.(type) {
	case *ChangeNoop:
		writeU32(buf, crcChangeNoop)
		buf.Write(v.Nonce[:])
		return nil
	case *ChangeSetValue:
		writeU32(buf, crcChangeSetValue)
		writeBytes(buf, v.Key)
		writeBytes(buf, v.Value)
		return nil
	case *ChangeSetGroupState:
		writeU32(buf, crcChangeSetGroupState)
		return writeGroupState(buf, &v.GroupState)
	case *ChangeSetSharedKey:
		writeU32(buf, crcChangeSetSharedKey)
		return writeSharedKey(buf, &v.SharedKey)
	default:
		return fmt.Errorf("unknown change %T", v)
	}
}

func writeGroupState(buf *bytes.Buffer, gs *GroupState) error {
	writeU32(buf, crcGroupState)
	writeU32(buf, uint32(len(gs.Participants)))
	for _, p := range gs.Participants {
		writeGroupParticipant(buf, &p)
	}
	writeI32(buf, gs.ExternalPermissions)
	return nil
}

func writeGroupParticipant(buf *bytes.Buffer, p *GroupParticipant) {
	writeU32(buf, crcGroupParticipant)
	writeI64(buf, p.UserID)
	buf.Write(p.PublicKey[:])
	flags := uint32(0)
	if p.AddUsers {
		flags |= 1 << 0
	}
	if p.RemoveUsers {
		flags |= 1 << 1
	}
	writeU32(buf, flags)
	writeI32(buf, p.Version)
}

func writeSharedKey(buf *bytes.Buffer, sk *SharedKeyTL) error {
	writeU32(buf, crcSharedKey)
	buf.Write(sk.EphemeralKey[:])
	writeBytes(buf, []byte(sk.EncryptedSharedKey))
	writeU32(buf, uint32(len(sk.DestUserID)))
	for _, u := range sk.DestUserID {
		writeI64(buf, u)
	}
	writeU32(buf, uint32(len(sk.DestHeader)))
	for _, h := range sk.DestHeader {
		writeBytes(buf, h)
	}
	return nil
}

func writeStateProof(buf *bytes.Buffer, sp *StateProof) error {
	writeU32(buf, crcStateProof)
	flags := uint32(0)
	if sp.GroupState != nil {
		flags |= 1 << 0
	}
	if sp.SharedKey != nil {
		flags |= 1 << 1
	}
	writeU32(buf, flags)
	buf.Write(sp.KVHash[:])
	if sp.GroupState != nil {
		if err := writeGroupState(buf, sp.GroupState); err != nil {
			return err
		}
	}
	if sp.SharedKey != nil {
		if err := writeSharedKey(buf, sp.SharedKey); err != nil {
			return err
		}
	}
	return nil
}

// ── Decode ─────────────────────────────────────────────────────────────

// DecodeBlock accepts either the local-form magic (crcBlock) or the
// server-form magic (crcBlock+1). For wire blocks coming from
// UpdateGroupCallChainBlocks, the server-form is used.
func DecodeBlock(data []byte) (*Block, error) {
	r := &reader{b: data}
	mag := r.readU32()
	if mag != crcBlock && mag != crcBlock+1 {
		return nil, fmt.Errorf("e2e: not a block (magic=%#x)", mag)
	}
	b := &Block{}
	r.readFull(b.Signature[:])
	flags := r.readU32()
	r.readFull(b.PrevBlockHash[:])
	n := r.readU32()
	for i := uint32(0); i < n; i++ {
		ch, err := readChange(r)
		if err != nil {
			return nil, err
		}
		b.Changes = append(b.Changes, ch)
	}
	b.Height = r.readI32()
	sp, err := readStateProof(r)
	if err != nil {
		return nil, err
	}
	b.StateProof = sp
	if flags&1 != 0 {
		var pk [32]byte
		r.readFull(pk[:])
		b.SignaturePublicKey = &pk
	}
	if r.err != nil {
		return nil, r.err
	}
	return b, nil
}

func readChange(r *reader) (Change, error) {
	tag := r.readU32()
	switch tag {
	case crcChangeNoop:
		ch := &ChangeNoop{}
		r.readFull(ch.Nonce[:])
		return ch, nil
	case crcChangeSetValue:
		return &ChangeSetValue{Key: r.readBytes(), Value: r.readBytes()}, nil
	case crcChangeSetGroupState:
		gs, err := readGroupState(r)
		if err != nil {
			return nil, err
		}
		return &ChangeSetGroupState{GroupState: gs}, nil
	case crcChangeSetSharedKey:
		sk, err := readSharedKey(r)
		if err != nil {
			return nil, err
		}
		return &ChangeSetSharedKey{SharedKey: sk}, nil
	default:
		return nil, fmt.Errorf("e2e: unknown change crc %#x", tag)
	}
}

func readGroupState(r *reader) (GroupState, error) {
	if r.readU32() != crcGroupState {
		return GroupState{}, errors.New("e2e: expected groupState crc")
	}
	n := r.readU32()
	gs := GroupState{}
	for i := uint32(0); i < n; i++ {
		gp, err := readGroupParticipant(r)
		if err != nil {
			return gs, err
		}
		gs.Participants = append(gs.Participants, gp)
	}
	gs.ExternalPermissions = r.readI32()
	return gs, nil
}

func readGroupParticipant(r *reader) (GroupParticipant, error) {
	if r.readU32() != crcGroupParticipant {
		return GroupParticipant{}, errors.New("e2e: expected groupParticipant crc")
	}
	gp := GroupParticipant{}
	gp.UserID = r.readI64()
	r.readFull(gp.PublicKey[:])
	flags := r.readU32()
	gp.AddUsers = flags&(1<<0) != 0
	gp.RemoveUsers = flags&(1<<1) != 0
	gp.Version = r.readI32()
	return gp, nil
}

func readSharedKey(r *reader) (SharedKeyTL, error) {
	if r.readU32() != crcSharedKey {
		return SharedKeyTL{}, errors.New("e2e: expected sharedKey crc")
	}
	sk := SharedKeyTL{}
	r.readFull(sk.EphemeralKey[:])
	sk.EncryptedSharedKey = string(r.readBytes())
	n := r.readU32()
	for i := uint32(0); i < n; i++ {
		sk.DestUserID = append(sk.DestUserID, r.readI64())
	}
	n = r.readU32()
	for i := uint32(0); i < n; i++ {
		sk.DestHeader = append(sk.DestHeader, r.readBytes())
	}
	return sk, nil
}

func readStateProof(r *reader) (StateProof, error) {
	if r.readU32() != crcStateProof {
		return StateProof{}, errors.New("e2e: expected stateProof crc")
	}
	sp := StateProof{}
	flags := r.readU32()
	r.readFull(sp.KVHash[:])
	if flags&(1<<0) != 0 {
		gs, err := readGroupState(r)
		if err != nil {
			return sp, err
		}
		sp.GroupState = &gs
	}
	if flags&(1<<1) != 0 {
		sk, err := readSharedKey(r)
		if err != nil {
			return sp, err
		}
		sp.SharedKey = &sk
	}
	return sp, nil
}

// ── primitive helpers ──────────────────────────────────────────────────

func writeU32(buf *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	buf.Write(tmp[:])
}

func writeI32(buf *bytes.Buffer, v int32) { writeU32(buf, uint32(v)) }

func writeI64(buf *bytes.Buffer, v int64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], uint64(v))
	buf.Write(tmp[:])
}

// TL "bytes": 1-byte length (or 0xfe + 3-byte LE length for >=254),
// payload, padded to 4-byte boundary.
func writeBytes(buf *bytes.Buffer, b []byte) {
	n := len(b)
	pad := 0
	if n < 254 {
		buf.WriteByte(byte(n))
		pad = (n + 1) % 4
	} else {
		buf.WriteByte(0xfe)
		buf.WriteByte(byte(n))
		buf.WriteByte(byte(n >> 8))
		buf.WriteByte(byte(n >> 16))
		pad = n % 4
	}
	buf.Write(b)
	if pad != 0 {
		for i := pad; i < 4; i++ {
			buf.WriteByte(0)
		}
	}
}

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) readU32() uint32 {
	if r.err != nil {
		return 0
	}
	if r.off+4 > len(r.b) {
		r.err = errors.New("e2e: short read u32")
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *reader) readI32() int32 { return int32(r.readU32()) }

func (r *reader) readI64() int64 {
	if r.err != nil {
		return 0
	}
	if r.off+8 > len(r.b) {
		r.err = errors.New("e2e: short read i64")
		return 0
	}
	v := int64(binary.LittleEndian.Uint64(r.b[r.off:]))
	r.off += 8
	return v
}

func (r *reader) readFull(dst []byte) {
	if r.err != nil {
		return
	}
	if r.off+len(dst) > len(r.b) {
		r.err = errors.New("e2e: short read")
		return
	}
	copy(dst, r.b[r.off:r.off+len(dst)])
	r.off += len(dst)
}

func (r *reader) readBytes() []byte {
	if r.err != nil {
		return nil
	}
	if r.off >= len(r.b) {
		r.err = errors.New("e2e: short read bytes head")
		return nil
	}
	first := r.b[r.off]
	r.off++
	var n int
	var pad int
	if first == 0xfe {
		if r.off+3 > len(r.b) {
			r.err = errors.New("e2e: short read bytes long")
			return nil
		}
		n = int(r.b[r.off]) | int(r.b[r.off+1])<<8 | int(r.b[r.off+2])<<16
		r.off += 3
		pad = n % 4
	} else {
		n = int(first)
		pad = (n + 1) % 4
	}
	if r.off+n > len(r.b) {
		r.err = errors.New("e2e: short read bytes body")
		return nil
	}
	out := make([]byte, n)
	copy(out, r.b[r.off:r.off+n])
	r.off += n
	if pad != 0 {
		r.off += 4 - pad
	}
	return out
}
