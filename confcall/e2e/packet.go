// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// PacketCipher wraps and unwraps audio/video frames for an active call,
// matching tdlib's tde2e/td/e2e/Call.cpp::CallEncryption::encrypt /
// CallEncryption::decrypt byte-for-byte.
//
// Outgoing frame layout:
//
//	unencrypted_prefix || header_a || header_b || encrypted_packet || trailer
//
// where:
//
//	unencrypted_prefix = data[0:unencryptedHeaderLength]
//	header_a           = int32_LE(epochs_count) || epoch_hash[0] || epoch_hash[1] || ...
//	header_b           = encrypted_header[0] || encrypted_header[1] || ...  (each 32 bytes)
//	encrypted_packet   = encryptDataTDE2E(payload, one_time_secret, extra) || ed25519_signature
//	trailer            = u32_LE(unencryptedHeaderLength)
//
// And:
//
//	payload = int32_LE(channel_id) || u32_LE(seqno) || data[unencryptedHeaderLength:]
//	extra   = magic(e2e.callPacket) || header_a || unencrypted_prefix
//	to_sign = magic(e2e.callPacketLargeMsgId) || large_msg_id  (32 bytes)
type PacketCipher struct {
	chain *Chain
	self  ed25519.PrivateKey

	seqMu sync.Mutex
	seq   map[int32]uint32 // per channel_id
}

func NewPacketCipher(chain *Chain, self ed25519.PrivateKey) *PacketCipher {
	return &PacketCipher{
		chain: chain,
		self:  self,
		seq:   make(map[int32]uint32),
	}
}

// nextSeq matches tdlib's `auto &seqno = seqno_[channel_id]; seqno++;`.
// Seqno starts at 1 (the first ++ from 0).
func (pc *PacketCipher) nextSeq(channelID int32) (uint32, error) {
	pc.seqMu.Lock()
	defer pc.seqMu.Unlock()
	cur := pc.seq[channelID]
	if cur == ^uint32(0) {
		return 0, errors.New("e2e: seqno overflow — must leave the call")
	}
	cur++
	pc.seq[channelID] = cur
	return cur, nil
}

// EncryptPacket transforms a media frame into the wire-form E2E packet
// per the layout described on PacketCipher. unencryptedHeaderLength is
// the number of leading bytes that stay in cleartext (the SFU may need
// to peek at codec start codes / RTP-ish fields). For Opus, tdesktop's
// FrameTransformer passes 0. For VP8/H264, it passes the codec's
// plaintext header size.
func (pc *PacketCipher) EncryptPacket(channelID int32, data []byte, unencryptedHeaderLength int) ([]byte, error) {
	if unencryptedHeaderLength < 0 || unencryptedHeaderLength > len(data) || unencryptedHeaderLength >= (1<<16) {
		return nil, fmt.Errorf("e2e: invalid unencryptedHeaderLength %d (data=%d)", unencryptedHeaderLength, len(data))
	}
	if channelID < 0 || channelID > 1023 {
		return nil, fmt.Errorf("e2e: invalid channel_id %d", channelID)
	}

	epochs := pc.chain.ActiveEpochs()
	if len(epochs) == 0 {
		return nil, errors.New("e2e: no active epoch")
	}

	unencryptedPrefix := data[:unencryptedHeaderLength]
	decryptedData := data[unencryptedHeaderLength:]

	// header_a = int32_LE(epochs_count) || epoch_hash[0] || ...
	headerA := make([]byte, 0, 4+len(epochs)*32)
	headerA = appendI32LE(headerA, int32(len(epochs)))
	for _, ep := range epochs {
		headerA = append(headerA, ep.BlockHash[:]...)
	}

	// one_time_secret (32 random bytes)
	var oneTimeSecret [32]byte
	if _, err := rand.Read(oneTimeSecret[:]); err != nil {
		return nil, fmt.Errorf("e2e: rand: %w", err)
	}

	// payload = int32_LE(channel_id) || u32_LE(seqno) || decryptedData
	seq, err := pc.nextSeq(channelID)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 4+4+len(decryptedData))
	payload = appendI32LE(payload, channelID)
	payload = appendU32LE(payload, seq)
	payload = append(payload, decryptedData...)

	// extra (additional data) = magic(callPacket) || header_a || unencrypted_prefix
	extra := make([]byte, 0, 4+len(headerA)+len(unencryptedPrefix))
	extra = append(extra, magicCallPacket...)
	extra = append(extra, headerA...)
	extra = append(extra, unencryptedPrefix...)

	encryptedPayload, largeMsgID, err := EncryptDataTDE2EWithLargeMsgID(oneTimeSecret[:], payload, extra)
	if err != nil {
		return nil, fmt.Errorf("e2e: encrypt_data: %w", err)
	}

	// header_b = encrypted_header[0] || encrypted_header[1] || ...
	// each is 32 bytes, AES-CBC of one_time_secret under epoch.secret_.
	headerB := make([]byte, 0, len(epochs)*32)
	for _, ep := range epochs {
		secret := ep.GroupSharedKey
		eh, err := EncryptHeaderTDE2E(oneTimeSecret[:], encryptedPayload, secret[:])
		if err != nil {
			return nil, fmt.Errorf("e2e: encrypt_header: %w", err)
		}
		if len(eh) != 32 {
			return nil, fmt.Errorf("e2e: encrypt_header returned %d bytes, want 32", len(eh))
		}
		headerB = append(headerB, eh...)
	}

	// signature = ed25519(self, magic(callPacketLargeMsgId) || large_msg_id)
	toSign := make([]byte, 0, 4+32)
	toSign = append(toSign, magicCallPacketLargeMsgID...)
	toSign = append(toSign, largeMsgID[:]...)
	sig := ed25519.Sign(pc.self, toSign)

	encryptedPacket := make([]byte, 0, len(encryptedPayload)+len(sig))
	encryptedPacket = append(encryptedPacket, encryptedPayload...)
	encryptedPacket = append(encryptedPacket, sig...)

	// trailer = u32_LE(unencryptedHeaderLength)
	var trailer [4]byte
	binary.LittleEndian.PutUint32(trailer[:], uint32(unencryptedHeaderLength))

	// Final = unencrypted_prefix || header_a || header_b || encrypted_packet || trailer
	out := make([]byte, 0, len(unencryptedPrefix)+len(headerA)+len(headerB)+len(encryptedPacket)+4)
	out = append(out, unencryptedPrefix...)
	out = append(out, headerA...)
	out = append(out, headerB...)
	out = append(out, encryptedPacket...)
	out = append(out, trailer[:]...)
	return out, nil
}

// little-endian append helpers
func appendI32LE(b []byte, v int32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(v))
	return append(b, buf[:]...)
}

func appendU32LE(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}
