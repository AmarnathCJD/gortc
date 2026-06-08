// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// TL constructor CRCs (little-endian wire prefix):
//   e2e.callPacket            = 0x40a6bee9
//   e2e.callPacketLargeMsgId  = 0x1ce56c2d
var (
	magicCallPacket           = []byte{0xe9, 0xbe, 0xa6, 0x40}
	magicCallPacketLargeMsgID = []byte{0x2d, 0x6c, 0xe5, 0x1c}
)

const (
	tde2eEncryptData   = "tde2e_encrypt_data"
	tde2eEncryptHeader = "tde2e_encrypt_header"
	minPaddingForData  = 16
)

// EncryptDataTDE2E produces msg_id(16) || AES-CBC(random-prefix-padded data).
func EncryptDataTDE2E(secret, data []byte) ([]byte, error) {
	out, _, err := encryptDataWithExtra(secret, data, nil)
	return out, err
}

func EncryptDataTDE2EWithLargeMsgID(secret, data, extra []byte) ([]byte, [32]byte, error) {
	return encryptDataWithExtra(secret, data, extra)
}

func encryptDataWithExtra(secret, data, extra []byte) ([]byte, [32]byte, error) {
	var largeMsgID [32]byte
	prefixLen := ((minPaddingForData + 15 + len(data)) & ^15) - len(data)
	prefix := make([]byte, prefixLen)
	if _, err := rand.Read(prefix); err != nil {
		return nil, largeMsgID, err
	}
	prefix[0] = byte(prefixLen)

	padded := append(prefix, data...)

	large := hmacSHA512(secret, []byte(tde2eEncryptData))
	encSecret := large[:32]
	hmacSecret := large[32:64]

	tail := make([]byte, 0, len(padded)+len(extra)+4)
	tail = append(tail, padded...)
	tail = append(tail, extra...)
	var lenExtra [4]byte
	binary.LittleEndian.PutUint32(lenExtra[:], uint32(len(extra)))
	tail = append(tail, lenExtra[:]...)

	macMsgID := hmac.New(sha256.New, hmacSecret)
	macMsgID.Write(tail)
	copy(largeMsgID[:], macMsgID.Sum(nil))
	msgID := largeMsgID[:16]

	cbcKey, cbcIV := splitAesCBCFromHash(hmacSHA512(encSecret, msgID))
	block, err := aes.NewCipher(cbcKey)
	if err != nil {
		return nil, largeMsgID, err
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, cbcIV).CryptBlocks(ct, padded)

	out := make([]byte, 0, 16+len(ct))
	out = append(out, msgID...)
	out = append(out, ct...)
	return out, largeMsgID, nil
}

// EncryptHeaderTDE2E AES-CBC-encrypts a 32-byte one-time-secret under a key
// derived from the shared secret and the encrypted message's msg_id.
func EncryptHeaderTDE2E(oneTimeSecret, encryptedMessage, secret []byte) ([]byte, error) {
	if len(oneTimeSecret) != 32 {
		return nil, fmt.Errorf("encrypt_header: one_time_secret must be 32 bytes, got %d", len(oneTimeSecret))
	}
	if len(encryptedMessage) < 16 {
		return nil, errors.New("encrypt_header: encrypted_message too short for msg_id")
	}
	large := hmacSHA512(secret, []byte(tde2eEncryptHeader))
	encKey := large[:32]
	msgID := encryptedMessage[:16]

	cbcKey, cbcIV := splitAesCBCFromHash(hmacSHA512(encKey, msgID))
	block, err := aes.NewCipher(cbcKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 32)
	cipher.NewCBCEncrypter(block, cbcIV).CryptBlocks(out, oneTimeSecret)
	return out, nil
}

func DecryptHeaderTDE2E(encryptedHeader, encryptedMessage, secret []byte) ([]byte, error) {
	if len(encryptedHeader) != 32 {
		return nil, fmt.Errorf("decrypt_header: encrypted_header must be 32 bytes, got %d", len(encryptedHeader))
	}
	if len(encryptedMessage) < 16 {
		return nil, errors.New("decrypt_header: encrypted_message too short for msg_id")
	}
	large := hmacSHA512(secret, []byte(tde2eEncryptHeader))
	encKey := large[:32]
	msgID := encryptedMessage[:16]

	cbcKey, cbcIV := splitAesCBCFromHash(hmacSHA512(encKey, msgID))
	block, err := aes.NewCipher(cbcKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 32)
	cipher.NewCBCDecrypter(block, cbcIV).CryptBlocks(out, encryptedHeader)
	return out, nil
}

func DecryptDataTDE2E(secret, encrypted []byte) ([]byte, error) {
	plain, _, err := DecryptDataTDE2EWithExtra(secret, encrypted, nil)
	return plain, err
}

func DecryptDataTDE2EWithExtra(secret, encrypted, extra []byte) ([]byte, [32]byte, error) {
	var largeMsgID [32]byte
	if len(encrypted) < 16 {
		return nil, largeMsgID, errors.New("decrypt_data: too short for msg_id")
	}
	msgID := encrypted[:16]
	ct := encrypted[16:]
	if len(ct) == 0 || len(ct)%16 != 0 {
		return nil, largeMsgID, fmt.Errorf("decrypt_data: ciphertext length %d not multiple of 16", len(ct))
	}

	large := hmacSHA512(secret, []byte(tde2eEncryptData))
	encSecret := large[:32]
	hmacSecret := large[32:64]

	cbcKey, cbcIV := splitAesCBCFromHash(hmacSHA512(encSecret, msgID))
	block, err := aes.NewCipher(cbcKey)
	if err != nil {
		return nil, largeMsgID, err
	}
	padded := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, cbcIV).CryptBlocks(padded, ct)

	if len(padded) == 0 {
		return nil, largeMsgID, errors.New("decrypt_data: empty plaintext")
	}
	prefixLen := int(padded[0])
	if prefixLen < minPaddingForData || prefixLen > len(padded) {
		return nil, largeMsgID, fmt.Errorf("decrypt_data: bad prefix length %d", prefixLen)
	}
	tail := make([]byte, 0, len(padded)+len(extra)+4)
	tail = append(tail, padded...)
	tail = append(tail, extra...)
	var lenExtra [4]byte
	binary.LittleEndian.PutUint32(lenExtra[:], uint32(len(extra)))
	tail = append(tail, lenExtra[:]...)
	macMsgID := hmac.New(sha256.New, hmacSecret)
	macMsgID.Write(tail)
	copy(largeMsgID[:], macMsgID.Sum(nil))
	if !hmac.Equal(msgID, largeMsgID[:16]) {
		return nil, largeMsgID, errors.New("decrypt_data: msg_id mismatch")
	}
	return padded[prefixLen:], largeMsgID, nil
}

func RecoverGroupSharedKey(myPriv ed25519.PrivateKey, ek [32]byte, destHeader, encGroupSharedKey []byte) ([32]byte, error) {
	return recoverWithEKMode(myPriv, ek, destHeader, encGroupSharedKey, 0)
}

// raw Curve25519 pubkey (mode 1), then runs X25519 + TDE2E decryption as usual. This is used for the founder block, which has no previous epoch to copy the EK from.
func recoverWithEKMode(myPriv ed25519.PrivateKey, ek [32]byte, destHeader, encGroupSharedKey []byte, ekMode int) ([32]byte, error) {
	var out [32]byte
	xPriv, err := ed25519PrivToCurveScalar(myPriv)
	if err != nil {
		return out, fmt.Errorf("priv-to-scalar: %w", err)
	}
	var xPub []byte
	switch ekMode {
	case 0:
		xPub, err = ed25519PubToCurve(ek[:])
		if err != nil {
			return out, fmt.Errorf("pub-to-curve: %w", err)
		}
	case 1:
		xPub = ek[:]
	default:
		return out, fmt.Errorf("bad ek mode %d", ekMode)
	}
	raw, err := curve25519.X25519(xPriv, xPub)
	if err != nil {
		return out, fmt.Errorf("x25519: %w", err)
	}
	mac := hmacSHA512([]byte("tde2e_shared_secret"), raw)
	sharedSecret := mac[:32]
	oneTimeSecret, err := DecryptHeaderTDE2E(destHeader, encGroupSharedKey, sharedSecret)
	if err != nil {
		return out, fmt.Errorf("decrypt_header: %w", err)
	}
	plain, err := DecryptDataTDE2E(oneTimeSecret, encGroupSharedKey)
	if err != nil {
		return out, fmt.Errorf("decrypt_data: %w", err)
	}
	if len(plain) != 32 {
		return out, fmt.Errorf("group_shared_key length=%d, want 32", len(plain))
	}
	copy(out[:], plain)
	return out, nil
}

func splitAesCBCFromHash(h []byte) (key, iv []byte) {
	return h[:32], h[32:48]
}

// ComputeSharedSecretTDE2E returns HMAC-SHA512("tde2e_shared_secret", X25519(priv, peerPub))[:32].
func ComputeSharedSecretTDE2E(priv ed25519.PrivateKey, peerPub ed25519.PublicKey) ([]byte, error) {
	xPriv, err := ed25519PrivToCurveScalar(priv)
	if err != nil {
		return nil, err
	}
	xPub, err := ed25519PubToCurve(peerPub)
	if err != nil {
		return nil, err
	}
	raw, err := curve25519.X25519(xPriv, xPub)
	if err != nil {
		return nil, err
	}
	mac := hmacSHA512([]byte("tde2e_shared_secret"), raw)
	return mac[:32], nil
}

// ed25519PubToCurve: u = (1 + y) / (1 - y) mod p.
func ed25519PubToCurve(pub ed25519.PublicKey) ([]byte, error) {
	if len(pub) != 32 {
		return nil, fmt.Errorf("ed25519PubToCurve: need 32 bytes, got %d", len(pub))
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("ed25519PubToCurve: %w", err)
	}
	return p.BytesMontgomery(), nil
}

// ed25519PrivToCurveScalar derives the Curve25519 scalar from an Ed25519
// seed: SHA-512(seed)[:32] with RFC 7748 clamping.
func ed25519PrivToCurveScalar(priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519PrivToCurveScalar: bad size %d", len(priv))
	}
	seed := priv.Seed()
	h := sha512.Sum512(seed)
	out := make([]byte, 32)
	copy(out, h[:32])
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out, nil
}

func BuildSharedKey(participants []GroupParticipant) (SharedKeyTL, error) {
	ePub, ePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SharedKeyTL{}, fmt.Errorf("eph keygen: %w", err)
	}

	var groupSharedKey [32]byte
	if _, err := rand.Read(groupSharedKey[:]); err != nil {
		return SharedKeyTL{}, err
	}
	var oneTimeSecret [32]byte
	if _, err := rand.Read(oneTimeSecret[:]); err != nil {
		return SharedKeyTL{}, err
	}

	encGroupSharedKey, err := EncryptDataTDE2E(oneTimeSecret[:], groupSharedKey[:])
	if err != nil {
		return SharedKeyTL{}, fmt.Errorf("encrypt_data: %w", err)
	}

	destUserID := make([]int64, 0, len(participants))
	destHeader := make([][]byte, 0, len(participants))
	for _, p := range participants {
		sharedSecret, err := ComputeSharedSecretTDE2E(ePriv, p.PublicKey[:])
		if err != nil {
			return SharedKeyTL{}, fmt.Errorf("ecdh for uid=%d: %w", p.UserID, err)
		}
		hdr, err := EncryptHeaderTDE2E(oneTimeSecret[:], encGroupSharedKey, sharedSecret)
		if err != nil {
			return SharedKeyTL{}, fmt.Errorf("encrypt_header for uid=%d: %w", p.UserID, err)
		}
		destUserID = append(destUserID, p.UserID)
		destHeader = append(destHeader, hdr)
	}

	var ek [32]byte
	copy(ek[:], ePub)
	return SharedKeyTL{
		EphemeralKey:       ek,
		EncryptedSharedKey: string(encGroupSharedKey),
		DestUserID:         destUserID,
		DestHeader:         destHeader,
	}, nil
}

func hmacSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// DeriveGroupSharedKey returns HMAC-SHA512(raw, blockHash)[0:32].
func DeriveGroupSharedKey(raw [32]byte, blockHash [32]byte) [32]byte {
	mac := hmacSHA512(raw[:], blockHash[:])
	var out [32]byte
	copy(out[:], mac[:32])
	return out
}

// ComputeSharedSecret performs raw X25519 ECDH.
func ComputeSharedSecret(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	var k [32]byte
	copy(k[:], out)
	return k, nil
}

// PacketCipher manages encryption state for outgoing packets and decrypts incoming packets, using the active epochs from the chain to determine which keys to use. It also tracks per-channel sequence numbers for replay protection.
type PacketCipher struct {
	chain *Chain
	self  ed25519.PrivateKey

	seqMu sync.Mutex
	seq   map[int32]uint32
}

type DecryptedPacket struct {
	ChannelID         int32
	Seq               uint32
	Payload           []byte
	UnencryptedPrefix []byte
}

func NewPacketCipher(chain *Chain, self ed25519.PrivateKey) *PacketCipher {
	return &PacketCipher{
		chain: chain,
		self:  self,
		seq:   make(map[int32]uint32),
	}
}

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

// EncryptPacket wraps a media frame as a wire-form E2E packet.
// unencryptedHeaderLength is the cleartext prefix (0 for Opus, codec header
// size for VP8/H264).
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

	headerA := make([]byte, 0, 4+len(epochs)*32)
	headerA = appendI32LE(headerA, int32(len(epochs)))
	for _, ep := range epochs {
		headerA = append(headerA, ep.BlockHash[:]...)
	}

	var oneTimeSecret [32]byte
	if _, err := rand.Read(oneTimeSecret[:]); err != nil {
		return nil, fmt.Errorf("e2e: rand: %w", err)
	}

	seq, err := pc.nextSeq(channelID)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 8+len(decryptedData))
	payload = appendI32LE(payload, channelID)
	payload = appendU32LE(payload, seq)
	payload = append(payload, decryptedData...)

	extra := make([]byte, 0, 4+len(headerA)+len(unencryptedPrefix))
	extra = append(extra, magicCallPacket...)
	extra = append(extra, headerA...)
	extra = append(extra, unencryptedPrefix...)

	encryptedPayload, largeMsgID, err := EncryptDataTDE2EWithLargeMsgID(oneTimeSecret[:], payload, extra)
	if err != nil {
		return nil, fmt.Errorf("e2e: encrypt_data: %w", err)
	}

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

	toSign := make([]byte, 0, 4+32)
	toSign = append(toSign, magicCallPacketLargeMsgID...)
	toSign = append(toSign, largeMsgID[:]...)
	sig := ed25519.Sign(pc.self, toSign)

	encryptedPacket := make([]byte, 0, len(encryptedPayload)+len(sig))
	encryptedPacket = append(encryptedPacket, encryptedPayload...)
	encryptedPacket = append(encryptedPacket, sig...)

	out := make([]byte, 0, len(unencryptedPrefix)+len(headerA)+len(headerB)+len(encryptedPacket)+4)
	out = append(out, unencryptedPrefix...)
	out = append(out, headerA...)
	out = append(out, headerB...)
	out = append(out, encryptedPacket...)
	out = appendU32LE(out, uint32(unencryptedHeaderLength))
	return out, nil
}

// DecryptIncomingPacket decrypts a remote packet, verifying its signature
// against the sender's public key (looked up by the caller via SSRC).
func (pc *PacketCipher) DecryptIncomingPacket(data []byte, senderPub ed25519.PublicKey) (*DecryptedPacket, error) {
	if len(data) < 4 {
		return nil, errors.New("e2e: packet too short")
	}
	prefixLen := int(binary.LittleEndian.Uint32(data[len(data)-4:]))
	if prefixLen < 0 || prefixLen >= (1<<16) || prefixLen > len(data)-4 {
		return nil, fmt.Errorf("e2e: bad trailer prefixLen %d", prefixLen)
	}
	body := data[prefixLen : len(data)-4]
	unencryptedPrefix := data[:prefixLen]
	if len(body) < 4 {
		return nil, errors.New("e2e: body too short for header_a")
	}
	n := int(binary.LittleEndian.Uint32(body[:4]))
	if n <= 0 {
		return nil, fmt.Errorf("e2e: bad epoch count %d", n)
	}
	headerALen := 4 + n*32
	headerBLen := n * 32
	if len(body) < headerALen+headerBLen+16+64 {
		return nil, fmt.Errorf("e2e: packet length %d too short for epochs=%d", len(body), n)
	}
	epochs := pc.chain.ActiveEpochs()
	if len(epochs) == 0 {
		return nil, errors.New("e2e: no active epoch")
	}
	headerA := body[:headerALen]
	headerB := body[headerALen : headerALen+headerBLen]
	encryptedPacket := body[headerALen+headerBLen:]
	if len(encryptedPacket) < 16+64 {
		return nil, errors.New("e2e: encrypted packet too short")
	}
	encryptedPayload := encryptedPacket[:len(encryptedPacket)-64]
	sig := encryptedPacket[len(encryptedPacket)-64:]
	extra := make([]byte, 0, 4+len(headerA)+len(unencryptedPrefix))
	extra = append(extra, magicCallPacket...)
	extra = append(extra, headerA...)
	extra = append(extra, unencryptedPrefix...)

	// msg_id check, and try every matching epoch.
	var plain []byte
	var largeMsgID [32]byte
	var lastErr error
	for j := range n {
		pktHash := headerA[4+j*32 : 4+(j+1)*32]
		for _, ep := range epochs {
			if string(pktHash) != string(ep.BlockHash[:]) {
				continue
			}
			ots, herr := DecryptHeaderTDE2E(headerB[j*32:(j+1)*32], encryptedPayload, ep.GroupSharedKey[:])
			if herr != nil {
				lastErr = herr
				continue
			}
			p, lmid, derr := DecryptDataTDE2EWithExtra(ots, encryptedPayload, extra)
			if derr != nil {
				lastErr = derr
				continue
			}
			plain = p
			largeMsgID = lmid
		}
		if plain != nil {
			break
		}
	}
	if plain == nil {
		if lastErr == nil {
			lastErr = errors.New("no matching epoch")
		}
		return nil, fmt.Errorf("e2e: decrypt failed: %w", lastErr)
	}
	toVerify := make([]byte, 0, 4+32)
	toVerify = append(toVerify, magicCallPacketLargeMsgID...)
	toVerify = append(toVerify, largeMsgID[:]...)
	if !ed25519.Verify(senderPub, toVerify, sig) {
		return nil, errors.New("e2e: signature verify failed")
	}
	if len(plain) < 8 {
		return nil, errors.New("e2e: plaintext too short")
	}
	return &DecryptedPacket{
		ChannelID:         int32(binary.LittleEndian.Uint32(plain[:4])),
		Seq:               binary.LittleEndian.Uint32(plain[4:8]),
		Payload:           plain[8:],
		UnencryptedPrefix: append([]byte(nil), unencryptedPrefix...),
	}, nil
}

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
