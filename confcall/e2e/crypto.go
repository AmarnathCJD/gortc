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

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// Magic CRCs from the e2e_api.tl schema:
//
//	e2e_callPacket::ID            = 1084669673  (0x40a76029)
//	e2e_callPacketLargeMsgId::ID  =  484797485  (0x1cea882d)
//
// They appear as 4-byte little-endian prefixes in the call-packet
// associated-data layout per tdlib's Call.cpp::encrypt.
var (
	magicCallPacket           = []byte{0xe9, 0xbe, 0xa6, 0x40}
	magicCallPacketLargeMsgID = []byte{0x2d, 0x6c, 0xe5, 0x1c}
)

const (
	tde2eEncryptData   = "tde2e_encrypt_data"
	tde2eEncryptHeader = "tde2e_encrypt_header"
	minPaddingForData  = 16
)

// EncryptDataTDE2E mirrors tde2e/td/e2e/MessageEncryption.cpp::encrypt_data.
// Output layout: msg_id(16 bytes) || AES-CBC(data with random prefix).
// The msg_id is HMAC-SHA256(hmac_secret, padded_data || extra || u32(extra)).
func EncryptDataTDE2E(secret, data []byte) ([]byte, error) {
	out, _, err := encryptDataWithExtra(secret, data, nil)
	return out, err
}

// EncryptDataTDE2EWithLargeMsgID is the same as EncryptDataTDE2E but
// also returns the 32-byte large_msg_id (the full HMAC-SHA256 result —
// msg_id is its first 16 bytes). Used by the call-packet encryption
// path which signs the large_msg_id separately.
func EncryptDataTDE2EWithLargeMsgID(secret, data, extra []byte) (out []byte, largeMsgID [32]byte, err error) {
	return encryptDataWithExtra(secret, data, extra)
}

func encryptDataWithExtra(secret, data, extra []byte) ([]byte, [32]byte, error) {
	var largeMsgID [32]byte
	// Prefix length is deterministic, NOT random — see TDLib's
	// MessageEncryption::gen_random_prefix:
	//   buff_size = ((MIN_PADDING + 15 + data_size) & ~15) - data_size
	// Only the bytes are random; the length is fixed by data_size.
	prefixLen := ((minPaddingForData + 15 + len(data)) & ^15) - len(data)
	prefix := make([]byte, prefixLen)
	if _, err := rand.Read(prefix); err != nil {
		return nil, largeMsgID, err
	}
	prefix[0] = byte(prefixLen)

	padded := append(prefix, data...)

	// Derive sub-keys.
	large := hmacSHA512(secret, []byte(tde2eEncryptData))
	encSecret := large[:32]
	hmacSecret := large[32:64]

	// large_msg_id = HMAC-SHA256(hmac_secret, padded || extra || u32_le(len(extra)))
	// msg_id = large_msg_id[0:16]
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

	// Derive AES-CBC key+IV.
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

// EncryptHeaderTDE2E mirrors tde2e/td/e2e/MessageEncryption.cpp::encrypt_header.
// Encrypts a 32-byte one-time-secret under AES-CBC keyed by the shared
// secret and IVed by the encrypted message's msg_id prefix.
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
	if len(encrypted) < 16 {
		return nil, errors.New("decrypt_data: too short for msg_id")
	}
	msgID := encrypted[:16]
	ct := encrypted[16:]
	if len(ct) == 0 || len(ct)%16 != 0 {
		return nil, fmt.Errorf("decrypt_data: ciphertext length %d not multiple of 16", len(ct))
	}

	large := hmacSHA512(secret, []byte(tde2eEncryptData))
	encSecret := large[:32]

	cbcKey, cbcIV := splitAesCBCFromHash(hmacSHA512(encSecret, msgID))
	block, err := aes.NewCipher(cbcKey)
	if err != nil {
		return nil, err
	}
	padded := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, cbcIV).CryptBlocks(padded, ct)

	if len(padded) == 0 {
		return nil, errors.New("decrypt_data: empty plaintext")
	}
	prefixLen := int(padded[0])
	if prefixLen < minPaddingForData || prefixLen > len(padded) {
		return nil, fmt.Errorf("decrypt_data: bad prefix length %d", prefixLen)
	}
	return padded[prefixLen:], nil
}

func RecoverGroupSharedKey(myPriv ed25519.PrivateKey, ek [32]byte, destHeader, encGroupSharedKey []byte) ([32]byte, error) {
	return recoverWithEKMode(myPriv, ek, destHeader, encGroupSharedKey, 0)
}

// recoverWithEKMode mode 0: treat ek as Ed25519 pubkey (edwards→montgomery).
// mode 1: treat ek as raw Curve25519 pubkey.
// Whichever mode, the X25519 raw output is fed through the same
// "tde2e_shared_secret" HMAC-SHA512[:32] KDF that PrivateKey::compute_shared_secret uses.
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

// ComputeSharedSecretTDE2E matches tde2e/Keys.cpp::PrivateKey::compute_shared_secret:
//   x25519 = Ed25519::compute_shared_secret(peer_pub, priv)
//   return HMAC-SHA512("tde2e_shared_secret", x25519)[:32]
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

// ed25519PubToCurve converts an Ed25519 public key (Edwards form) to
// the corresponding Curve25519 (Montgomery) public key.
//
// Formula: u = (1 + y) / (1 - y) mod p, where y is the Edwards y-coord.
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

// ed25519PrivToCurveScalar extracts the Curve25519 scalar from an
// Ed25519 private key by SHA-512'ing the 32-byte seed and clamping the
// low 32 bytes per RFC 7748.
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

// buildFounderSharedKey constructs the ChangeSetSharedKey payload for
// a freshly-created call. Algorithm mirrors tde2e/Call.cpp.
func buildFounderSharedKey(founderPriv ed25519.PrivateKey, participants []GroupParticipant) (SharedKeyTL, error) {
	// Ephemeral Ed25519 keypair (acts as the broadcast "ek").
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
	_ = founderPriv
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

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// DeriveGroupSharedKey: group_shared_key = HMAC-SHA512(raw, block_hash)[0:32]
func DeriveGroupSharedKey(raw [32]byte, blockHash [32]byte) [32]byte {
	mac := hmacSHA512(raw[:], blockHash[:])
	var out [32]byte
	copy(out[:], mac[:32])
	return out
}

// ComputeSharedSecret performs X25519 ECDH.
func ComputeSharedSecret(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	out, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	var k [32]byte
	copy(k[:], out)
	return k, nil
}

func readU32LE(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func appendU64LE(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}
