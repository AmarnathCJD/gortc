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
)

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

// EncodeNonceCommit serializes the commit message in the wire form that
// goes into phone.sendConferenceCallBroadcast.
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

// EncodeNonceReveal serializes the reveal message in the wire form that
// goes into phone.sendConferenceCallBroadcast.
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

// DecodeNonceCommit parses an inbound commit message.
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

// DecodeNonceReveal parses an inbound reveal message.
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

// BroadcastMagic returns the TL magic of a broadcast message, accepting
// both local and server-form (server-form is local + 1).
func BroadcastMagic(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}

// IsNonceCommit returns true if the wire bytes are a NonceCommit.
func IsNonceCommit(data []byte) bool {
	mag := BroadcastMagic(data)
	return mag == crcGroupBroadcastNonceCommit || mag == crcGroupBroadcastNonceCommit+1
}

// IsNonceReveal returns true if the wire bytes are a NonceReveal.
func IsNonceReveal(data []byte) bool {
	mag := BroadcastMagic(data)
	return mag == crcGroupBroadcastNonceReveal || mag == crcGroupBroadcastNonceReveal+1
}

// BuildNonceCommit constructs and signs a commit message. Returns both
// the signed message AND the secret nonce that the caller must hold
// onto for the subsequent reveal step.
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
	signed := EncodeNonceCommit(c) // signature field is zero
	sig := ed25519.Sign(priv, signed)
	copy(c.Signature[:], sig)
	return c, nonce, nil
}

// BuildNonceReveal constructs and signs a reveal message containing the
// previously-committed nonce.
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

// VerifyNonceCommit checks the ed25519 signature on a commit message.
func VerifyNonceCommit(pub ed25519.PublicKey, c *NonceCommit) bool {
	cp := *c
	cp.Signature = [64]byte{}
	signed := EncodeNonceCommit(&cp)
	return ed25519.Verify(pub, signed, c.Signature[:])
}

// VerifyNonceReveal checks signature AND that sha256(nonce) matches
// the previously-received commit hash.
func VerifyNonceReveal(pub ed25519.PublicKey, r *NonceReveal, expectedHash [32]byte) bool {
	if sha256.Sum256(r.Nonce[:]) != expectedHash {
		return false
	}
	cp := *r
	cp.Signature = [64]byte{}
	signed := EncodeNonceReveal(&cp)
	return ed25519.Verify(pub, signed, r.Signature[:])
}
