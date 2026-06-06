package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestZeroBlockRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := BuildZeroBlock(priv, 12345)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBlock(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Height != 0 {
		t.Fatalf("height: got %d", decoded.Height)
	}
	if !bytes.Equal(decoded.Signature[:], block.Signature[:]) {
		t.Fatalf("signature differs after round-trip")
	}
	if decoded.SignaturePublicKey == nil {
		t.Fatal("signature_public_key dropped")
	}
}

func TestChainRejectsBadPrevHash(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	chain := NewChain(priv)
	chain.SetSelfUserID(12345)
	zero, _ := BuildZeroBlock(priv, 12345)
	if err := chain.ApplyBlock(zero); err != nil {
		t.Fatal(err)
	}
	bad := &Block{
		Height:        1,
		PrevBlockHash: [32]byte{0xff, 0xff}, // wrong
		Changes:       []Change{&ChangeNoop{Nonce: [32]byte{1}}},
	}
	signed, _ := EncodeBlockForSignature(bad)
	sig := ed25519.Sign(priv, signed)
	copy(bad.Signature[:], sig)
	if err := chain.ApplyBlock(bad); err == nil {
		t.Fatal("expected prev_hash error")
	}
}

func TestEmojiStable(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	chain := NewChain(priv)
	chain.SetSelfUserID(12345)
	zero, _ := BuildZeroBlock(priv, 12345)
	if err := chain.ApplyBlock(zero); err != nil {
		t.Fatal(err)
	}
	em1 := chain.EmojiFingerprint()
	em2 := chain.EmojiFingerprint()
	if len(em1) != 4 {
		t.Fatalf("want 4 emojis, got %v", em1)
	}
	for i := range em1 {
		if em1[i] != em2[i] {
			t.Fatalf("emoji not stable: %v vs %v", em1, em2)
		}
	}
}
