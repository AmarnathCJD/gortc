// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package phonecall

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	sigCustomID = 0x7f
	sigAckID    = 0xff
	sigEmptyID  = 0xfe

	sigSingleMessageBit = uint32(1) << 31
	sigRequiresAckBit   = uint32(1) << 30
	sigCounterMask      = ^(sigSingleMessageBit | sigRequiresAckBit)
)

type signaling struct {
	key        []byte
	isOutgoing bool

	mu       sync.Mutex
	outSeq   uint32
	seenIncl map[uint32]struct{}
	toAck    []uint32
}

func newSignaling(key []byte, isOutgoing bool) *signaling {
	return &signaling{
		key:        key,
		isOutgoing: isOutgoing,
		seenIncl:   make(map[uint32]struct{}),
	}
}

func counterFromSeq(seq uint32) uint32 { return seq & sigCounterMask }

func (s *signaling) encryptMessage(json []byte) ([]byte, error) {
	s.mu.Lock()
	s.outSeq++
	seq := s.outSeq | sigRequiresAckBit
	s.mu.Unlock()

	body := make([]byte, 0, 4+1+4+len(json))
	body = appendUint32(body, seq)
	body = append(body, sigCustomID)
	body = appendUint32(body, uint32(len(json)))
	body = append(body, json...)

	return s.seal(body)
}

func (s *signaling) encryptAcks(seqs []uint32) ([]byte, error) {
	if len(seqs) == 0 {
		return nil, nil
	}
	s.mu.Lock()
	s.outSeq++
	headSeq := s.outSeq
	s.mu.Unlock()

	body := make([]byte, 0, 5+len(seqs)*5)
	body = appendUint32(body, headSeq)
	body = append(body, sigEmptyID)
	for _, seq := range seqs {
		body = appendUint32(body, seq)
		body = append(body, sigAckID)
	}
	return s.seal(body)
}

func (s *signaling) drainAcks() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.toAck) == 0 {
		return nil
	}
	out := s.toAck
	s.toAck = nil
	return out
}

func (s *signaling) decryptMessages(packet []byte) ([][]byte, error) {
	body, err := s.open(packet)
	if err != nil {
		return nil, err
	}
	if len(body) < 4 {
		return nil, fmt.Errorf("signaling packet too short after decrypt")
	}

	seq := binary.BigEndian.Uint32(body[:4])
	pos := 4
	single := seq&sigSingleMessageBit != 0

	var out [][]byte
	additional := false
	for {
		if pos >= len(body) {
			break
		}
		typ := body[pos]
		pos++
		switch typ {
		case sigEmptyID:
		case sigAckID:
		case sigCustomID:
			if pos+4 > len(body) {
				return nil, fmt.Errorf("signaling custom message truncated length")
			}
			n := int(binary.BigEndian.Uint32(body[pos : pos+4]))
			pos += 4
			if n < 0 || pos+n > len(body) {
				return nil, fmt.Errorf("signaling custom message truncated body")
			}
			msg := make([]byte, n)
			copy(msg, body[pos:pos+n])
			pos += n
			out = append(out, msg)
			if seq&sigRequiresAckBit != 0 {
				s.mu.Lock()
				s.toAck = append(s.toAck, seq)
				s.mu.Unlock()
			}
		default:
			return nil, fmt.Errorf("signaling unknown record type 0x%02x", typ)
		}
		if pos >= len(body) {
			break
		}
		if single {
			return nil, fmt.Errorf("single-message packet had trailing data")
		}
		if pos+4 > len(body) {
			return nil, fmt.Errorf("signaling trailing record truncated seq")
		}
		seq = binary.BigEndian.Uint32(body[pos : pos+4])
		pos += 4
		additional = true
		_ = additional
	}
	return out, nil
}

func (s *signaling) seal(plaintext []byte) ([]byte, error) {
	x := 128
	if !s.isOutgoing {
		x += 8
	}
	msgKey := s.messageKey(plaintext, x)
	out := make([]byte, 16+len(plaintext))
	copy(out[:16], msgKey)
	stream, err := s.ctrStream(msgKey, x)
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(out[16:], plaintext)
	return out, nil
}

func (s *signaling) open(packet []byte) ([]byte, error) {
	if len(packet) < 21 {
		return nil, fmt.Errorf("signaling packet too short (%d bytes)", len(packet))
	}
	x := 128
	if s.isOutgoing {
		x += 8
	}
	msgKey := packet[:16]
	stream, err := s.ctrStream(msgKey, x)
	if err != nil {
		return nil, err
	}
	body := make([]byte, len(packet)-16)
	stream.XORKeyStream(body, packet[16:])

	want := s.messageKey(body, x)
	if subtle.ConstantTimeCompare(want, msgKey) != 1 {
		return nil, fmt.Errorf("signaling msg_key mismatch")
	}

	counter := counterFromSeq(binary.BigEndian.Uint32(body[:4]))
	s.mu.Lock()
	if _, dup := s.seenIncl[counter]; dup {
		s.mu.Unlock()
		return nil, fmt.Errorf("duplicate signaling packet %d", counter)
	}
	s.seenIncl[counter] = struct{}{}
	s.mu.Unlock()
	return body, nil
}

func (s *signaling) messageKey(plaintext []byte, x int) []byte {
	h := sha256.New()
	h.Write(s.key[88+x : 88+x+32])
	h.Write(plaintext)
	full := h.Sum(nil)
	return full[8:24]
}

func (s *signaling) ctrStream(msgKey []byte, x int) (cipher.Stream, error) {
	aesKey, aesIV := s.aesKeyIV(msgKey, x)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	return cipher.NewCTR(block, aesIV), nil
}

func (s *signaling) aesKeyIV(msgKey []byte, x int) (key, iv []byte) {
	a := sha256.New()
	a.Write(msgKey[:16])
	a.Write(s.key[x : x+36])
	sha256a := a.Sum(nil)

	b := sha256.New()
	b.Write(s.key[40+x : 40+x+36])
	b.Write(msgKey[:16])
	sha256b := b.Sum(nil)

	key = make([]byte, 0, 32)
	key = append(key, sha256a[0:8]...)
	key = append(key, sha256b[8:24]...)
	key = append(key, sha256a[24:32]...)

	iv = make([]byte, 0, 16)
	iv = append(iv, sha256b[0:4]...)
	iv = append(iv, sha256a[8:16]...)
	iv = append(iv, sha256b[24:28]...)
	return key, iv
}

func appendUint32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}
