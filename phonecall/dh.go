// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package phonecall

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/amarnathcjd/gogram/telegram"
)

type dhParams struct {
	g int32
	p *big.Int
}

var bigOne = big.NewInt(1)

func getDH(client *telegram.Client) (*dhParams, error) {
	cfg, err := client.MessagesGetDhConfig(0, 256)
	if err != nil {
		return nil, fmt.Errorf("get dh config: %w", err)
	}
	obj, ok := cfg.(*telegram.MessagesDhConfigObj)
	if !ok {
		return nil, fmt.Errorf("unexpected dh config type %T", cfg)
	}
	p := new(big.Int).SetBytes(obj.P)
	dh := &dhParams{g: obj.G, p: p}
	if err := dh.checkPrime(); err != nil {
		return nil, err
	}
	return dh, nil
}

func (dh *dhParams) genGA() (a *big.Int, gA []byte, gAHash []byte, err error) {
	a, gAInt, err := dh.randomExp()
	if err != nil {
		return nil, nil, nil, err
	}
	gA = pad256(gAInt)
	sum := sha256.Sum256(gA)
	return a, gA, sum[:], nil
}

func (dh *dhParams) genGB() (b *big.Int, gB []byte, err error) {
	b, gBInt, err := dh.randomExp()
	if err != nil {
		return nil, nil, err
	}
	return b, pad256(gBInt), nil
}

func (dh *dhParams) computeKey(otherPub []byte, exp *big.Int) (key []byte, fingerprint int64, err error) {
	pub := new(big.Int).SetBytes(otherPub)
	if err := dh.checkValue(pub); err != nil {
		return nil, 0, err
	}
	shared := new(big.Int).Exp(pub, exp, dh.p)
	key = pad256(shared)
	sum := sha1.Sum(key)
	tail := sum[len(sum)-8:]
	for i := 0; i < 8; i++ {
		fingerprint |= int64(tail[i]) << (uint(i) * 8)
	}
	return key, fingerprint, nil
}

func (dh *dhParams) randomExp() (exp, pub *big.Int, err error) {
	buf := make([]byte, 256)
	if _, err := rand.Read(buf); err != nil {
		return nil, nil, fmt.Errorf("read random: %w", err)
	}
	exp = new(big.Int).SetBytes(buf)
	exp.Mod(exp, new(big.Int).Sub(dh.p, big.NewInt(2)))
	exp.Add(exp, big.NewInt(2))
	pub = new(big.Int).Exp(big.NewInt(int64(dh.g)), exp, dh.p)
	if err := dh.checkValue(pub); err != nil {
		return dh.randomExp()
	}
	return exp, pub, nil
}

func (dh *dhParams) checkValue(v *big.Int) error {
	if v.Cmp(bigOne) <= 0 {
		return fmt.Errorf("dh value out of range (too small)")
	}
	pMinusOne := new(big.Int).Sub(dh.p, bigOne)
	if v.Cmp(pMinusOne) >= 0 {
		return fmt.Errorf("dh value out of range (too large)")
	}
	return nil
}

func (dh *dhParams) checkPrime() error {
	if dh.p.BitLen() != 2048 {
		return fmt.Errorf("dh prime is not 2048 bits (got %d)", dh.p.BitLen())
	}
	if dh.p.Sign() <= 0 {
		return fmt.Errorf("dh prime is not positive")
	}
	return nil
}

func pad256(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 256 {
		return b
	}
	out := make([]byte, 256)
	copy(out[256-len(b):], b)
	return out
}
