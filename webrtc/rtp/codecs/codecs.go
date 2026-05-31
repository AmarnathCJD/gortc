// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package codecs

func minInt(a, b int) int {
	if a < b {
		return a
	}

	return b
}

type OpusPayloader struct{}

func (p *OpusPayloader) Payload(_ uint16, payload []byte) [][]byte {
	if payload == nil {
		return [][]byte{}
	}

	out := make([]byte, len(payload))
	copy(out, payload)

	return [][]byte{out}
}

type VP8Payloader struct {
	EnablePictureID bool
	pictureID       uint16
}

const (
	vp8HeaderSize = 1
)

func (p *VP8Payloader) Payload(mtu uint16, payload []byte) [][]byte {
	usingHeaderSize := vp8HeaderSize
	if p.EnablePictureID {
		switch {
		case p.pictureID == 0:
		case p.pictureID < 128:
			usingHeaderSize = vp8HeaderSize + 2
		default:
			usingHeaderSize = vp8HeaderSize + 3
		}
	}

	maxFragmentSize := int(mtu) - usingHeaderSize

	payloadData := payload
	payloadDataRemaining := len(payload)

	payloadDataIndex := 0
	var payloads [][]byte

	if minInt(maxFragmentSize, payloadDataRemaining) <= 0 {
		return payloads
	}
	first := true
	for payloadDataRemaining > 0 {
		currentFragmentSize := minInt(maxFragmentSize, payloadDataRemaining)
		out := make([]byte, usingHeaderSize+currentFragmentSize)

		if first {
			out[0] = 0x10
			first = false
		}
		if p.EnablePictureID {
			switch usingHeaderSize {
			case vp8HeaderSize:
			case vp8HeaderSize + 2:
				out[0] |= 0x80
				out[1] |= 0x80
				out[2] |= uint8(p.pictureID & 0x7F)
			case vp8HeaderSize + 3:
				out[0] |= 0x80
				out[1] |= 0x80
				out[2] |= 0x80 | uint8((p.pictureID>>8)&0x7F)
				out[3] |= uint8(p.pictureID & 0xFF)
			}
		}

		copy(out[usingHeaderSize:], payloadData[payloadDataIndex:payloadDataIndex+currentFragmentSize])
		payloads = append(payloads, out)

		payloadDataRemaining -= currentFragmentSize
		payloadDataIndex += currentFragmentSize
	}

	p.pictureID++
	p.pictureID &= 0x7FFF

	return payloads
}
