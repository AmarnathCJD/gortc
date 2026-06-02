// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package webrtc

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

type VP9Payloader struct {
	pictureID uint16
	frames    uint32
}

func (p *VP9Payloader) Payload(mtu uint16, payload []byte) [][]byte {
	const hdrSize = 3
	maxFragment := int(mtu) - hdrSize
	if maxFragment <= 0 || len(payload) == 0 {
		return nil
	}

	isKeyframe := vp9IsKeyframe(payload)

	var out [][]byte
	idx := 0
	for idx < len(payload) {
		size := minInt(maxFragment, len(payload)-idx)
		buf := make([]byte, hdrSize+size)

		buf[0] = 0x80
		if !isKeyframe {
			buf[0] |= 0x40
		}
		if idx == 0 {
			buf[0] |= 0x08
		}
		if idx+size == len(payload) {
			buf[0] |= 0x04
		}
		buf[1] = 0x80 | byte((p.pictureID>>8)&0x7F)
		buf[2] = byte(p.pictureID & 0xFF)

		copy(buf[hdrSize:], payload[idx:idx+size])
		out = append(out, buf)
		idx += size
	}

	p.pictureID++
	if p.pictureID == 0 || p.pictureID > 0x7FFF {
		p.pictureID = 1
	}
	p.frames++
	return out
}

func vp9IsKeyframe(frame []byte) bool {
	if len(frame) < 1 {
		return false
	}
	b := frame[0]
	frameMarker := (b >> 6) & 0x3
	if frameMarker != 0x2 {
		return false
	}
	profile := (b >> 4) & 0x3
	showExisting := (b >> 3) & 0x1
	if profile <= 2 {
		if showExisting == 1 {
			return false
		}
		return ((b >> 2) & 0x1) == 0
	}
	if showExisting == 1 {
		return false
	}
	if len(frame) < 2 {
		return false
	}
	return ((frame[1] >> 7) & 0x1) == 0
}

type VP8Payloader struct {
	EnablePictureID bool
	pictureID       uint16
}

const vp8HeaderSize = 1

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
