// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/amarnathcjd/gortc/webrtc/rtp"
)

type codecKind int

const (
	vp8Codec codecKind = iota
	vp9Codec
)

type ivfWriter struct {
	w      io.WriteCloser
	fourcc [4]byte

	codec     codecKind
	assembler frameAssembler

	frameCount  uint64
	wroteHeader bool

	lastTimestamp      uint32
	firstTimestamp     uint32
	haveFirstTimestamp bool

	closed bool
}

type frameAssembler interface {
	push(p *rtp.Packet) ([]byte, bool, error)
}

func newIVFWriter(w io.WriteCloser, fourcc string, codec codecKind) *ivfWriter {
	iw := &ivfWriter{w: w, codec: codec}
	copy(iw.fourcc[:], []byte(fourcc))
	switch codec {
	case vp9Codec:
		iw.assembler = &vp9Assembler{}
	default:
		iw.assembler = &vp8Assembler{}
	}
	return iw
}

func (i *ivfWriter) writeFileHeader() error {
	hdr := make([]byte, 32)
	copy(hdr[0:4], []byte("DKIF"))
	binary.LittleEndian.PutUint16(hdr[4:6], 0)
	binary.LittleEndian.PutUint16(hdr[6:8], 32)
	copy(hdr[8:12], i.fourcc[:])
	binary.LittleEndian.PutUint16(hdr[12:14], 640)
	binary.LittleEndian.PutUint16(hdr[14:16], 480)
	binary.LittleEndian.PutUint32(hdr[16:20], 90000)
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	binary.LittleEndian.PutUint32(hdr[24:28], 0)
	binary.LittleEndian.PutUint32(hdr[28:32], 0)
	_, err := i.w.Write(hdr)
	return err
}

func (i *ivfWriter) writePacket(p *rtp.Packet) error {
	if i.closed {
		return io.ErrClosedPipe
	}
	if !i.wroteHeader {
		if err := i.writeFileHeader(); err != nil {
			return err
		}
		i.wroteHeader = true
	}

	frame, ok, err := i.assembler.push(p)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	if !i.haveFirstTimestamp {
		i.firstTimestamp = p.Timestamp
		i.haveFirstTimestamp = true
	}
	pts := uint64(p.Timestamp - i.firstTimestamp)

	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(frame)))
	binary.LittleEndian.PutUint64(hdr[4:12], pts)
	if _, err := i.w.Write(hdr); err != nil {
		return err
	}
	if _, err := i.w.Write(frame); err != nil {
		return err
	}
	i.frameCount++
	i.lastTimestamp = p.Timestamp
	return nil
}

func (i *ivfWriter) Close() error {
	if i.closed {
		return nil
	}
	i.closed = true
	return i.w.Close()
}

type vp8Assembler struct {
	buf  []byte
	open bool
}

func (a *vp8Assembler) push(p *rtp.Packet) ([]byte, bool, error) {
	if len(p.Payload) < 1 {
		return nil, false, nil
	}
	payload, err := stripVP8Descriptor(p.Payload)
	if err != nil {
		return nil, false, err
	}
	desc := p.Payload[0]
	start := desc&0x10 != 0

	if start {
		a.buf = a.buf[:0]
		a.open = true
	}
	if !a.open {
		return nil, false, nil
	}
	a.buf = append(a.buf, payload...)

	if p.Marker {
		out := make([]byte, len(a.buf))
		copy(out, a.buf)
		a.buf = a.buf[:0]
		a.open = false
		return out, true, nil
	}
	return nil, false, nil
}

type vp9Assembler struct {
	buf  []byte
	open bool
}

func (a *vp9Assembler) push(p *rtp.Packet) ([]byte, bool, error) {
	if len(p.Payload) < 1 {
		return nil, false, nil
	}
	payload, start, err := stripVP9Descriptor(p.Payload)
	if err != nil {
		return nil, false, err
	}
	if start {
		a.buf = a.buf[:0]
		a.open = true
	}
	if !a.open {
		return nil, false, nil
	}
	a.buf = append(a.buf, payload...)
	if p.Marker {
		out := make([]byte, len(a.buf))
		copy(out, a.buf)
		a.buf = a.buf[:0]
		a.open = false
		return out, true, nil
	}
	return nil, false, nil
}

func stripVP9Descriptor(payload []byte) ([]byte, bool, error) {
	if len(payload) < 1 {
		return nil, false, fmt.Errorf("vp9: empty payload")
	}
	d := payload[0]
	hasPicID := d&0x80 != 0
	hasLayer := d&0x40 != 0
	hasFlex := d&0x20 != 0
	start := d&0x08 != 0
	hasSS := d&0x02 != 0
	idx := 1

	if hasPicID {
		if len(payload) < idx+1 {
			return nil, false, fmt.Errorf("vp9: truncated picID")
		}
		if payload[idx]&0x80 != 0 {
			if len(payload) < idx+2 {
				return nil, false, fmt.Errorf("vp9: truncated picID-ext")
			}
			idx += 2
		} else {
			idx++
		}
	}
	if hasLayer {
		if len(payload) < idx+1 {
			return nil, false, fmt.Errorf("vp9: truncated layer")
		}
		idx++
		if !hasFlex {
			if len(payload) < idx+1 {
				return nil, false, fmt.Errorf("vp9: truncated tl0picidx")
			}
			idx++
		}
	}
	if hasFlex && hasPicID {
		for j := 0; j < 3; j++ {
			if len(payload) < idx+1 {
				break
			}
			ref := payload[idx]
			idx++
			if ref&0x01 == 0 {
				break
			}
		}
	}
	if hasSS {
		if len(payload) < idx+1 {
			return nil, false, fmt.Errorf("vp9: truncated ss")
		}
		ss := payload[idx]
		idx++
		ns := int((ss>>5)&0x07) + 1
		y := ss&0x10 != 0
		g := ss&0x08 != 0
		if y {
			if len(payload) < idx+ns*4 {
				return nil, false, fmt.Errorf("vp9: truncated ss-res")
			}
			idx += ns * 4
		}
		if g {
			if len(payload) < idx+1 {
				return nil, false, fmt.Errorf("vp9: truncated ng")
			}
			ng := int(payload[idx])
			idx++
			for j := 0; j < ng; j++ {
				if len(payload) < idx+1 {
					return nil, false, fmt.Errorf("vp9: truncated pg")
				}
				pg := payload[idx]
				idx++
				r := int((pg >> 2) & 0x03)
				if len(payload) < idx+r {
					return nil, false, fmt.Errorf("vp9: truncated pg-refs")
				}
				idx += r
			}
		}
	}
	if len(payload) < idx {
		return nil, false, fmt.Errorf("vp9: short payload")
	}
	return payload[idx:], start, nil
}

func stripVP8Descriptor(payload []byte) ([]byte, error) {
	if len(payload) < 1 {
		return nil, fmt.Errorf("vp8: empty payload")
	}
	idx := 1
	x := payload[0] & 0x80
	if x != 0 {
		if len(payload) < idx+1 {
			return nil, fmt.Errorf("vp8: truncated X")
		}
		ext := payload[idx]
		idx++
		i := ext & 0x80
		l := ext & 0x40
		t := ext & 0x20
		k := ext & 0x10
		if i != 0 {
			if len(payload) < idx+1 {
				return nil, fmt.Errorf("vp8: truncated I")
			}
			m := payload[idx] & 0x80
			idx++
			if m != 0 {
				if len(payload) < idx+1 {
					return nil, fmt.Errorf("vp8: truncated I-ext")
				}
				idx++
			}
		}
		if l != 0 {
			if len(payload) < idx+1 {
				return nil, fmt.Errorf("vp8: truncated L")
			}
			idx++
		}
		if t != 0 || k != 0 {
			if len(payload) < idx+1 {
				return nil, fmt.Errorf("vp8: truncated T/K")
			}
			idx++
		}
	}
	if len(payload) < idx {
		return nil, fmt.Errorf("vp8: short payload")
	}
	return payload[idx:], nil
}
