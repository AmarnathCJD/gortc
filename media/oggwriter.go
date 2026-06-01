// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/amarnathcjd/gortc/webrtc/rtp"
)

// RFC 7845 (Ogg encapsulation for Opus).
type oggWriter struct {
	w          io.WriteCloser
	serial     uint32
	pageIndex  uint32
	sampleRate uint32
	channels   uint8

	granule       uint64
	lastTimestamp uint32
	haveTimestamp bool

	closed bool
}

var oggCRCTable = crc32.MakeTable(0x04c11db7)

func newOggWriter(w io.WriteCloser, sampleRate uint32, channels uint8) (*oggWriter, error) {
	var sbuf [4]byte
	if _, err := rand.Read(sbuf[:]); err != nil {
		return nil, fmt.Errorf("media: oggwriter serial: %w", err)
	}
	ow := &oggWriter{
		w:          w,
		serial:     binary.LittleEndian.Uint32(sbuf[:]),
		sampleRate: sampleRate,
		channels:   channels,
	}
	if err := ow.writeHeaders(); err != nil {
		return nil, err
	}
	return ow, nil
}

func (o *oggWriter) writeHeaders() error {
	head := make([]byte, 19)
	copy(head[0:8], []byte("OpusHead"))
	head[8] = 1 // version
	head[9] = o.channels
	binary.LittleEndian.PutUint16(head[10:12], 0) // pre-skip
	binary.LittleEndian.PutUint32(head[12:16], o.sampleRate)
	binary.LittleEndian.PutUint16(head[16:18], 0) // output gain
	head[18] = 0                                  // mapping family
	if err := o.writePage(head, 0, 0x02); err != nil {
		return err
	}

	vendor := []byte("gortc")
	tags := make([]byte, 0, 8+4+len(vendor)+4)
	tags = append(tags, []byte("OpusTags")...)
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(vendor)))
	tags = append(tags, lenBuf[:]...)
	tags = append(tags, vendor...)
	binary.LittleEndian.PutUint32(lenBuf[:], 0)
	tags = append(tags, lenBuf[:]...)
	return o.writePage(tags, 0, 0x00)
}

func (o *oggWriter) writePage(payload []byte, granule uint64, headerType byte) error {
	segments := (len(payload) + 254) / 255
	if segments == 0 {
		segments = 1
	}
	header := make([]byte, 27+segments)
	copy(header[0:4], []byte("OggS"))
	header[4] = 0 // version
	header[5] = headerType
	binary.LittleEndian.PutUint64(header[6:14], granule)
	binary.LittleEndian.PutUint32(header[14:18], o.serial)
	binary.LittleEndian.PutUint32(header[18:22], o.pageIndex)
	header[22], header[23], header[24], header[25] = 0, 0, 0, 0
	header[26] = byte(segments)

	remaining := len(payload)
	for i := 0; i < segments; i++ {
		if remaining >= 255 {
			header[27+i] = 255
			remaining -= 255
		} else {
			header[27+i] = byte(remaining)
			remaining = 0
		}
	}

	crc := crc32.Update(0, oggCRCTable, header)
	crc = crc32.Update(crc, oggCRCTable, payload)
	binary.LittleEndian.PutUint32(header[22:26], crc)

	if _, err := o.w.Write(header); err != nil {
		return err
	}
	if _, err := o.w.Write(payload); err != nil {
		return err
	}
	o.pageIndex++
	return nil
}

func (o *oggWriter) writePacket(p *rtp.Packet) error {
	if o.closed {
		return io.ErrClosedPipe
	}
	if len(p.Payload) == 0 {
		return nil
	}
	if o.haveTimestamp {
		delta := p.Timestamp - o.lastTimestamp
		o.granule += uint64(delta)
	} else {
		o.granule += opusPacketSamples(p.Payload)
		o.haveTimestamp = true
	}
	o.lastTimestamp = p.Timestamp
	return o.writePage(p.Payload, o.granule, 0x00)
}

func (o *oggWriter) Close() error {
	if o.closed {
		return nil
	}
	o.closed = true
	_ = o.writePage(nil, o.granule, 0x04)
	return o.w.Close()
}
