// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/amarnathcjd/gortc/webrtc"
)

// RFC 7845 (Ogg encapsulation for Opus).
type oggWriter struct {
	w          io.WriteCloser
	serial     uint32
	pageIndex  uint32
	sampleRate uint32
	channels   uint8
	preSkip    uint16

	granule uint64

	closed bool
}

var oggCRCTable = func() [256]uint32 {
	var t [256]uint32
	for i := range 256 {
		c := uint32(i) << 24
		for j := 0; j < 8; j++ {
			if c&0x80000000 != 0 {
				c = (c << 1) ^ 0x04c11db7
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

func oggCRC(crc uint32, b []byte) uint32 {
	for _, x := range b {
		crc = (crc << 8) ^ oggCRCTable[byte(crc>>24)^x]
	}
	return crc
}

func newOggWriter(w io.WriteCloser, sampleRate uint32, channels uint8) (*oggWriter, error) {
	return newOggWriterFull(w, sampleRate, channels, 0)
}

func newOggWriterFull(w io.WriteCloser, sampleRate uint32, channels uint8, preSkip uint16) (*oggWriter, error) {
	var sbuf [4]byte
	if _, err := rand.Read(sbuf[:]); err != nil {
		return nil, fmt.Errorf("media: oggwriter serial: %w", err)
	}
	ow := &oggWriter{
		w:          w,
		serial:     binary.LittleEndian.Uint32(sbuf[:]),
		sampleRate: sampleRate,
		channels:   channels,
		preSkip:    preSkip,
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
	binary.LittleEndian.PutUint16(head[10:12], o.preSkip)
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

	crc := oggCRC(0, header)
	crc = oggCRC(crc, payload)
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

func (o *oggWriter) writePacket(p *webrtc.RtpPacket) error {
	if o.closed {
		return io.ErrClosedPipe
	}
	if len(p.Payload) == 0 {
		return nil
	}
	samples := opusPacketSamples(p.Payload)
	if samples == 0 {
		samples = 960
	}
	o.granule += samples
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

// OggOpusRecorder helps to record and save Opus audio from RTP packets into an Ogg file.
type OggOpusRecorder struct{ inner *oggWriter }

func NewOggOpusRecorder(w io.WriteCloser, sampleRate uint32, channels uint8) (*OggOpusRecorder, error) {
	return NewOggOpusRecorderWithPreSkip(w, sampleRate, channels, 0)
}

func NewOggOpusRecorderWithPreSkip(w io.WriteCloser, sampleRate uint32, channels uint8, preSkip uint16) (*OggOpusRecorder, error) {
	ow, err := newOggWriterFull(w, sampleRate, channels, preSkip)
	if err != nil {
		return nil, err
	}
	return &OggOpusRecorder{inner: ow}, nil
}

func (r *OggOpusRecorder) WritePacket(p *webrtc.RtpPacket) error { return r.inner.writePacket(p) }

func (r *OggOpusRecorder) WritePacketWithSamples(p *webrtc.RtpPacket, samples uint64) error {
	o := r.inner
	if o.closed {
		return io.ErrClosedPipe
	}
	if len(p.Payload) == 0 {
		return nil
	}
	o.granule += samples
	return o.writePage(p.Payload, o.granule, 0x00)
}

func (r *OggOpusRecorder) Close() error { return r.inner.Close() }
