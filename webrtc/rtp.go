// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package webrtc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

var (
	rtpErrHeaderSizeInsufficient             = errors.New("RTP header size insufficient")
	rtpErrHeaderSizeInsufficientForExtension = errors.New("RTP header size insufficient for extension")
	rtpErrTooSmall                           = errors.New("buffer too small")
	rtpErrInvalidRTPPadding                  = errors.New("invalid RTP padding")
)

var rtpGlobalMathRandomGenerator = NewRandGenerator()

const (
	RtpExtensionProfileOneByte = 0xBEDE
	RtpExtensionProfileTwoByte = 0x1000
	RtpCryptexProfileOneByte = 0xC0DE
	RtpCryptexProfileTwoByte = 0xC2DE
)

const (
	rtpHeaderLength        = 4
	rtpVersionShift        = 6
	rtpVersionMask         = 0x3
	rtpPaddingShift        = 5
	rtpPaddingMask         = 0x1
	rtpExtensionShift      = 4
	rtpExtensionMask       = 0x1
	rtpExtensionIDReserved = 0xF
	rtpExtensionIDPadding  = 0x0
	rtpCcMask              = 0xF
	rtpMarkerShift         = 7
	rtpMarkerMask          = 0x1
	rtpPtMask              = 0x7F
	rtpSeqNumOffset        = 2
	rtpSeqNumLength        = 2
	rtpTimestampOffset     = 4
	rtpTimestampLength     = 4
	rtpSsrcOffset          = 8
	rtpSsrcLength          = 4
	rtpCsrcOffset          = 12
	rtpCsrcLength          = 4
)

type RtpExtension struct {
	id      uint8
	payload []byte
}

func rtpHeaderExtensionCheck(profile uint16, id uint8, payload []byte) error {
	switch profile {
	case RtpExtensionProfileOneByte:
		if id < 1 || id > 14 {
			return fmt.Errorf("header extension id must be between 1 and 14 for RFC 5285 one byte extensions: %d", id)
		}
		if len(payload) > 16 {
			return fmt.Errorf("header extension payload must be 16bytes or less for RFC 5285 one byte extensions: %d", len(payload))
		}
	case RtpExtensionProfileTwoByte:
		if id < 1 {
			return fmt.Errorf("header extension id must be between 1 and 255 for RFC 5285 two byte extensions: %d", id)
		}
		if len(payload) > 255 {
			return fmt.Errorf("header extension payload must be 255bytes or less for RFC 5285 two byte extensions: %d", len(payload))
		}
	default:
		return fmt.Errorf("header extension id must be 0 < id < 15 for RFC 5285 extensions: %d", id)
	}

	return nil
}

type RtpHeader struct {
	Version          uint8
	Padding          bool
	Extension        bool
	Marker           bool
	PayloadType      uint8
	SequenceNumber   uint16
	Timestamp        uint32
	SSRC             uint32
	CSRC             []uint32
	ExtensionProfile uint16
	Extensions       []RtpExtension
	PaddingSize      byte
}

type RtpPacket struct {
	RtpHeader
	Payload     []byte
	PaddingSize byte
}

func (h *RtpHeader) Unmarshal(buf []byte) (n int, err error) {
	if len(buf) < rtpHeaderLength {
		return 0, fmt.Errorf("%w: %d < %d", rtpErrHeaderSizeInsufficient, len(buf), rtpHeaderLength)
	}

	h.Version = buf[0] >> rtpVersionShift & rtpVersionMask
	h.Padding = (buf[0] >> rtpPaddingShift & rtpPaddingMask) > 0
	h.Extension = (buf[0] >> rtpExtensionShift & rtpExtensionMask) > 0
	nCSRC := int(buf[0] & rtpCcMask)
	if cap(h.CSRC) < nCSRC {
		h.CSRC = make([]uint32, nCSRC)
	} else {
		h.CSRC = h.CSRC[:nCSRC]
	}

	n = rtpCsrcOffset + (nCSRC * rtpCsrcLength)
	if len(buf) < n {
		return n, fmt.Errorf("size %d < %d: %w", len(buf), n,
			rtpErrHeaderSizeInsufficient)
	}
	headerLength := n

	h.Marker = (buf[1] >> rtpMarkerShift & rtpMarkerMask) > 0
	h.PayloadType = buf[1] & rtpPtMask

	h.SequenceNumber = binary.BigEndian.Uint16(buf[rtpSeqNumOffset : rtpSeqNumOffset+rtpSeqNumLength])
	h.Timestamp = binary.BigEndian.Uint32(buf[rtpTimestampOffset : rtpTimestampOffset+rtpTimestampLength])
	h.SSRC = binary.BigEndian.Uint32(buf[rtpSsrcOffset : rtpSsrcOffset+rtpSsrcLength])

	for i := range h.CSRC {
		offset := rtpCsrcOffset + (i * rtpCsrcLength)
		h.CSRC[i] = binary.BigEndian.Uint32(buf[offset:])
	}

	h.Extensions = h.Extensions[:0]

	if h.Extension {
		if expected := n + 4; len(buf) < expected {
			return n, fmt.Errorf("size %d < %d: %w",
				len(buf), expected,
				rtpErrHeaderSizeInsufficientForExtension,
			)
		}

		h.ExtensionProfile = binary.BigEndian.Uint16(buf[n:])
		n += 2
		extensionLength := int(binary.BigEndian.Uint16(buf[n:])) * 4
		n += 2
		extensionEnd := n + extensionLength
		headerLength = extensionEnd

		if len(buf) < extensionEnd {
			return n, fmt.Errorf("size %d < %d: %w", len(buf), extensionEnd, rtpErrHeaderSizeInsufficientForExtension)
		}

		if h.ExtensionProfile == RtpExtensionProfileOneByte || h.ExtensionProfile == RtpExtensionProfileTwoByte {
			var (
				extid      uint8
				payloadLen int
			)

			for n < extensionEnd {
				if buf[n] == rtpExtensionIDPadding {
					n++

					continue
				}

				if h.ExtensionProfile == RtpExtensionProfileOneByte {
					extid = buf[n] >> 4
					payloadLen = int(buf[n]&^0xF0 + 1)
					n++

					if extid == rtpExtensionIDReserved || extid == rtpExtensionIDPadding {
						break
					}
				} else {
					extid = buf[n]
					n++

					if extensionEnd <= n {
						return n, fmt.Errorf("size %d < %d: %w", extensionEnd, n, rtpErrHeaderSizeInsufficientForExtension)
					}

					payloadLen = int(buf[n])
					n++
				}

				if extensionPayloadEnd := n + payloadLen; extensionEnd < extensionPayloadEnd {
					return n, fmt.Errorf("size %d < %d: %w", extensionEnd, extensionPayloadEnd, rtpErrHeaderSizeInsufficientForExtension)
				}

				extension := RtpExtension{id: extid, payload: buf[n : n+payloadLen]}
				h.Extensions = append(h.Extensions, extension)
				n += payloadLen
			}
		} else {

			extension := RtpExtension{id: 0, payload: buf[n:extensionEnd]}
			h.Extensions = append(h.Extensions, extension)
		}
	}

	return headerLength, nil
}

func (p *RtpPacket) Unmarshal(buf []byte) error {
	n, err := p.RtpHeader.Unmarshal(buf)
	if err != nil {
		return err
	}

	end := len(buf)
	if p.RtpHeader.Padding {
		if end <= n {
			return rtpErrTooSmall
		}
		p.RtpHeader.PaddingSize = buf[end-1]
		if p.RtpHeader.PaddingSize == 0 {
			return rtpErrInvalidRTPPadding
		}
		end -= int(p.RtpHeader.PaddingSize)
	} else {
		p.RtpHeader.PaddingSize = 0
	}
	p.PaddingSize = p.RtpHeader.PaddingSize
	if end < n {
		return rtpErrTooSmall
	}

	p.Payload = buf[n:end]

	return nil
}

func (h RtpHeader) MarshalTo(buf []byte) (n int, err error) {
	size := h.MarshalSize()
	if size > len(buf) {
		return 0, io.ErrShortBuffer
	}

	buf[0] = (h.Version << rtpVersionShift) | uint8(len(h.CSRC))
	if h.Padding {
		buf[0] |= 1 << rtpPaddingShift
	}

	if h.Extension {
		buf[0] |= 1 << rtpExtensionShift
	}

	buf[1] = h.PayloadType
	if h.Marker {
		buf[1] |= 1 << rtpMarkerShift
	}

	binary.BigEndian.PutUint16(buf[2:4], h.SequenceNumber)
	binary.BigEndian.PutUint32(buf[4:8], h.Timestamp)
	binary.BigEndian.PutUint32(buf[8:12], h.SSRC)

	n = 12
	for _, csrc := range h.CSRC {
		binary.BigEndian.PutUint32(buf[n:n+4], csrc)
		n += 4
	}

	if h.Extension {
		extHeaderPos := n
		binary.BigEndian.PutUint16(buf[n+0:n+2], h.ExtensionProfile)
		n += 4
		startExtensionsPos := n

		switch h.ExtensionProfile {

		case RtpExtensionProfileOneByte:
			for _, extension := range h.Extensions {
				buf[n] = extension.id<<4 | (uint8(len(extension.payload)) - 1)
				n++
				n += copy(buf[n:], extension.payload)
			}

		case RtpExtensionProfileTwoByte:
			for _, extension := range h.Extensions {
				buf[n] = extension.id
				n++
				buf[n] = uint8(len(extension.payload))
				n++
				n += copy(buf[n:], extension.payload)
			}
		default:

			if len(h.Extensions) > 0 {
				extlen := len(h.Extensions[0].payload)
				if extlen%4 != 0 {

					return 0, io.ErrShortBuffer
				}
				n += copy(buf[n:], h.Extensions[0].payload)
			}
		}

		extSize := n - startExtensionsPos
		roundedExtSize := ((extSize + 3) / 4) * 4

		binary.BigEndian.PutUint16(buf[extHeaderPos+2:extHeaderPos+4], uint16(roundedExtSize/4))

		for i := 0; i < roundedExtSize-extSize; i++ {
			buf[n] = 0
			n++
		}
	}

	return n, nil
}

func (h RtpHeader) MarshalSize() int {

	size := 12 + (len(h.CSRC) * rtpCsrcLength)

	if h.Extension {
		extSize := 4

		switch h.ExtensionProfile {

		case RtpExtensionProfileOneByte:
			for _, extension := range h.Extensions {
				extSize += 1 + len(extension.payload)
			}

		case RtpExtensionProfileTwoByte:
			for _, extension := range h.Extensions {
				extSize += 2 + len(extension.payload)
			}
		default:
			if len(h.Extensions) > 0 {
				extSize += len(h.Extensions[0].payload)
			}
		}

		size += ((extSize + 3) / 4) * 4
	}

	return size
}

func (h *RtpHeader) SetExtension(id uint8, payload []byte) error {
	if h.Extension {
		if err := rtpHeaderExtensionCheck(h.ExtensionProfile, id, payload); err != nil {
			return err
		}

		for i, extension := range h.Extensions {
			if extension.id == id {
				h.Extensions[i].payload = payload

				return nil
			}
		}

		h.Extensions = append(h.Extensions, RtpExtension{id: id, payload: payload})

		return nil
	}

	h.Extension = true

	switch payloadLen := len(payload); {
	case payloadLen <= 16:
		h.ExtensionProfile = RtpExtensionProfileOneByte
	case payloadLen > 16 && payloadLen < 256:
		h.ExtensionProfile = RtpExtensionProfileTwoByte
	}

	h.Extensions = append(h.Extensions, RtpExtension{id: id, payload: payload})

	return nil
}

func (h *RtpHeader) GetExtensionIDs() []uint8 {
	if !h.Extension {
		return nil
	}

	if len(h.Extensions) == 0 {
		return nil
	}

	ids := make([]uint8, 0, len(h.Extensions))
	for _, extension := range h.Extensions {
		ids = append(ids, extension.id)
	}

	return ids
}

func (h *RtpHeader) GetExtension(id uint8) []byte {
	if !h.Extension {
		return nil
	}
	for _, extension := range h.Extensions {
		if extension.id == id {
			return extension.payload
		}
	}

	return nil
}

func (h RtpHeader) Clone() RtpHeader {
	clone := h
	if h.CSRC != nil {
		clone.CSRC = make([]uint32, len(h.CSRC))
		copy(clone.CSRC, h.CSRC)
	}
	if h.Extensions != nil {
		ext := make([]RtpExtension, len(h.Extensions))
		for i, e := range h.Extensions {
			ext[i] = e
			if e.payload != nil {
				ext[i].payload = make([]byte, len(e.payload))
				copy(ext[i].payload, e.payload)
			}
		}
		clone.Extensions = ext
	}

	return clone
}

func rtpMarshalPayloadAndPaddingTo(buf []byte, offset int, header *RtpHeader, payload []byte, paddingSize byte,
) (n int, err error) {

	if offset+len(payload)+int(paddingSize) > len(buf) {
		return 0, io.ErrShortBuffer
	}

	m := copy(buf[offset:], payload)

	if header.Padding {
		buf[offset+m+int(paddingSize-1)] = paddingSize
	}

	return offset + m + int(paddingSize), nil
}

func RtpMarshalPacketTo(buf []byte, header *RtpHeader, payload []byte) (int, error) {
	n, err := header.MarshalTo(buf)
	if err != nil {
		return 0, err
	}

	return rtpMarshalPayloadAndPaddingTo(buf, n, header, payload, header.PaddingSize)
}

func RtpHeaderAndPacketMarshalSize(header *RtpHeader, payload []byte) (headerSize int, packetSize int) {
	headerSize = header.MarshalSize()

	return headerSize, headerSize + len(payload) + int(header.PaddingSize)
}

type RtpPayloader interface {
	Payload(mtu uint16, payload []byte) [][]byte
}

type RtpPacketizer interface {
	Packetize(payload []byte, samples uint32) []*RtpPacket
	GeneratePadding(samples uint32) []*RtpPacket
	SkipSamples(skippedSamples uint32)
}

type rtpPacketizer struct {
	MTU         uint16
	PayloadType uint8
	SSRC        uint32
	Payloader   RtpPayloader
	Sequencer   RtpSequencer
	Timestamp   uint32
	ClockRate   uint32
}

func RtpWithTimestamp(timestamp uint32) func(*rtpPacketizer) {
	return func(p *rtpPacketizer) {
		p.Timestamp = timestamp
	}
}

type RtpPacketizerOption func(*rtpPacketizer)

func RtpNewPacketizerWithOptions(
	mtu uint16,
	payloader RtpPayloader, sequencer RtpSequencer, clockRate uint32,
	options ...RtpPacketizerOption) RtpPacketizer {
	packetizerInstance := &rtpPacketizer{
		MTU:       mtu,
		Payloader: payloader,
		Sequencer: sequencer,
		Timestamp: rtpGlobalMathRandomGenerator.Uint32(),
		ClockRate: clockRate,
	}

	for _, option := range options {
		option(packetizerInstance)
	}

	return packetizerInstance
}

func (p *rtpPacketizer) Packetize(payload []byte, samples uint32) []*RtpPacket {

	if len(payload) == 0 {
		p.SkipSamples(samples)

		return nil
	}

	payloads := p.Payloader.Payload(p.MTU-12, payload)
	packets := make([]*RtpPacket, len(payloads))

	for i, pp := range payloads {
		packets[i] = &RtpPacket{
			RtpHeader: RtpHeader{
				Version:        2,
				Padding:        false,
				Extension:      false,
				Marker:         i == len(payloads)-1,
				PayloadType:    p.PayloadType,
				SequenceNumber: p.Sequencer.NextSequenceNumber(),
				Timestamp:      p.Timestamp,
				SSRC:           p.SSRC,
			},
			Payload: pp,
		}
	}
	p.Timestamp += samples

	return packets
}

func (p *rtpPacketizer) GeneratePadding(samples uint32) []*RtpPacket {

	if samples == 0 {
		return nil
	}

	packets := make([]*RtpPacket, samples)

	for i := 0; i < int(samples); i++ {
		packets[i] = &RtpPacket{
			RtpHeader: RtpHeader{
				Version:        2,
				Padding:        true,
				Extension:      false,
				Marker:         false,
				PayloadType:    p.PayloadType,
				SequenceNumber: p.Sequencer.NextSequenceNumber(),
				Timestamp:      p.Timestamp,
				SSRC:           p.SSRC,
				PaddingSize:    255,
			},
		}
	}

	return packets
}

func (p *rtpPacketizer) SkipSamples(skippedSamples uint32) {
	p.Timestamp += skippedSamples
}

type RtpSequencer interface {
	NextSequenceNumber() uint16
}

const rtpMaxInitialRandomSequenceNumber = 1<<15 - 1

func RtpNewRandomSequencer() RtpSequencer {
	s := &rtpSequencer{}
	s.state.Store(uint64(rtpGlobalMathRandomGenerator.Intn(rtpMaxInitialRandomSequenceNumber)))

	return s
}

func RtpNewFixedSequencer(s uint16) RtpSequencer {
	seq := &rtpSequencer{}
	seq.state.Store(uint64(s - 1))

	return seq
}

type rtpSequencer struct {
	state atomic.Uint64
}

func (s *rtpSequencer) NextSequenceNumber() uint16 {
	return uint16(s.state.Add(1))
}
