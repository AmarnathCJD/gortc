package rtp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/amarnathcjd/gortc/webrtc"
)

var (
	errHeaderSizeInsufficient             = errors.New("RTP header size insufficient")
	errHeaderSizeInsufficientForExtension = errors.New("RTP header size insufficient for extension")
	errTooSmall                           = errors.New("buffer too small")
	errInvalidRTPPadding                  = errors.New("invalid RTP padding")
)

var globalMathRandomGenerator = webrtc.NewRandGenerator()

const (
	ExtensionProfileOneByte = 0xBEDE

	ExtensionProfileTwoByte = 0x1000

	CryptexProfileOneByte = 0xC0DE

	CryptexProfileTwoByte = 0xC2DE
)

const (
	headerLength        = 4
	versionShift        = 6
	versionMask         = 0x3
	paddingShift        = 5
	paddingMask         = 0x1
	extensionShift      = 4
	extensionMask       = 0x1
	extensionIDReserved = 0xF
	extensionIDPadding  = 0x0
	ccMask              = 0xF
	markerShift         = 7
	markerMask          = 0x1
	ptMask              = 0x7F
	seqNumOffset        = 2
	seqNumLength        = 2
	timestampOffset     = 4
	timestampLength     = 4
	ssrcOffset          = 8
	ssrcLength          = 4
	csrcOffset          = 12
	csrcLength          = 4
)

type Extension struct {
	id      uint8
	payload []byte
}

func headerExtensionCheck(profile uint16, id uint8, payload []byte) error {
	switch profile {
	case ExtensionProfileOneByte:
		if id < 1 || id > 14 {
			return fmt.Errorf("header extension id must be between 1 and 14 for RFC 5285 one byte extensions: %d", id)
		}
		if len(payload) > 16 {
			return fmt.Errorf("header extension payload must be 16bytes or less for RFC 5285 one byte extensions: %d", len(payload))
		}
	case ExtensionProfileTwoByte:
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

type Header struct {
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
	Extensions       []Extension
	PaddingSize      byte
}

type Packet struct {
	Header
	Payload     []byte
	PaddingSize byte
}

func (h *Header) Unmarshal(buf []byte) (n int, err error) {
	if len(buf) < headerLength {
		return 0, fmt.Errorf("%w: %d < %d", errHeaderSizeInsufficient, len(buf), headerLength)
	}

	h.Version = buf[0] >> versionShift & versionMask
	h.Padding = (buf[0] >> paddingShift & paddingMask) > 0
	h.Extension = (buf[0] >> extensionShift & extensionMask) > 0
	nCSRC := int(buf[0] & ccMask)
	if cap(h.CSRC) < nCSRC {
		h.CSRC = make([]uint32, nCSRC)
	} else {
		h.CSRC = h.CSRC[:nCSRC]
	}

	n = csrcOffset + (nCSRC * csrcLength)
	if len(buf) < n {
		return n, fmt.Errorf("size %d < %d: %w", len(buf), n,
			errHeaderSizeInsufficient)
	}
	headerLength := n

	h.Marker = (buf[1] >> markerShift & markerMask) > 0
	h.PayloadType = buf[1] & ptMask

	h.SequenceNumber = binary.BigEndian.Uint16(buf[seqNumOffset : seqNumOffset+seqNumLength])
	h.Timestamp = binary.BigEndian.Uint32(buf[timestampOffset : timestampOffset+timestampLength])
	h.SSRC = binary.BigEndian.Uint32(buf[ssrcOffset : ssrcOffset+ssrcLength])

	for i := range h.CSRC {
		offset := csrcOffset + (i * csrcLength)
		h.CSRC[i] = binary.BigEndian.Uint32(buf[offset:])
	}

	h.Extensions = h.Extensions[:0]

	if h.Extension {
		if expected := n + 4; len(buf) < expected {
			return n, fmt.Errorf("size %d < %d: %w",
				len(buf), expected,
				errHeaderSizeInsufficientForExtension,
			)
		}

		h.ExtensionProfile = binary.BigEndian.Uint16(buf[n:])
		n += 2
		extensionLength := int(binary.BigEndian.Uint16(buf[n:])) * 4
		n += 2
		extensionEnd := n + extensionLength
		headerLength = extensionEnd

		if len(buf) < extensionEnd {
			return n, fmt.Errorf("size %d < %d: %w", len(buf), extensionEnd, errHeaderSizeInsufficientForExtension)
		}

		if h.ExtensionProfile == ExtensionProfileOneByte || h.ExtensionProfile == ExtensionProfileTwoByte {
			var (
				extid      uint8
				payloadLen int
			)

			for n < extensionEnd {
				if buf[n] == extensionIDPadding {
					n++

					continue
				}

				if h.ExtensionProfile == ExtensionProfileOneByte {
					extid = buf[n] >> 4
					payloadLen = int(buf[n]&^0xF0 + 1)
					n++

					if extid == extensionIDReserved || extid == extensionIDPadding {
						break
					}
				} else {
					extid = buf[n]
					n++

					if extensionEnd <= n {
						return n, fmt.Errorf("size %d < %d: %w", extensionEnd, n, errHeaderSizeInsufficientForExtension)
					}

					payloadLen = int(buf[n])
					n++
				}

				if extensionPayloadEnd := n + payloadLen; extensionEnd < extensionPayloadEnd {
					return n, fmt.Errorf("size %d < %d: %w", extensionEnd, extensionPayloadEnd, errHeaderSizeInsufficientForExtension)
				}

				extension := Extension{id: extid, payload: buf[n : n+payloadLen]}
				h.Extensions = append(h.Extensions, extension)
				n += payloadLen
			}
		} else {

			extension := Extension{id: 0, payload: buf[n:extensionEnd]}
			h.Extensions = append(h.Extensions, extension)
		}
	}

	return headerLength, nil
}

func (p *Packet) Unmarshal(buf []byte) error {
	n, err := p.Header.Unmarshal(buf)
	if err != nil {
		return err
	}

	end := len(buf)
	if p.Header.Padding {
		if end <= n {
			return errTooSmall
		}
		p.Header.PaddingSize = buf[end-1]
		if p.Header.PaddingSize == 0 {
			return errInvalidRTPPadding
		}
		end -= int(p.Header.PaddingSize)
	} else {
		p.Header.PaddingSize = 0
	}
	p.PaddingSize = p.Header.PaddingSize
	if end < n {
		return errTooSmall
	}

	p.Payload = buf[n:end]

	return nil
}

func (h Header) MarshalTo(buf []byte) (n int, err error) {
	size := h.MarshalSize()
	if size > len(buf) {
		return 0, io.ErrShortBuffer
	}

	buf[0] = (h.Version << versionShift) | uint8(len(h.CSRC))
	if h.Padding {
		buf[0] |= 1 << paddingShift
	}

	if h.Extension {
		buf[0] |= 1 << extensionShift
	}

	buf[1] = h.PayloadType
	if h.Marker {
		buf[1] |= 1 << markerShift
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

		case ExtensionProfileOneByte:
			for _, extension := range h.Extensions {
				buf[n] = extension.id<<4 | (uint8(len(extension.payload)) - 1)
				n++
				n += copy(buf[n:], extension.payload)
			}

		case ExtensionProfileTwoByte:
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

func (h Header) MarshalSize() int {

	size := 12 + (len(h.CSRC) * csrcLength)

	if h.Extension {
		extSize := 4

		switch h.ExtensionProfile {

		case ExtensionProfileOneByte:
			for _, extension := range h.Extensions {
				extSize += 1 + len(extension.payload)
			}

		case ExtensionProfileTwoByte:
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

func (h *Header) SetExtension(id uint8, payload []byte) error {
	if h.Extension {
		if err := headerExtensionCheck(h.ExtensionProfile, id, payload); err != nil {
			return err
		}

		for i, extension := range h.Extensions {
			if extension.id == id {
				h.Extensions[i].payload = payload

				return nil
			}
		}

		h.Extensions = append(h.Extensions, Extension{id: id, payload: payload})

		return nil
	}

	h.Extension = true

	switch payloadLen := len(payload); {
	case payloadLen <= 16:
		h.ExtensionProfile = ExtensionProfileOneByte
	case payloadLen > 16 && payloadLen < 256:
		h.ExtensionProfile = ExtensionProfileTwoByte
	}

	h.Extensions = append(h.Extensions, Extension{id: id, payload: payload})

	return nil
}

func (h *Header) GetExtensionIDs() []uint8 {
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

func (h *Header) GetExtension(id uint8) []byte {
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

func (h Header) Clone() Header {
	clone := h
	if h.CSRC != nil {
		clone.CSRC = make([]uint32, len(h.CSRC))
		copy(clone.CSRC, h.CSRC)
	}
	if h.Extensions != nil {
		ext := make([]Extension, len(h.Extensions))
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

func marshalPayloadAndPaddingTo(buf []byte, offset int, header *Header, payload []byte, paddingSize byte,
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

func MarshalPacketTo(buf []byte, header *Header, payload []byte) (int, error) {
	n, err := header.MarshalTo(buf)
	if err != nil {
		return 0, err
	}

	return marshalPayloadAndPaddingTo(buf, n, header, payload, header.PaddingSize)
}

func HeaderAndPacketMarshalSize(header *Header, payload []byte) (headerSize int, packetSize int) {
	headerSize = header.MarshalSize()

	return headerSize, headerSize + len(payload) + int(header.PaddingSize)
}

type Payloader interface {
	Payload(mtu uint16, payload []byte) [][]byte
}

type Packetizer interface {
	Packetize(payload []byte, samples uint32) []*Packet
	GeneratePadding(samples uint32) []*Packet
	SkipSamples(skippedSamples uint32)
}

type packetizer struct {
	MTU         uint16
	PayloadType uint8
	SSRC        uint32
	Payloader   Payloader
	Sequencer   Sequencer
	Timestamp   uint32
	ClockRate   uint32
}

func WithTimestamp(timestamp uint32) func(*packetizer) {
	return func(p *packetizer) {
		p.Timestamp = timestamp
	}
}

type PacketizerOption func(*packetizer)

func NewPacketizerWithOptions(
	mtu uint16,
	payloader Payloader,
	sequencer Sequencer,
	clockRate uint32,
	options ...PacketizerOption,
) Packetizer {
	packetizerInstance := &packetizer{
		MTU:       mtu,
		Payloader: payloader,
		Sequencer: sequencer,
		Timestamp: globalMathRandomGenerator.Uint32(),
		ClockRate: clockRate,
	}

	for _, option := range options {
		option(packetizerInstance)
	}

	return packetizerInstance
}

func (p *packetizer) Packetize(payload []byte, samples uint32) []*Packet {

	if len(payload) == 0 {
		p.SkipSamples(samples)

		return nil
	}

	payloads := p.Payloader.Payload(p.MTU-12, payload)
	packets := make([]*Packet, len(payloads))

	for i, pp := range payloads {
		packets[i] = &Packet{
			Header: Header{
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

func (p *packetizer) GeneratePadding(samples uint32) []*Packet {

	if samples == 0 {
		return nil
	}

	packets := make([]*Packet, samples)

	for i := 0; i < int(samples); i++ {
		packets[i] = &Packet{
			Header: Header{
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

func (p *packetizer) SkipSamples(skippedSamples uint32) {
	p.Timestamp += skippedSamples
}

type Sequencer interface {
	NextSequenceNumber() uint16
}

const maxInitialRandomSequenceNumber = 1<<15 - 1

func NewRandomSequencer() Sequencer {
	s := &sequencer{}
	s.state.Store(uint64(globalMathRandomGenerator.Intn(maxInitialRandomSequenceNumber)))

	return s
}

func NewFixedSequencer(s uint16) Sequencer {
	seq := &sequencer{}
	seq.state.Store(uint64(s - 1))

	return seq
}

type sequencer struct {
	state atomic.Uint64
}

func (s *sequencer) NextSequenceNumber() uint16 {
	return uint16(s.state.Add(1))
}

const (
	transportCCExtensionSize = 2
)

type TransportCCExtension struct {
	TransportSequence uint16
}

func (t *TransportCCExtension) Unmarshal(rawData []byte) error {
	if len(rawData) < transportCCExtensionSize {
		return errTooSmall
	}
	t.TransportSequence = binary.BigEndian.Uint16(rawData[0:2])

	return nil
}
