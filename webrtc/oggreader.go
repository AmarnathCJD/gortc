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
)

const (
	oggPageHeaderTypeBeginningOfStream = 0x02
	oggPageHeaderSignature             = "OggS"

	oggIdPageBasePayloadLength = 19
	oggPageHeaderLen           = 27
)

var (
	oggErrNilStream                       = errors.New("stream is nil")
	oggErrBadIDPageSignature              = errors.New("bad header signature")
	oggErrBadIDPageType                   = errors.New("wrong header, expected beginning of stream")
	oggErrBadIDPageLength                 = errors.New("payload for id page must be 19 bytes")
	oggErrBadIDPagePayloadSignature       = errors.New("bad payload signature")
	oggErrShortPageHeader                 = errors.New("not enough data for payload header")
	oggErrChecksumMismatch                = errors.New("expected and actual checksum do not match")
	oggErrUnsupportedChannelMappingFamily = errors.New("unsupported channel mapping family")
)

type OggOggReader struct {
	stream               io.Reader
	bytesReadSuccesfully int64
	checksumTable        *[256]uint32
	doChecksum           bool
	lastSegSizes         []byte
}

type OggOggHeader struct {
	ChannelMap     uint8
	Channels       uint8
	OutputGain     uint16
	PreSkip        uint16
	SampleRate     uint32
	Version        uint8
	StreamCount    uint8
	CoupledCount   uint8
	ChannelMapping string
}

type OggOggPageHeader struct {
	GranulePosition uint64
	sig             [4]byte
	version         uint8
	headerType      uint8
	Serial          uint32
	index           uint32
	segmentsCount   uint8
}

type OggHeaderType string

const (
	oggHeaderUnknown  OggHeaderType = ""
	OggHeaderOpusID   OggHeaderType = "OpusHead"
	OggHeaderOpusTags OggHeaderType = "OpusTags"
)

func oggOpusPayloadSignature(payload []byte) (OggHeaderType, bool) {
	if len(payload) < 8 {
		return oggHeaderUnknown, false
	}

	sig := OggHeaderType(payload[:8])
	if sig == OggHeaderOpusID || sig == OggHeaderOpusTags {
		return sig, true
	}

	return oggHeaderUnknown, false
}

func OggNewWith(in io.Reader) (*OggOggReader, *OggOggHeader, error) {
	return oggNewWith(in, true)
}

func oggNewWith(in io.Reader, doChecksum bool) (*OggOggReader, *OggOggHeader, error) {
	if in == nil {
		return nil, nil, oggErrNilStream
	}

	reader := &OggOggReader{
		stream:        in,
		checksumTable: oggGenerateChecksumTable(),
		doChecksum:    doChecksum,
	}

	header, err := reader.readOpusHeader()
	if err != nil {
		return nil, nil, err
	}

	return reader, header, nil
}

func (o *OggOggReader) readOpusHeader() (*OggOggHeader, error) {
	payload, pageHeader, err := o.ParseNextPage()
	if err != nil {
		return nil, err
	}

	if err := oggValidateOpusPageHeader(pageHeader, payload); err != nil {
		return nil, err
	}

	header := oggParseBasicHeaderFields(payload)
	if err := oggParseChannelMapping(header, payload); err != nil {
		return nil, err
	}

	return header, nil
}

func oggValidateOpusPageHeader(pageHeader *OggOggPageHeader, payload []byte) error {
	if string(pageHeader.sig[:]) != oggPageHeaderSignature {
		return oggErrBadIDPageSignature
	}

	if pageHeader.headerType != oggPageHeaderTypeBeginningOfStream {
		return oggErrBadIDPageType
	}

	if len(payload) < oggIdPageBasePayloadLength {
		return oggErrBadIDPageLength
	}

	if sig, ok := oggOpusPayloadSignature(payload); !ok || sig != OggHeaderOpusID {
		return fmt.Errorf("%w: expected OpusHead, got %s", oggErrBadIDPagePayloadSignature, sig)
	}

	return nil
}

func oggParseBasicHeaderFields(payload []byte) *OggOggHeader {
	header := &OggOggHeader{}
	header.Version = payload[8]
	header.Channels = payload[9]
	header.PreSkip = binary.LittleEndian.Uint16(payload[10:12])
	header.SampleRate = binary.LittleEndian.Uint32(payload[12:16])
	header.OutputGain = binary.LittleEndian.Uint16(payload[16:18])
	header.ChannelMap = payload[18]

	return header
}

func oggParseChannelMapping(header *OggOggHeader, payload []byte) error {
	switch header.ChannelMap {
	case 0:
		return oggValidatePayloadLength(payload, oggIdPageBasePayloadLength)
	case 1, 2, 255:
		return oggParseExtendedChannelMapping(header, payload)
	case 3:
		return fmt.Errorf("%w: ambisonics family type 3 is not supported", oggErrUnsupportedChannelMappingFamily)
	default:
		return oggErrUnsupportedChannelMappingFamily
	}
}

func oggValidatePayloadLength(payload []byte, expectedLen int) error {
	if len(payload) != expectedLen {
		return oggErrBadIDPageLength
	}

	return nil
}

func oggParseExtendedChannelMapping(header *OggOggHeader, payload []byte) error {
	expectedPayloadLen := 21 + int(header.Channels)
	if err := oggValidatePayloadLength(payload, expectedPayloadLen); err != nil {
		return err
	}

	header.StreamCount = payload[19]
	header.CoupledCount = payload[20]
	header.ChannelMapping = string(payload[21:expectedPayloadLen])

	return nil
}

func (o *OggOggReader) ParseNextPage() ([]byte, *OggOggPageHeader, error) {
	header := make([]byte, oggPageHeaderLen)

	n, err := io.ReadFull(o.stream, header)
	if err != nil {
		return nil, nil, err
	} else if n < len(header) {
		return nil, nil, oggErrShortPageHeader
	}

	pageHeader := &OggOggPageHeader{
		sig: [4]byte{header[0], header[1], header[2], header[3]},
	}

	pageHeader.version = header[4]
	pageHeader.headerType = header[5]
	pageHeader.GranulePosition = binary.LittleEndian.Uint64(header[6 : 6+8])
	pageHeader.Serial = binary.LittleEndian.Uint32(header[14 : 14+4])
	pageHeader.index = binary.LittleEndian.Uint32(header[18 : 18+4])
	pageHeader.segmentsCount = header[26]

	sizeBuffer := make([]byte, pageHeader.segmentsCount)
	if _, err = io.ReadFull(o.stream, sizeBuffer); err != nil {
		return nil, nil, err
	}

	payloadSize := 0
	for _, s := range sizeBuffer {
		payloadSize += int(s)
	}

	payload := make([]byte, payloadSize)
	if _, err = io.ReadFull(o.stream, payload); err != nil {
		return nil, nil, err
	}

	if o.doChecksum {
		var checksum uint32
		updateChecksum := func(v byte) {
			checksum = (checksum << 8) ^ o.checksumTable[byte(checksum>>24)^v]
		}

		for index := range header {

			if index > 21 && index < 26 {
				updateChecksum(0)

				continue
			}

			updateChecksum(header[index])
		}
		for _, s := range sizeBuffer {
			updateChecksum(s)
		}
		for index := range payload {
			updateChecksum(payload[index])
		}

		if binary.LittleEndian.Uint32(header[22:22+4]) != checksum {
			return nil, nil, oggErrChecksumMismatch
		}
	}

	o.bytesReadSuccesfully += int64(len(header) + len(sizeBuffer) + len(payload))
	o.lastSegSizes = sizeBuffer

	return payload, pageHeader, nil
}

func (o *OggOggReader) ParseNextPageSegments() ([][]byte, *OggOggPageHeader, error) {
	payload, hdr, err := o.ParseNextPage()
	if err != nil {
		return nil, nil, err
	}

	segs := make([][]byte, 0, hdr.segmentsCount)
	off, start := 0, 0
	inPacket := false
	for i := 0; i < int(hdr.segmentsCount); i++ {
		size := int(o.lastSegmentSizes(i))
		if !inPacket {
			start = off
			inPacket = true
		}
		off += size
		if size < 255 {
			segs = append(segs, payload[start:off])
			inPacket = false
		}
	}
	if inPacket {
		segs = append(segs, payload[start:off])
	}
	return segs, hdr, nil
}

// lastSegmentSizes returns the i-th segment size from the most recent page.
// We keep a copy on the reader for ParseNextPageSegments to avoid changing
// the ParseNextPage return signature.
func (o *OggOggReader) lastSegmentSizes(i int) byte {
	if i < 0 || i >= len(o.lastSegSizes) {
		return 0
	}
	return o.lastSegSizes[i]
}

// LastPageLastSegmentSize returns the size of the final segment of the most
// recently parsed page (0 if no page has been parsed). A value of 255 means
// the page's last packet continues onto the next page.
func (o *OggOggReader) LastPageLastSegmentSize() byte {
	if len(o.lastSegSizes) == 0 {
		return 0
	}
	return o.lastSegSizes[len(o.lastSegSizes)-1]
}

func oggGenerateChecksumTable() *[256]uint32 {
	var table [256]uint32
	const poly = 0x04c11db7

	for i := range table {
		r := uint32(i) << 24
		for range 8 {
			if (r & 0x80000000) != 0 {
				r = (r << 1) ^ poly
			} else {
				r <<= 1
			}
		}
		table[i] = (r & 0xffffffff)
	}

	return &table
}
