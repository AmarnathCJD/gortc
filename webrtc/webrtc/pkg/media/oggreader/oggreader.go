package oggreader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	pageHeaderTypeBeginningOfStream = 0x02
	pageHeaderSignature             = "OggS"

	idPageBasePayloadLength = 19
	pageHeaderLen           = 27
)

var (
	errNilStream                       = errors.New("stream is nil")
	errBadIDPageSignature              = errors.New("bad header signature")
	errBadIDPageType                   = errors.New("wrong header, expected beginning of stream")
	errBadIDPageLength                 = errors.New("payload for id page must be 19 bytes")
	errBadIDPagePayloadSignature       = errors.New("bad payload signature")
	errShortPageHeader                 = errors.New("not enough data for payload header")
	errChecksumMismatch                = errors.New("expected and actual checksum do not match")
	errUnsupportedChannelMappingFamily = errors.New("unsupported channel mapping family")
)

type OggReader struct {
	stream               io.Reader
	bytesReadSuccesfully int64
	checksumTable        *[256]uint32
	doChecksum           bool
}

type OggHeader struct {
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

type OggPageHeader struct {
	GranulePosition uint64
	sig             [4]byte
	version         uint8
	headerType      uint8
	Serial          uint32
	index           uint32
	segmentsCount   uint8
}

type HeaderType string

const (
	headerUnknown  HeaderType = ""
	HeaderOpusID   HeaderType = "OpusHead"
	HeaderOpusTags HeaderType = "OpusTags"
)

func opusPayloadSignature(payload []byte) (HeaderType, bool) {
	if len(payload) < 8 {
		return headerUnknown, false
	}

	sig := HeaderType(payload[:8])
	if sig == HeaderOpusID || sig == HeaderOpusTags {
		return sig, true
	}

	return headerUnknown, false
}

func NewWith(in io.Reader) (*OggReader, *OggHeader, error) {
	return newWith(in, true)
}

func newWith(in io.Reader, doChecksum bool) (*OggReader, *OggHeader, error) {
	if in == nil {
		return nil, nil, errNilStream
	}

	reader := &OggReader{
		stream:        in,
		checksumTable: generateChecksumTable(),
		doChecksum:    doChecksum,
	}

	header, err := reader.readOpusHeader()
	if err != nil {
		return nil, nil, err
	}

	return reader, header, nil
}

func (o *OggReader) readOpusHeader() (*OggHeader, error) {
	payload, pageHeader, err := o.ParseNextPage()
	if err != nil {
		return nil, err
	}

	if err := validateOpusPageHeader(pageHeader, payload); err != nil {
		return nil, err
	}

	header := parseBasicHeaderFields(payload)
	if err := parseChannelMapping(header, payload); err != nil {
		return nil, err
	}

	return header, nil
}

func validateOpusPageHeader(pageHeader *OggPageHeader, payload []byte) error {
	if string(pageHeader.sig[:]) != pageHeaderSignature {
		return errBadIDPageSignature
	}

	if pageHeader.headerType != pageHeaderTypeBeginningOfStream {
		return errBadIDPageType
	}

	if len(payload) < idPageBasePayloadLength {
		return errBadIDPageLength
	}

	if sig, ok := opusPayloadSignature(payload); !ok || sig != HeaderOpusID {
		return fmt.Errorf("%w: expected OpusHead, got %s", errBadIDPagePayloadSignature, sig)
	}

	return nil
}

func parseBasicHeaderFields(payload []byte) *OggHeader {
	header := &OggHeader{}
	header.Version = payload[8]
	header.Channels = payload[9]
	header.PreSkip = binary.LittleEndian.Uint16(payload[10:12])
	header.SampleRate = binary.LittleEndian.Uint32(payload[12:16])
	header.OutputGain = binary.LittleEndian.Uint16(payload[16:18])
	header.ChannelMap = payload[18]

	return header
}

func parseChannelMapping(header *OggHeader, payload []byte) error {
	switch header.ChannelMap {
	case 0:
		return validatePayloadLength(payload, idPageBasePayloadLength)
	case 1, 2, 255:
		return parseExtendedChannelMapping(header, payload)
	case 3:
		return fmt.Errorf("%w: ambisonics family type 3 is not supported", errUnsupportedChannelMappingFamily)
	default:
		return errUnsupportedChannelMappingFamily
	}
}

func validatePayloadLength(payload []byte, expectedLen int) error {
	if len(payload) != expectedLen {
		return errBadIDPageLength
	}

	return nil
}

func parseExtendedChannelMapping(header *OggHeader, payload []byte) error {
	expectedPayloadLen := 21 + int(header.Channels)
	if err := validatePayloadLength(payload, expectedPayloadLen); err != nil {
		return err
	}

	header.StreamCount = payload[19]
	header.CoupledCount = payload[20]
	header.ChannelMapping = string(payload[21:expectedPayloadLen])

	return nil
}

func (o *OggReader) ParseNextPage() ([]byte, *OggPageHeader, error) {
	header := make([]byte, pageHeaderLen)

	n, err := io.ReadFull(o.stream, header)
	if err != nil {
		return nil, nil, err
	} else if n < len(header) {
		return nil, nil, errShortPageHeader
	}

	pageHeader := &OggPageHeader{
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
			return nil, nil, errChecksumMismatch
		}
	}

	o.bytesReadSuccesfully += int64(len(header) + len(sizeBuffer) + len(payload))

	return payload, pageHeader, nil
}

func generateChecksumTable() *[256]uint32 {
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
