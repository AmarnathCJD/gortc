// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package ivfreader

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ivfFileHeaderSignature = "DKIF"
	ivfFileHeaderSize      = 32
	ivfFrameHeaderSize     = 12
)

var (
	errNilStream             = errors.New("stream is nil")
	errIncompleteFrameHeader = errors.New("incomplete frame header")
	errIncompleteFrameData   = errors.New("incomplete frame data")
	errIncompleteFileHeader  = errors.New("incomplete file header")
	errSignatureMismatch     = errors.New("IVF signature mismatch")
	errUnknownIVFVersion     = errors.New("IVF version unknown, parser may not parse correctly")
	errInvalidMediaTimebase  = errors.New("invalid media timebase")
)

type IVFFileHeader struct {
	signature           string
	version             uint16
	headerSize          uint16
	FourCC              string
	Width               uint16
	Height              uint16
	TimebaseDenominator uint32
	TimebaseNumerator   uint32
	NumFrames           uint32
	unused              uint32
}

type IVFFrameHeader struct {
	FrameSize uint32
	Timestamp uint64
}

type IVFReader struct {
	stream               io.Reader
	bytesReadSuccesfully int64
	timebaseDenominator  uint32
	timebaseNumerator    uint32
}

func NewWith(stream io.Reader) (*IVFReader, *IVFFileHeader, error) {
	if stream == nil {
		return nil, nil, errNilStream
	}

	reader := &IVFReader{
		stream: stream,
	}

	header, err := reader.parseFileHeader()
	if err != nil {
		return nil, nil, err
	}
	if header.TimebaseDenominator == 0 || header.TimebaseNumerator == 0 {
		return nil, nil, errInvalidMediaTimebase
	}
	reader.timebaseDenominator = header.TimebaseDenominator
	reader.timebaseNumerator = header.TimebaseNumerator

	return reader, header, nil
}

func (i *IVFReader) ptsToTimestamp(pts uint64) uint64 {
	return pts * uint64(i.timebaseDenominator) / uint64(i.timebaseNumerator)
}

func (i *IVFReader) ParseNextFrame() ([]byte, *IVFFrameHeader, error) {
	buffer := make([]byte, ivfFrameHeaderSize)
	var header *IVFFrameHeader

	bytesRead, err := io.ReadFull(i.stream, buffer)
	headerBytesRead := bytesRead
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, nil, errIncompleteFrameHeader
	} else if err != nil {
		return nil, nil, err
	}

	pts := binary.LittleEndian.Uint64(buffer[4:12])
	header = &IVFFrameHeader{
		FrameSize: binary.LittleEndian.Uint32(buffer[:4]),
		Timestamp: i.ptsToTimestamp(pts),
	}

	payload := make([]byte, header.FrameSize)
	bytesRead, err = io.ReadFull(i.stream, payload)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, nil, errIncompleteFrameData
	} else if err != nil {
		return nil, nil, err
	}

	i.bytesReadSuccesfully += int64(headerBytesRead) + int64(bytesRead)

	return payload, header, nil
}

func (i *IVFReader) parseFileHeader() (*IVFFileHeader, error) {
	buffer := make([]byte, ivfFileHeaderSize)

	bytesRead, err := io.ReadFull(i.stream, buffer)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, errIncompleteFileHeader
	} else if err != nil {
		return nil, err
	}

	header := &IVFFileHeader{
		signature:           string(buffer[:4]),
		version:             binary.LittleEndian.Uint16(buffer[4:6]),
		headerSize:          binary.LittleEndian.Uint16(buffer[6:8]),
		FourCC:              string(buffer[8:12]),
		Width:               binary.LittleEndian.Uint16(buffer[12:14]),
		Height:              binary.LittleEndian.Uint16(buffer[14:16]),
		TimebaseDenominator: binary.LittleEndian.Uint32(buffer[16:20]),
		TimebaseNumerator:   binary.LittleEndian.Uint32(buffer[20:24]),
		NumFrames:           binary.LittleEndian.Uint32(buffer[24:28]),
		unused:              binary.LittleEndian.Uint32(buffer[28:32]),
	}

	if header.signature != ivfFileHeaderSignature {
		return nil, errSignatureMismatch
	} else if header.version != uint16(0) {
		return nil, fmt.Errorf("%w: expected(0) got(%d)", errUnknownIVFVersion, header.version)
	}

	i.bytesReadSuccesfully += int64(bytesRead)

	return header, nil
}
