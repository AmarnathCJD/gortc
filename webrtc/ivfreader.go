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
	ivfIvfFileHeaderSignature = "DKIF"
	ivfIvfFileHeaderSize      = 32
	ivfIvfFrameHeaderSize     = 12
)

var (
	ivfErrNilStream             = errors.New("stream is nil")
	ivfErrIncompleteFrameHeader = errors.New("incomplete frame header")
	ivfErrIncompleteFrameData   = errors.New("incomplete frame data")
	ivfErrIncompleteFileHeader  = errors.New("incomplete file header")
	ivfErrSignatureMismatch     = errors.New("IVF signature mismatch")
	ivfErrUnknownIVFVersion     = errors.New("IVF version unknown, parser may not parse correctly")
	ivfErrInvalidMediaTimebase  = errors.New("invalid media timebase")
)

type IvfIVFFileHeader struct {
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

type IvfIVFFrameHeader struct {
	FrameSize uint32
	Timestamp uint64
}

type IvfIVFReader struct {
	stream               io.Reader
	bytesReadSuccesfully int64
	timebaseDenominator  uint32
	timebaseNumerator    uint32
}

func IvfNewWith(stream io.Reader) (*IvfIVFReader, *IvfIVFFileHeader, error) {
	if stream == nil {
		return nil, nil, ivfErrNilStream
	}

	reader := &IvfIVFReader{
		stream: stream,
	}

	header, err := reader.parseFileHeader()
	if err != nil {
		return nil, nil, err
	}
	if header.TimebaseDenominator == 0 || header.TimebaseNumerator == 0 {
		return nil, nil, ivfErrInvalidMediaTimebase
	}
	reader.timebaseDenominator = header.TimebaseDenominator
	reader.timebaseNumerator = header.TimebaseNumerator

	return reader, header, nil
}

func (i *IvfIVFReader) ptsToTimestamp(pts uint64) uint64 {
	return pts * uint64(i.timebaseDenominator) / uint64(i.timebaseNumerator)
}

func (i *IvfIVFReader) ParseNextFrame() ([]byte, *IvfIVFFrameHeader, error) {
	buffer := make([]byte, ivfIvfFrameHeaderSize)
	var header *IvfIVFFrameHeader

	bytesRead, err := io.ReadFull(i.stream, buffer)
	headerBytesRead := bytesRead
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, nil, ivfErrIncompleteFrameHeader
	} else if err != nil {
		return nil, nil, err
	}

	pts := binary.LittleEndian.Uint64(buffer[4:12])
	header = &IvfIVFFrameHeader{
		FrameSize: binary.LittleEndian.Uint32(buffer[:4]),
		Timestamp: i.ptsToTimestamp(pts),
	}

	payload := make([]byte, header.FrameSize)
	bytesRead, err = io.ReadFull(i.stream, payload)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, nil, ivfErrIncompleteFrameData
	} else if err != nil {
		return nil, nil, err
	}

	i.bytesReadSuccesfully += int64(headerBytesRead) + int64(bytesRead)

	return payload, header, nil
}

func (i *IvfIVFReader) parseFileHeader() (*IvfIVFFileHeader, error) {
	buffer := make([]byte, ivfIvfFileHeaderSize)

	bytesRead, err := io.ReadFull(i.stream, buffer)
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, ivfErrIncompleteFileHeader
	} else if err != nil {
		return nil, err
	}

	header := &IvfIVFFileHeader{
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

	if header.signature != ivfIvfFileHeaderSignature {
		return nil, ivfErrSignatureMismatch
	} else if header.version != uint16(0) {
		return nil, fmt.Errorf("%w: expected(0) got(%d)", ivfErrUnknownIVFVersion, header.version)
	}

	i.bytesReadSuccesfully += int64(bytesRead)

	return header, nil
}
