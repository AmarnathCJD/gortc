// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package webrtc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"unsafe"
)

type RtcpApplicationDefined struct {
	SubType uint8
	SSRC    uint32
	Name    string
	Data    []byte
}

func (a RtcpApplicationDefined) DestinationSSRC() []uint32 {
	return []uint32{a.SSRC}
}

func (a RtcpApplicationDefined) Marshal() ([]byte, error) {
	dataLength := len(a.Data)
	if dataLength > 0xFFFF-12 {
		return nil, rtcpErrAppDefinedDataTooLarge
	}
	if len(a.Name) != 4 {
		return nil, rtcpErrAppDefinedInvalidName
	}

	paddingSize := 4 - (dataLength % 4)
	if paddingSize == 4 {
		paddingSize = 0
	}

	packetSize := a.MarshalSize()
	header := RtcpHeader{
		Type:    RtcpTypeApplicationDefined,
		Length:  uint16((packetSize / 4) - 1),
		Padding: paddingSize != 0,
		Count:   a.SubType,
	}

	headerBytes, err := header.Marshal()
	if err != nil {
		return nil, err
	}

	rawPacket := make([]byte, packetSize)
	copy(rawPacket, headerBytes)
	binary.BigEndian.PutUint32(rawPacket[4:8], a.SSRC)
	copy(rawPacket[8:12], a.Name)
	copy(rawPacket[12:], a.Data)

	if paddingSize > 0 {
		for i := 0; i < paddingSize; i++ {
			rawPacket[12+dataLength+i] = byte(paddingSize)
		}
	}

	return rawPacket, nil
}

func (a *RtcpApplicationDefined) Unmarshal(rawPacket []byte) error {

	header := RtcpHeader{}
	err := header.Unmarshal(rawPacket)
	if err != nil {
		return err
	}
	if len(rawPacket) < 12 {
		return rtcpErrPacketTooShort
	}

	if int(header.Length+1)*4 != len(rawPacket) {
		return rtcpErrAppDefinedInvalidLength
	}

	a.SubType = header.Count
	a.SSRC = binary.BigEndian.Uint32(rawPacket[4:8])
	a.Name = string(rawPacket[8:12])

	paddingSize := 0
	if header.Padding {
		paddingSize = int(rawPacket[len(rawPacket)-1])
		if paddingSize > len(rawPacket)-12 {
			return rtcpErrWrongPadding
		}
	}

	a.Data = rawPacket[12 : len(rawPacket)-paddingSize]

	return nil
}

func (a *RtcpApplicationDefined) MarshalSize() int {
	dataLength := len(a.Data)

	paddingSize := 4 - (dataLength % 4)
	if paddingSize == 4 {
		paddingSize = 0
	}

	return 12 + dataLength + paddingSize
}

var (
	rtcpErrWrongMarshalSize         = errors.New("rtcp: wrong marshal size")
	rtcpErrInvalidTotalLost         = errors.New("rtcp: invalid total lost count")
	rtcpErrInvalidHeader            = errors.New("rtcp: invalid header")
	rtcpErrTooManyReports           = errors.New("rtcp: too many reports")
	rtcpErrTooManyChunks            = errors.New("rtcp: too many chunks")
	rtcpErrTooManySources           = errors.New("rtcp: too many sources")
	rtcpErrPacketTooShort           = errors.New("rtcp: packet too short")
	rtcpErrWrongType                = errors.New("rtcp: wrong packet type")
	rtcpErrSDESTextTooLong          = errors.New("rtcp: sdes must be < 255 octets long")
	rtcpErrSDESMissingType          = errors.New("rtcp: sdes item missing type")
	rtcpErrReasonTooLong            = errors.New("rtcp: reason must be < 255 octets long")
	rtcpErrBadVersion               = errors.New("rtcp: invalid packet version")
	rtcpErrBadLength                = errors.New("rtcp: invalid packet length")
	rtcpErrWrongPadding             = errors.New("rtcp: invalid padding value")
	rtcpErrWrongFeedbackType        = errors.New("rtcp: wrong feedback message type")
	rtcpErrWrongPayloadType         = errors.New("rtcp: wrong payload type")
	rtcpErrHeaderTooSmall           = errors.New("rtcp: header length is too small")
	rtcpErrSSRCMustBeZero           = errors.New("rtcp: media SSRC must be 0")
	rtcpErrMissingREMBidentifier    = errors.New("missing REMB identifier")
	rtcpErrSSRCNumAndLengthMismatch = errors.New("SSRC num and length do not match")
	rtcpErrInvalidSizeOrStartIndex  = errors.New("invalid size or startIndex")
	rtcpErrInvalidBitrate           = errors.New("invalid bitrate")
	rtcpErrWrongChunkType           = errors.New("rtcp: wrong chunk type")
	rtcpErrBadStructMemberType      = errors.New("rtcp: struct contains unexpected member type")
	rtcpErrBadReadParameter         = errors.New("rtcp: cannot read into non-pointer")
	rtcpErrAppDefinedInvalidLength  = errors.New("rtcp: application defined type invalid length")
	rtcpErrAppDefinedDataTooLarge   = errors.New("rtcp: application defined data is too large")
	rtcpErrAppDefinedInvalidName    = errors.New("rtcp: application defined name must be 4 ASCII chars")
)

type RtcpExtendedReport struct {
	SenderSSRC uint32 `fmt:"0x%X"`
	Reports    []RtcpReportBlock
}

type RtcpReportBlock interface {
	DestinationSSRC() []uint32
	setupBlockHeader()
	unpackBlockHeader()
}

type RtcpTypeSpecificField uint8

type RtcpXRHeader struct {
	BlockType    RtcpBlockTypeType
	TypeSpecific RtcpTypeSpecificField `fmt:"0x%X"`
	BlockLength  uint16
}

type RtcpBlockTypeType uint8

const (
	RtcpLossRLEReportBlockType               = 1
	RtcpDuplicateRLEReportBlockType          = 2
	RtcpPacketReceiptTimesReportBlockType    = 3
	RtcpReceiverReferenceTimeReportBlockType = 4
	RtcpDLRRReportBlockType                  = 5
	RtcpStatisticsSummaryReportBlockType     = 6
	RtcpVoIPMetricsReportBlockType           = 7
)

func (t RtcpBlockTypeType) String() string {
	switch t {
	case RtcpLossRLEReportBlockType:
		return "LossRLEReportBlockType"
	case RtcpDuplicateRLEReportBlockType:
		return "DuplicateRLEReportBlockType"
	case RtcpPacketReceiptTimesReportBlockType:
		return "PacketReceiptTimesReportBlockType"
	case RtcpReceiverReferenceTimeReportBlockType:
		return "ReceiverReferenceTimeReportBlockType"
	case RtcpDLRRReportBlockType:
		return "DLRRReportBlockType"
	case RtcpStatisticsSummaryReportBlockType:
		return "StatisticsSummaryReportBlockType"
	case RtcpVoIPMetricsReportBlockType:
		return "VoIPMetricsReportBlockType"
	}

	return fmt.Sprintf("invalid value %d", t)
}

type rtcpRleReportBlock struct {
	RtcpXRHeader
	T        uint8  `encoding:"omit"`
	SSRC     uint32 `fmt:"0x%X"`
	BeginSeq uint16
	EndSeq   uint16
	Chunks   []RtcpChunk
}

type RtcpChunk uint16

type RtcpLossRLEReportBlock rtcpRleReportBlock

func (b *RtcpLossRLEReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *RtcpLossRLEReportBlock) setupBlockHeader() {
	b.RtcpXRHeader.BlockType = RtcpLossRLEReportBlockType
	b.RtcpXRHeader.TypeSpecific = RtcpTypeSpecificField(b.T & 0x0F)
	b.RtcpXRHeader.BlockLength = uint16(rtcpWireSize(b)/4 - 1)
}

func (b *RtcpLossRLEReportBlock) unpackBlockHeader() {
	b.T = uint8(b.RtcpXRHeader.TypeSpecific) & 0x0F
}

type RtcpDuplicateRLEReportBlock rtcpRleReportBlock

func (b *RtcpDuplicateRLEReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *RtcpDuplicateRLEReportBlock) setupBlockHeader() {
	b.RtcpXRHeader.BlockType = RtcpDuplicateRLEReportBlockType
	b.RtcpXRHeader.TypeSpecific = RtcpTypeSpecificField(b.T & 0x0F)
	b.RtcpXRHeader.BlockLength = uint16(rtcpWireSize(b)/4 - 1)
}

func (b *RtcpDuplicateRLEReportBlock) unpackBlockHeader() {
	b.T = uint8(b.RtcpXRHeader.TypeSpecific) & 0x0F
}

type RtcpChunkType uint8

const (
	RtcpRunLengthChunkType       = 0
	RtcpBitVectorChunkType       = 1
	RtcpTerminatingNullChunkType = 2
)

func (c RtcpChunk) String() string {
	switch c.Type() {
	case RtcpRunLengthChunkType:
		runType, _ := c.RunType()

		return fmt.Sprintf("[RunLength type=%d, length=%d]", runType, c.Value())
	case RtcpBitVectorChunkType:
		return fmt.Sprintf("[BitVector 0b%015b]", c.Value())
	case RtcpTerminatingNullChunkType:
		return "[TerminatingNull]"
	}

	return fmt.Sprintf("[0x%X]", uint16(c))
}

func (c RtcpChunk) Type() RtcpChunkType {
	if c == 0 {
		return RtcpTerminatingNullChunkType
	}

	return RtcpChunkType(c >> 15)
}

func (c RtcpChunk) RunType() (uint, error) {
	if c.Type() != RtcpRunLengthChunkType {
		return 0, rtcpErrWrongChunkType
	}

	return uint((c >> 14) & 0x01), nil
}

func (c RtcpChunk) Value() uint {
	switch c.Type() {
	case RtcpRunLengthChunkType:
		return uint(c & 0x3FFF)
	case RtcpBitVectorChunkType:
		return uint(c & 0x7FFF)
	case RtcpTerminatingNullChunkType:
		return 0
	}

	return uint(c)
}

type RtcpPacketReceiptTimesReportBlock struct {
	RtcpXRHeader
	T           uint8  `encoding:"omit"`
	SSRC        uint32 `fmt:"0x%X"`
	BeginSeq    uint16
	EndSeq      uint16
	ReceiptTime []uint32
}

func (b *RtcpPacketReceiptTimesReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *RtcpPacketReceiptTimesReportBlock) setupBlockHeader() {
	b.RtcpXRHeader.BlockType = RtcpPacketReceiptTimesReportBlockType
	b.RtcpXRHeader.TypeSpecific = RtcpTypeSpecificField(b.T & 0x0F)
	b.RtcpXRHeader.BlockLength = uint16(rtcpWireSize(b)/4 - 1)
}

func (b *RtcpPacketReceiptTimesReportBlock) unpackBlockHeader() {
	b.T = uint8(b.RtcpXRHeader.TypeSpecific) & 0x0F
}

type RtcpReceiverReferenceTimeReportBlock struct {
	RtcpXRHeader
	NTPTimestamp uint64
}

func (b *RtcpReceiverReferenceTimeReportBlock) DestinationSSRC() []uint32 {
	return []uint32{}
}

func (b *RtcpReceiverReferenceTimeReportBlock) setupBlockHeader() {
	b.RtcpXRHeader.BlockType = RtcpReceiverReferenceTimeReportBlockType
	b.RtcpXRHeader.TypeSpecific = 0
	b.RtcpXRHeader.BlockLength = uint16(rtcpWireSize(b)/4 - 1)
}

func (b *RtcpReceiverReferenceTimeReportBlock) unpackBlockHeader() {
}

type RtcpDLRRReportBlock struct {
	RtcpXRHeader
	Reports []RtcpDLRRReport
}

type RtcpDLRRReport struct {
	SSRC   uint32 `fmt:"0x%X"`
	LastRR uint32
	DLRR   uint32
}

func (b *RtcpDLRRReportBlock) DestinationSSRC() []uint32 {
	ssrc := make([]uint32, len(b.Reports))
	for i, r := range b.Reports {
		ssrc[i] = r.SSRC
	}

	return ssrc
}

func (b *RtcpDLRRReportBlock) setupBlockHeader() {
	b.RtcpXRHeader.BlockType = RtcpDLRRReportBlockType
	b.RtcpXRHeader.TypeSpecific = 0
	b.RtcpXRHeader.BlockLength = uint16(rtcpWireSize(b)/4 - 1)
}

func (b *RtcpDLRRReportBlock) unpackBlockHeader() {
}

type RtcpStatisticsSummaryReportBlock struct {
	RtcpXRHeader
	LossReports      bool                  `encoding:"omit"`
	DuplicateReports bool                  `encoding:"omit"`
	JitterReports    bool                  `encoding:"omit"`
	TTLorHopLimit    RtcpTTLorHopLimitType `encoding:"omit"`
	SSRC             uint32                `fmt:"0x%X"`
	BeginSeq         uint16
	EndSeq           uint16
	LostPackets      uint32
	DupPackets       uint32
	MinJitter        uint32
	MaxJitter        uint32
	MeanJitter       uint32
	DevJitter        uint32
	MinTTLOrHL       uint8
	MaxTTLOrHL       uint8
	MeanTTLOrHL      uint8
	DevTTLOrHL       uint8
}

type RtcpTTLorHopLimitType uint8

const (
	RtcpToHMissing = 0
	RtcpToHIPv4    = 1
	RtcpToHIPv6    = 2
)

func (t RtcpTTLorHopLimitType) String() string {
	switch t {
	case RtcpToHMissing:
		return "[ToH Missing]"
	case RtcpToHIPv4:
		return "[ToH = IPv4]"
	case RtcpToHIPv6:
		return "[ToH = IPv6]"
	}

	return "[ToH Flag is Invalid]"
}

func (b *RtcpStatisticsSummaryReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *RtcpStatisticsSummaryReportBlock) setupBlockHeader() {
	b.RtcpXRHeader.BlockType = RtcpStatisticsSummaryReportBlockType
	b.RtcpXRHeader.TypeSpecific = 0x00
	if b.LossReports {
		b.RtcpXRHeader.TypeSpecific |= 0x80
	}
	if b.DuplicateReports {
		b.RtcpXRHeader.TypeSpecific |= 0x40
	}
	if b.JitterReports {
		b.RtcpXRHeader.TypeSpecific |= 0x20
	}
	b.RtcpXRHeader.TypeSpecific |= RtcpTypeSpecificField((b.TTLorHopLimit & 0x03) << 3)
	b.RtcpXRHeader.BlockLength = uint16(rtcpWireSize(b)/4 - 1)
}

func (b *RtcpStatisticsSummaryReportBlock) unpackBlockHeader() {
	b.LossReports = b.RtcpXRHeader.TypeSpecific&0x80 != 0
	b.DuplicateReports = b.RtcpXRHeader.TypeSpecific&0x40 != 0
	b.JitterReports = b.RtcpXRHeader.TypeSpecific&0x20 != 0
	b.TTLorHopLimit = RtcpTTLorHopLimitType((b.RtcpXRHeader.TypeSpecific & 0x18) >> 3)
}

type RtcpVoIPMetricsReportBlock struct {
	RtcpXRHeader
	SSRC           uint32 `fmt:"0x%X"`
	LossRate       uint8
	DiscardRate    uint8
	BurstDensity   uint8
	GapDensity     uint8
	BurstDuration  uint16
	GapDuration    uint16
	RoundTripDelay uint16
	EndSystemDelay uint16
	SignalLevel    uint8
	NoiseLevel     uint8
	RERL           uint8
	Gmin           uint8
	RFactor        uint8
	ExtRFactor     uint8
	MOSLQ          uint8
	MOSCQ          uint8
	RXConfig       uint8
	_              uint8
	JBNominal      uint16
	JBMaximum      uint16
	JBAbsMax       uint16
}

func (b *RtcpVoIPMetricsReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *RtcpVoIPMetricsReportBlock) setupBlockHeader() {
	b.RtcpXRHeader.BlockType = RtcpVoIPMetricsReportBlockType
	b.RtcpXRHeader.TypeSpecific = 0
	b.RtcpXRHeader.BlockLength = uint16(rtcpWireSize(b)/4 - 1)
}

func (b *RtcpVoIPMetricsReportBlock) unpackBlockHeader() {
}

type RtcpUnknownReportBlock struct {
	RtcpXRHeader
	Bytes []byte
}

func (b *RtcpUnknownReportBlock) DestinationSSRC() []uint32 {
	return []uint32{}
}

func (b *RtcpUnknownReportBlock) setupBlockHeader() {
	b.RtcpXRHeader.BlockLength = uint16(rtcpWireSize(b)/4 - 1)
}

func (b *RtcpUnknownReportBlock) unpackBlockHeader() {
}

func (x RtcpExtendedReport) MarshalSize() int {
	return rtcpWireSize(x)
}

func (x RtcpExtendedReport) Marshal() ([]byte, error) {
	for _, p := range x.Reports {
		p.setupBlockHeader()
	}

	length := rtcpWireSize(x)

	header := RtcpHeader{
		Type:   RtcpTypeExtendedReport,
		Length: uint16(length / 4),
	}
	headerBuffer, err := header.Marshal()
	if err != nil {
		return []byte{}, err
	}
	length += len(headerBuffer)

	rawPacket := make([]byte, length)
	buffer := rtcpPacketBuffer{bytes: rawPacket}

	err = buffer.write(headerBuffer)
	if err != nil {
		return []byte{}, err
	}
	err = buffer.write(x)
	if err != nil {
		return []byte{}, err
	}

	return rawPacket, nil
}

func (x *RtcpExtendedReport) Unmarshal(b []byte) error {
	var header RtcpHeader
	if err := header.Unmarshal(b); err != nil {
		return err
	}
	if header.Type != RtcpTypeExtendedReport {
		return rtcpErrWrongType
	}

	buffer := rtcpPacketBuffer{bytes: b[rtcpHeaderLength:]}
	err := buffer.read(&x.SenderSSRC)
	if err != nil {
		return err
	}

	for len(buffer.bytes) > 0 {
		var block RtcpReportBlock

		headerBuffer := buffer
		xrHeader := RtcpXRHeader{}
		err = headerBuffer.read(&xrHeader)
		if err != nil {
			return err
		}

		switch xrHeader.BlockType {
		case RtcpLossRLEReportBlockType:
			block = new(RtcpLossRLEReportBlock)
		case RtcpDuplicateRLEReportBlockType:
			block = new(RtcpDuplicateRLEReportBlock)
		case RtcpPacketReceiptTimesReportBlockType:
			block = new(RtcpPacketReceiptTimesReportBlock)
		case RtcpReceiverReferenceTimeReportBlockType:
			block = new(RtcpReceiverReferenceTimeReportBlock)
		case RtcpDLRRReportBlockType:
			block = new(RtcpDLRRReportBlock)
		case RtcpStatisticsSummaryReportBlockType:
			block = new(RtcpStatisticsSummaryReportBlock)
		case RtcpVoIPMetricsReportBlockType:
			block = new(RtcpVoIPMetricsReportBlock)
		default:
			block = new(RtcpUnknownReportBlock)
		}

		blockLength := (int(xrHeader.BlockLength) + 1) * 4
		blockBuffer := buffer.split(blockLength)
		err = blockBuffer.read(block)
		if err != nil {
			return err
		}
		block.unpackBlockHeader()
		x.Reports = append(x.Reports, block)
	}

	return nil
}

func (x *RtcpExtendedReport) DestinationSSRC() []uint32 {
	ssrc := make([]uint32, 0, len(x.Reports)+1)
	ssrc = append(ssrc, x.SenderSSRC)
	for _, p := range x.Reports {
		ssrc = append(ssrc, p.DestinationSSRC()...)
	}

	return ssrc
}

func (x *RtcpExtendedReport) String() string {
	return rtcpStringify(x)
}

type RtcpFIREntry struct {
	SSRC           uint32
	SequenceNumber uint8
}

type RtcpFullIntraRequest struct {
	SenderSSRC uint32
	MediaSSRC  uint32
	FIR        []RtcpFIREntry
}

const (
	rtcpFirOffset = 8
)

var _ RtcpPacket = (*RtcpFullIntraRequest)(nil)

func (p RtcpFullIntraRequest) Marshal() ([]byte, error) {
	rawPacket := make([]byte, rtcpFirOffset+(len(p.FIR)*8))
	binary.BigEndian.PutUint32(rawPacket, p.SenderSSRC)
	binary.BigEndian.PutUint32(rawPacket[4:], p.MediaSSRC)
	for i, fir := range p.FIR {
		binary.BigEndian.PutUint32(rawPacket[rtcpFirOffset+8*i:], fir.SSRC)
		rawPacket[rtcpFirOffset+8*i+4] = fir.SequenceNumber
	}
	h := p.Header()
	hData, err := h.Marshal()
	if err != nil {
		return nil, err
	}

	return append(hData, rawPacket...), nil
}

func (p *RtcpFullIntraRequest) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (rtcpHeaderLength + rtcpSsrcLength) {
		return rtcpErrPacketTooShort
	}

	var header RtcpHeader
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if len(rawPacket) < (rtcpHeaderLength + int(4*header.Length)) {
		return rtcpErrPacketTooShort
	}

	if header.Type != RtcpTypePayloadSpecificFeedback || header.Count != RtcpFormatFIR {
		return rtcpErrWrongType
	}

	if 4*header.Length-rtcpFirOffset <= 0 || (4*header.Length)%8 != 0 {
		return rtcpErrBadLength
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength+rtcpSsrcLength:])
	for i := rtcpHeaderLength + rtcpFirOffset; i < (rtcpHeaderLength + int(header.Length*4)); i += 8 {
		p.FIR = append(p.FIR, RtcpFIREntry{
			binary.BigEndian.Uint32(rawPacket[i:]),
			rawPacket[i+4],
		})
	}

	return nil
}

func (p *RtcpFullIntraRequest) Header() RtcpHeader {
	return RtcpHeader{
		Count:  RtcpFormatFIR,
		Type:   RtcpTypePayloadSpecificFeedback,
		Length: uint16((p.MarshalSize() / 4) - 1),
	}
}

func (p *RtcpFullIntraRequest) MarshalSize() int {
	return rtcpHeaderLength + rtcpFirOffset + len(p.FIR)*8
}

func (p *RtcpFullIntraRequest) String() string {
	out := fmt.Sprintf("FullIntraRequest %x %x",
		p.SenderSSRC, p.MediaSSRC)
	for _, e := range p.FIR {
		out += fmt.Sprintf(" (%x %v)", e.SSRC, e.SequenceNumber)
	}

	return out
}

func (p *RtcpFullIntraRequest) DestinationSSRC() []uint32 {
	ssrcs := make([]uint32, 0, len(p.FIR))
	for _, entry := range p.FIR {
		ssrcs = append(ssrcs, entry.SSRC)
	}

	return ssrcs
}

type RtcpGoodbye struct {
	Sources []uint32
	Reason  string
}

func (g RtcpGoodbye) Marshal() ([]byte, error) {

	rawPacket := make([]byte, g.MarshalSize())
	packetBody := rawPacket[rtcpHeaderLength:]

	if len(g.Sources) > rtcpCountMax {
		return nil, rtcpErrTooManySources
	}

	for i, s := range g.Sources {
		binary.BigEndian.PutUint32(packetBody[i*rtcpSsrcLength:], s)
	}

	if g.Reason != "" {
		reason := []byte(g.Reason)

		if len(reason) > rtcpSdesMaxOctetCount {
			return nil, rtcpErrReasonTooLong
		}

		reasonOffset := len(g.Sources) * rtcpSsrcLength
		packetBody[reasonOffset] = uint8(len(reason))
		copy(packetBody[reasonOffset+1:], reason)
	}

	hData, err := g.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (g *RtcpGoodbye) Unmarshal(rawPacket []byte) error {

	var header RtcpHeader
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != RtcpTypeGoodbye {
		return rtcpErrWrongType
	}

	if rtcpGetPadding(len(rawPacket)) != 0 {
		return rtcpErrPacketTooShort
	}

	g.Sources = make([]uint32, header.Count)

	reasonOffset := int(rtcpHeaderLength + header.Count*rtcpSsrcLength)
	if reasonOffset > len(rawPacket) {
		return rtcpErrPacketTooShort
	}

	for i := 0; i < int(header.Count); i++ {
		offset := rtcpHeaderLength + i*rtcpSsrcLength

		g.Sources[i] = binary.BigEndian.Uint32(rawPacket[offset:])
	}

	if reasonOffset < len(rawPacket) {
		reasonLen := int(rawPacket[reasonOffset])
		reasonEnd := reasonOffset + 1 + reasonLen

		if reasonEnd > len(rawPacket) {
			return rtcpErrPacketTooShort
		}

		g.Reason = string(rawPacket[reasonOffset+1 : reasonEnd])
	}

	return nil
}

func (g *RtcpGoodbye) Header() RtcpHeader {
	return RtcpHeader{
		Padding: false,
		Count:   uint8(len(g.Sources)),
		Type:    RtcpTypeGoodbye,
		Length:  uint16((g.MarshalSize() / 4) - 1),
	}
}

func (g *RtcpGoodbye) MarshalSize() int {
	srcsLength := len(g.Sources) * rtcpSsrcLength

	reasonLength := len(g.Reason)
	if reasonLength > 0 {
		reasonLength++
	}

	l := rtcpHeaderLength + srcsLength + reasonLength

	return l + rtcpGetPadding(l)
}

func (g *RtcpGoodbye) DestinationSSRC() []uint32 {
	out := make([]uint32, len(g.Sources))
	copy(out, g.Sources)

	return out
}

func (g RtcpGoodbye) String() string {
	out := "Goodbye\n"
	for i, s := range g.Sources {
		out += fmt.Sprintf("\tSource %d: %x\n", i, s)
	}
	out += fmt.Sprintf("\tReason: %s\n", g.Reason)

	return out
}

type RtcpPacketType uint8

const (
	RtcpTypeSenderReport              RtcpPacketType = 200
	RtcpTypeReceiverReport            RtcpPacketType = 201
	RtcpTypeSourceDescription         RtcpPacketType = 202
	RtcpTypeGoodbye                   RtcpPacketType = 203
	RtcpTypeApplicationDefined        RtcpPacketType = 204
	RtcpTypeTransportSpecificFeedback RtcpPacketType = 205
	RtcpTypePayloadSpecificFeedback   RtcpPacketType = 206
	RtcpTypeExtendedReport            RtcpPacketType = 207
)

const (
	RtcpFormatSLI  uint8 = 2
	RtcpFormatPLI  uint8 = 1
	RtcpFormatFIR  uint8 = 4
	RtcpFormatTLN  uint8 = 1
	RtcpFormatRRR  uint8 = 5
	RtcpFormatCCFB uint8 = 11
	RtcpFormatREMB uint8 = 15

	RtcpFormatTCC uint8 = 15
)

func (p RtcpPacketType) String() string {
	switch p {
	case RtcpTypeSenderReport:
		return "SR"
	case RtcpTypeReceiverReport:
		return "RR"
	case RtcpTypeSourceDescription:
		return "SDES"
	case RtcpTypeGoodbye:
		return "BYE"
	case RtcpTypeApplicationDefined:
		return "APP"
	case RtcpTypeTransportSpecificFeedback:
		return "TSFB"
	case RtcpTypePayloadSpecificFeedback:
		return "PSFB"
	case RtcpTypeExtendedReport:
		return "XR"
	default:
		return string(p)
	}
}

const rtcpRtpVersion = 2

type RtcpHeader struct {
	Padding bool
	Count   uint8
	Type    RtcpPacketType
	Length  uint16
}

const (
	rtcpHeaderLength = 4
	rtcpVersionShift = 6
	rtcpVersionMask  = 0x3
	rtcpPaddingShift = 5
	rtcpPaddingMask  = 0x1
	rtcpCountShift   = 0
	rtcpCountMask    = 0x1f
	rtcpCountMax     = (1 << 5) - 1
)

func (h RtcpHeader) Marshal() ([]byte, error) {

	rawPacket := make([]byte, rtcpHeaderLength)

	rawPacket[0] |= rtcpRtpVersion << rtcpVersionShift

	if h.Padding {
		rawPacket[0] |= 1 << rtcpPaddingShift
	}

	if h.Count > 31 {
		return nil, rtcpErrInvalidHeader
	}
	rawPacket[0] |= h.Count << rtcpCountShift

	rawPacket[1] = uint8(h.Type)

	binary.BigEndian.PutUint16(rawPacket[2:], h.Length)

	return rawPacket, nil
}

func (h *RtcpHeader) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < rtcpHeaderLength {
		return rtcpErrPacketTooShort
	}

	version := rawPacket[0] >> rtcpVersionShift & rtcpVersionMask
	if version != rtcpRtpVersion {
		return rtcpErrBadVersion
	}

	h.Padding = (rawPacket[0] >> rtcpPaddingShift & rtcpPaddingMask) > 0
	h.Count = rawPacket[0] >> rtcpCountShift & rtcpCountMask

	h.Type = RtcpPacketType(rawPacket[1])

	h.Length = binary.BigEndian.Uint16(rawPacket[2:])

	return nil
}

type RtcpPacket interface {
	DestinationSSRC() []uint32
	Marshal() ([]byte, error)
	Unmarshal(rawPacket []byte) error
	MarshalSize() int
}

func RtcpUnmarshal(rawData []byte) ([]RtcpPacket, error) {
	var packets []RtcpPacket
	for len(rawData) != 0 {
		p, processed, err := rtcpUnmarshal(rawData)
		if err != nil {
			return nil, err
		}

		packets = append(packets, p)
		rawData = rawData[processed:]
	}

	switch len(packets) {

	case 0:
		return nil, rtcpErrInvalidHeader

	default:
		return packets, nil
	}
}

func RtcpMarshal(packets []RtcpPacket) ([]byte, error) {
	out := make([]byte, 0)
	for _, p := range packets {
		data, err := p.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, data...)
	}

	return out, nil
}

func rtcpUnmarshal(rawData []byte) (packet RtcpPacket, bytesprocessed int, err error) {
	var header RtcpHeader

	err = header.Unmarshal(rawData)
	if err != nil {
		return nil, 0, err
	}

	bytesprocessed = int(header.Length+1) * 4
	if bytesprocessed > len(rawData) {
		return nil, 0, rtcpErrPacketTooShort
	}
	inPacket := rawData[:bytesprocessed]

	switch header.Type {
	case RtcpTypeSenderReport:
		packet = new(RtcpSenderReport)

	case RtcpTypeReceiverReport:
		packet = new(RtcpReceiverReport)

	case RtcpTypeSourceDescription:
		packet = new(RtcpSourceDescription)

	case RtcpTypeGoodbye:
		packet = new(RtcpGoodbye)

	case RtcpTypeTransportSpecificFeedback:
		switch header.Count {
		case RtcpFormatTLN:
			packet = new(RtcpTransportLayerNack)
		case RtcpFormatRRR:
			packet = new(RtcpRapidResynchronizationRequest)
		case RtcpFormatTCC:
			packet = new(RtcpTransportLayerCC)
		case RtcpFormatCCFB:
			packet = new(RtcpCCFeedbackReport)
		default:
			packet = new(RtcpRawPacket)
		}

	case RtcpTypePayloadSpecificFeedback:
		switch header.Count {
		case RtcpFormatPLI:
			packet = new(RtcpPictureLossIndication)
		case RtcpFormatSLI:
			packet = new(RtcpSliceLossIndication)
		case RtcpFormatREMB:
			packet = new(RtcpReceiverEstimatedMaximumBitrate)
		case RtcpFormatFIR:
			packet = new(RtcpFullIntraRequest)
		default:
			packet = new(RtcpRawPacket)
		}

	case RtcpTypeExtendedReport:
		packet = new(RtcpExtendedReport)

	case RtcpTypeApplicationDefined:
		packet = new(RtcpApplicationDefined)

	default:
		packet = new(RtcpRawPacket)
	}

	err = packet.Unmarshal(inPacket)

	return packet, bytesprocessed, err
}

type rtcpPacketBuffer struct {
	bytes []byte
}

const rtcpOmit = "omit"

func (b *rtcpPacketBuffer) write(v any) error {
	value := reflect.ValueOf(v)

	value = reflect.Indirect(value)

	switch value.Kind() {
	case reflect.Uint8:
		if len(b.bytes) < 1 {
			return rtcpErrWrongMarshalSize
		}
		if value.CanInterface() {
			b.bytes[0] = byte(value.Uint())
		}
		b.bytes = b.bytes[1:]
	case reflect.Uint16:
		if len(b.bytes) < 2 {
			return rtcpErrWrongMarshalSize
		}
		if value.CanInterface() {
			binary.BigEndian.PutUint16(b.bytes, uint16(value.Uint()))
		}
		b.bytes = b.bytes[2:]
	case reflect.Uint32:
		if len(b.bytes) < 4 {
			return rtcpErrWrongMarshalSize
		}
		if value.CanInterface() {
			binary.BigEndian.PutUint32(b.bytes, uint32(value.Uint()))
		}
		b.bytes = b.bytes[4:]
	case reflect.Uint64:
		if len(b.bytes) < 8 {
			return rtcpErrWrongMarshalSize
		}
		if value.CanInterface() {
			binary.BigEndian.PutUint64(b.bytes, value.Uint())
		}
		b.bytes = b.bytes[8:]
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if value.Index(i).CanInterface() {
				if err := b.write(value.Index(i).Interface()); err != nil {
					return err
				}
			} else {
				b.bytes = b.bytes[value.Index(i).Type().Size():]
			}
		}
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			encoding := value.Type().Field(i).Tag.Get("encoding")
			if encoding == rtcpOmit {
				continue
			}
			if value.Field(i).CanInterface() {
				if err := b.write(value.Field(i).Interface()); err != nil {
					return err
				}
			} else {
				advance := int(value.Field(i).Type().Size())
				if len(b.bytes) < advance {
					return rtcpErrWrongMarshalSize
				}
				b.bytes = b.bytes[advance:]
			}
		}
	default:
		return rtcpErrBadStructMemberType
	}

	return nil
}

func (b *rtcpPacketBuffer) read(v any) error {
	ptr := reflect.ValueOf(v)
	if ptr.Kind() != reflect.Ptr {
		return rtcpErrBadReadParameter
	}
	value := reflect.Indirect(ptr)

	if value.Kind() == reflect.Interface {
		value = reflect.ValueOf(value.Interface())
	}
	value = reflect.Indirect(value)

	switch value.Kind() {
	case reflect.Uint8:
		if len(b.bytes) < 1 {
			return rtcpErrWrongMarshalSize
		}
		value.SetUint(uint64(b.bytes[0]))
		b.bytes = b.bytes[1:]

	case reflect.Uint16:
		if len(b.bytes) < 2 {
			return rtcpErrWrongMarshalSize
		}
		value.SetUint(uint64(binary.BigEndian.Uint16(b.bytes)))
		b.bytes = b.bytes[2:]

	case reflect.Uint32:
		if len(b.bytes) < 4 {
			return rtcpErrWrongMarshalSize
		}
		value.SetUint(uint64(binary.BigEndian.Uint32(b.bytes)))
		b.bytes = b.bytes[4:]

	case reflect.Uint64:
		if len(b.bytes) < 8 {
			return rtcpErrWrongMarshalSize
		}
		value.SetUint(binary.BigEndian.Uint64(b.bytes))
		b.bytes = b.bytes[8:]

	case reflect.Slice:

		for len(b.bytes) > 0 {
			newElementPtr := reflect.New(value.Type().Elem())
			if err := b.read(newElementPtr.Interface()); err != nil {
				return err
			}
			if value.CanSet() {
				value.Set(reflect.Append(value, reflect.Indirect(newElementPtr)))
			}
		}

	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			encoding := value.Type().Field(i).Tag.Get("encoding")
			if encoding == rtcpOmit {
				continue
			}
			if value.Field(i).CanInterface() {
				field := value.Field(i)
				newFieldPtr := reflect.NewAt(

					field.Type(), unsafe.Pointer(field.UnsafeAddr()),
				)
				if err := b.read(newFieldPtr.Interface()); err != nil {
					return err
				}
			} else {
				advance := int(value.Field(i).Type().Size())
				if len(b.bytes) < advance {
					return rtcpErrWrongMarshalSize
				}
				b.bytes = b.bytes[advance:]
			}
		}

	default:
		return rtcpErrBadStructMemberType
	}

	return nil
}

func (b *rtcpPacketBuffer) split(size int) rtcpPacketBuffer {
	if size > len(b.bytes) {
		size = len(b.bytes)
	}
	newBuffer := rtcpPacketBuffer{bytes: b.bytes[:size]}

	b.bytes = b.bytes[size:]

	return newBuffer
}

func rtcpWireSize(v any) int {
	value := reflect.ValueOf(v)

	value = reflect.Indirect(value)
	size := int(0)

	switch value.Kind() {
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if value.Index(i).CanInterface() {
				size += rtcpWireSize(value.Index(i).Interface())
			} else {
				size += int(value.Index(i).Type().Size())
			}
		}

	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			encoding := value.Type().Field(i).Tag.Get("encoding")
			if encoding == rtcpOmit {
				continue
			}
			if value.Field(i).CanInterface() {
				size += rtcpWireSize(value.Field(i).Interface())
			} else {
				size += int(value.Field(i).Type().Size())
			}
		}

	default:
		size = int(value.Type().Size())
	}

	return size
}

func rtcpStringify(p RtcpPacket) string {
	value := reflect.Indirect(reflect.ValueOf(p))

	return rtcpFormatField(value.Type().String(), "", p, "")
}

func rtcpFormatField(name string, format string, f any, indent string) string {
	out := indent
	value := reflect.ValueOf(f)

	if !value.IsValid() {
		return fmt.Sprintf("%s%s: <nil>\n", out, name)
	}

	isPacket := reflect.TypeOf(f).Implements(reflect.TypeOf((*RtcpPacket)(nil)).Elem())

	if value.Type().Kind() == reflect.Ptr && !value.IsNil() {
		underlying := reflect.Indirect(value)
		if underlying.IsValid() {
			value = underlying
		}
	}

	if stringMethod := value.MethodByName("String"); !isPacket && stringMethod.IsValid() {
		out += fmt.Sprintf("%s: %s\n", name, stringMethod.Call([]reflect.Value{}))

		return out
	}

	switch value.Kind() {
	case reflect.Struct:
		out += fmt.Sprintf("%s:\n", name)
		for i := 0; i < value.NumField(); i++ {
			if value.Field(i).CanInterface() {
				format = value.Type().Field(i).Tag.Get("fmt")
				if format == "" {
					format = "%+v"
				}
				out += rtcpFormatField(value.Type().Field(i).Name, format, value.Field(i).Interface(), indent+"\t")
			}
		}
	case reflect.Slice:
		childKind := value.Type().Elem().Kind()
		_, hasStringMethod := value.Type().Elem().MethodByName("String")
		if hasStringMethod || childKind == reflect.Struct || childKind == reflect.Ptr ||
			childKind == reflect.Interface || childKind == reflect.Slice {
			out += fmt.Sprintf("%s:\n", name)
			for i := 0; i < value.Len(); i++ {
				childName := fmt.Sprint(i)

				if value.Index(i).Kind() == reflect.Interface {
					childName += fmt.Sprintf(" (%s)", reflect.Indirect(reflect.ValueOf(value.Index(i).Interface())).Type())
				}
				if value.Index(i).CanInterface() {
					out += rtcpFormatField(childName, format, value.Index(i).Interface(), indent+"\t")
				}
			}

			return out
		}

		fallthrough
	default:
		if value.CanInterface() {
			out += fmt.Sprintf("%s: "+format+"\n", name, value.Interface())
		}
	}

	return out
}

type RtcpPictureLossIndication struct {
	SenderSSRC uint32
	MediaSSRC  uint32
}

const (
	rtcpPliLength = 2
)

func (p RtcpPictureLossIndication) Marshal() ([]byte, error) {

	rawPacket := make([]byte, p.MarshalSize())
	packetBody := rawPacket[rtcpHeaderLength:]

	binary.BigEndian.PutUint32(packetBody, p.SenderSSRC)
	binary.BigEndian.PutUint32(packetBody[4:], p.MediaSSRC)

	h := RtcpHeader{
		Count:  RtcpFormatPLI,
		Type:   RtcpTypePayloadSpecificFeedback,
		Length: rtcpPliLength,
	}
	hData, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (p *RtcpPictureLossIndication) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (rtcpHeaderLength + (rtcpSsrcLength * 2)) {
		return rtcpErrPacketTooShort
	}

	var h RtcpHeader
	if err := h.Unmarshal(rawPacket); err != nil {
		return err
	}

	if h.Type != RtcpTypePayloadSpecificFeedback || h.Count != RtcpFormatPLI {
		return rtcpErrWrongType
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength+rtcpSsrcLength:])

	return nil
}

func (p *RtcpPictureLossIndication) Header() RtcpHeader {
	return RtcpHeader{
		Count:  RtcpFormatPLI,
		Type:   RtcpTypePayloadSpecificFeedback,
		Length: rtcpPliLength,
	}
}

func (p *RtcpPictureLossIndication) MarshalSize() int {
	return rtcpHeaderLength + rtcpSsrcLength*2
}

func (p *RtcpPictureLossIndication) String() string {
	return fmt.Sprintf("PictureLossIndication %x %x", p.SenderSSRC, p.MediaSSRC)
}

func (p *RtcpPictureLossIndication) DestinationSSRC() []uint32 {
	return []uint32{p.MediaSSRC}
}

type RtcpRapidResynchronizationRequest struct {
	SenderSSRC uint32
	MediaSSRC  uint32
}

type RtcpRapidResynchronisationRequest = RtcpRapidResynchronizationRequest

const (
	rtcpRrrLength       = 2
	rtcpRrrHeaderLength = rtcpSsrcLength * 2
	rtcpRrrMediaOffset  = 4
)

func (p RtcpRapidResynchronizationRequest) Marshal() ([]byte, error) {

	rawPacket := make([]byte, p.MarshalSize())
	packetBody := rawPacket[rtcpHeaderLength:]

	binary.BigEndian.PutUint32(packetBody, p.SenderSSRC)
	binary.BigEndian.PutUint32(packetBody[rtcpRrrMediaOffset:], p.MediaSSRC)

	hData, err := p.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (p *RtcpRapidResynchronizationRequest) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (rtcpHeaderLength + (rtcpSsrcLength * 2)) {
		return rtcpErrPacketTooShort
	}

	var h RtcpHeader
	if err := h.Unmarshal(rawPacket); err != nil {
		return err
	}

	if h.Type != RtcpTypeTransportSpecificFeedback || h.Count != RtcpFormatRRR {
		return rtcpErrWrongType
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength+rtcpSsrcLength:])

	return nil
}

func (p *RtcpRapidResynchronizationRequest) MarshalSize() int {
	return rtcpHeaderLength + rtcpRrrHeaderLength
}

func (p *RtcpRapidResynchronizationRequest) Header() RtcpHeader {
	return RtcpHeader{
		Count:  RtcpFormatRRR,
		Type:   RtcpTypeTransportSpecificFeedback,
		Length: rtcpRrrLength,
	}
}

func (p *RtcpRapidResynchronizationRequest) DestinationSSRC() []uint32 {
	return []uint32{p.MediaSSRC}
}

func (p *RtcpRapidResynchronizationRequest) String() string {
	return fmt.Sprintf("RapidResynchronizationRequest %x %x", p.SenderSSRC, p.MediaSSRC)
}

type RtcpRawPacket []byte

func (r RtcpRawPacket) Marshal() ([]byte, error) {
	return r, nil
}

func (r *RtcpRawPacket) Unmarshal(b []byte) error {
	if len(b) < (rtcpHeaderLength) {
		return rtcpErrPacketTooShort
	}
	*r = b

	var h RtcpHeader

	return h.Unmarshal(b)
}

func (r RtcpRawPacket) Header() RtcpHeader {
	var h RtcpHeader
	if err := h.Unmarshal(r); err != nil {
		return RtcpHeader{}
	}

	return h
}

func (r *RtcpRawPacket) DestinationSSRC() []uint32 {
	return []uint32{}
}

func (r RtcpRawPacket) String() string {
	out := fmt.Sprintf("RawPacket: %v", ([]byte)(r))

	return out
}

func (r RtcpRawPacket) MarshalSize() int {
	return len(r)
}

type RtcpReceiverEstimatedMaximumBitrate struct {
	SenderSSRC uint32
	Bitrate    float32
	SSRCs      []uint32
}

func (p RtcpReceiverEstimatedMaximumBitrate) Marshal() (buf []byte, err error) {

	buf = make([]byte, p.MarshalSize())

	n, err := p.MarshalTo(buf)
	if err != nil {
		return nil, err
	}

	if n != len(buf) {
		return nil, rtcpErrWrongMarshalSize
	}

	return buf, nil
}

func (p RtcpReceiverEstimatedMaximumBitrate) MarshalSize() int {
	return 20 + 4*len(p.SSRCs)
}

func (p RtcpReceiverEstimatedMaximumBitrate) MarshalTo(buf []byte) (n int, err error) {
	const bitratemax = 0x3FFFFp+63

	size := p.MarshalSize()
	if len(buf) < size {
		return 0, rtcpErrPacketTooShort
	}

	buf[0] = 143
	buf[1] = 206

	length := uint16((p.MarshalSize() / 4) - 1)
	binary.BigEndian.PutUint16(buf[2:4], length)

	binary.BigEndian.PutUint32(buf[4:8], p.SenderSSRC)
	binary.BigEndian.PutUint32(buf[8:12], 0)

	buf[12] = 'R'
	buf[13] = 'E'
	buf[14] = 'M'
	buf[15] = 'B'

	buf[16] = byte(len(p.SSRCs))

	exp := 0
	bitrate := p.Bitrate

	if bitrate >= bitratemax {
		bitrate = bitratemax
	}

	if bitrate < 0 {
		return 0, rtcpErrInvalidBitrate
	}

	for bitrate >= (1 << 18) {
		bitrate /= 2.0
		exp++
	}

	if exp >= (1 << 6) {
		return 0, rtcpErrInvalidBitrate
	}

	mantissa := uint(math.Floor(float64(bitrate)))

	buf[17] = byte(exp<<2) | byte(mantissa>>16)
	buf[18] = byte(mantissa >> 8)
	buf[19] = byte(mantissa)

	n = 20
	for _, ssrc := range p.SSRCs {
		binary.BigEndian.PutUint32(buf[n:n+4], ssrc)
		n += 4
	}

	return n, nil
}

func (p *RtcpReceiverEstimatedMaximumBitrate) Unmarshal(buf []byte) (err error) {
	const mantissamax = 0x7FFFFF

	if len(buf) < 20 {
		return rtcpErrPacketTooShort
	}

	version := buf[0] >> 6
	if version != 2 {
		return fmt.Errorf("%w expected(2) actual(%d)", rtcpErrBadVersion, version)
	}

	padding := (buf[0] >> 5) & 1
	if padding != 0 {
		return fmt.Errorf("%w expected(0) actual(%d)", rtcpErrWrongPadding, padding)
	}

	fmtVal := buf[0] & 31
	if fmtVal != 15 {
		return fmt.Errorf("%w expected(15) actual(%d)", rtcpErrWrongFeedbackType, fmtVal)
	}

	if buf[1] != 206 {
		return fmt.Errorf("%w expected(206) actual(%d)", rtcpErrWrongPayloadType, buf[1])
	}

	length := binary.BigEndian.Uint16(buf[2:4])
	size := int((length + 1) * 4)

	if size < 20 {
		return rtcpErrHeaderTooSmall
	}

	if len(buf) < size {
		return rtcpErrPacketTooShort
	}

	p.SenderSSRC = binary.BigEndian.Uint32(buf[4:8])

	media := binary.BigEndian.Uint32(buf[8:12])
	if media != 0 {
		return rtcpErrSSRCMustBeZero
	}

	if !bytes.Equal(buf[12:16], []byte{'R', 'E', 'M', 'B'}) {
		return rtcpErrMissingREMBidentifier
	}

	num := int(buf[16])

	if size != 20+4*num {
		return rtcpErrSSRCNumAndLengthMismatch
	}

	exp := buf[17] >> 2
	exp += 127
	exp += 23

	mantissa := uint32(buf[17]&3)<<16 | uint32(buf[18])<<8 | uint32(buf[19])

	if mantissa != 0 {

		for (mantissa & (mantissamax + 1)) == 0 {
			exp--
			mantissa *= 2
		}
	}

	p.Bitrate = math.Float32frombits((uint32(exp) << 23) | (mantissa & mantissamax))

	p.SSRCs = nil

	for n := 20; n < size; n += 4 {
		ssrc := binary.BigEndian.Uint32(buf[n : n+4])
		p.SSRCs = append(p.SSRCs, ssrc)
	}

	return nil
}

func (p *RtcpReceiverEstimatedMaximumBitrate) Header() RtcpHeader {
	return RtcpHeader{
		Count:  RtcpFormatREMB,
		Type:   RtcpTypePayloadSpecificFeedback,
		Length: uint16((p.MarshalSize() / 4) - 1),
	}
}

func (p *RtcpReceiverEstimatedMaximumBitrate) String() string {

	bitUnits := []string{"b", "Kb", "Mb", "Gb", "Tb", "Pb", "Eb"}

	bitrate := p.Bitrate
	powers := 0

	for bitrate >= 1000.0 && powers < len(bitUnits) {
		bitrate /= 1000.0
		powers++
	}

	unit := bitUnits[powers]

	return fmt.Sprintf("ReceiverEstimatedMaximumBitrate %x %.2f %s/s", p.SenderSSRC, bitrate, unit)
}

func (p *RtcpReceiverEstimatedMaximumBitrate) DestinationSSRC() []uint32 {
	return p.SSRCs
}

type RtcpReceiverReport struct {
	SSRC              uint32
	Reports           []RtcpReceptionReport
	ProfileExtensions []byte
}

const (
	rtcpSsrcLength     = 4
	rtcpRrSSRCOffset   = rtcpHeaderLength
	rtcpRrReportOffset = rtcpRrSSRCOffset + rtcpSsrcLength
)

func (r RtcpReceiverReport) Marshal() ([]byte, error) {

	rawPacket := make([]byte, r.MarshalSize())
	packetBody := rawPacket[rtcpHeaderLength:]

	binary.BigEndian.PutUint32(packetBody, r.SSRC)

	for i, rp := range r.Reports {
		data, err := rp.Marshal()
		if err != nil {
			return nil, err
		}
		offset := rtcpSsrcLength + rtcpReceptionReportLength*i
		copy(packetBody[offset:], data)
	}

	if len(r.Reports) > rtcpCountMax {
		return nil, rtcpErrTooManyReports
	}

	pe := make([]byte, len(r.ProfileExtensions))
	copy(pe, r.ProfileExtensions)

	for (len(pe) & 0x3) != 0 {
		pe = append(pe, 0)
	}

	rawPacket = append(rawPacket, pe...)

	hData, err := r.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (r *RtcpReceiverReport) Unmarshal(rawPacket []byte) error {

	if len(rawPacket) < (rtcpHeaderLength + rtcpSsrcLength) {
		return rtcpErrPacketTooShort
	}

	var header RtcpHeader
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != RtcpTypeReceiverReport {
		return rtcpErrWrongType
	}

	r.SSRC = binary.BigEndian.Uint32(rawPacket[rtcpRrSSRCOffset:])

	for i := rtcpRrReportOffset; i < len(rawPacket) && len(r.Reports) < int(header.Count); i += rtcpReceptionReportLength {
		var rr RtcpReceptionReport
		if err := rr.Unmarshal(rawPacket[i:]); err != nil {
			return err
		}
		r.Reports = append(r.Reports, rr)
	}
	r.ProfileExtensions = rawPacket[rtcpRrReportOffset+(len(r.Reports)*rtcpReceptionReportLength):]

	if uint8(len(r.Reports)) != header.Count {
		return rtcpErrInvalidHeader
	}

	return nil
}

func (r *RtcpReceiverReport) MarshalSize() int {
	repsLength := 0
	for _, rep := range r.Reports {
		repsLength += rep.len()
	}

	return rtcpHeaderLength + rtcpSsrcLength + repsLength
}

func (r *RtcpReceiverReport) Header() RtcpHeader {
	return RtcpHeader{
		Count:  uint8(len(r.Reports)),
		Type:   RtcpTypeReceiverReport,
		Length: uint16((r.MarshalSize()/4)-1) + uint16(rtcpGetPadding(len(r.ProfileExtensions))),
	}
}

func (r *RtcpReceiverReport) DestinationSSRC() []uint32 {
	out := make([]uint32, len(r.Reports))
	for i, v := range r.Reports {
		out[i] = v.SSRC
	}

	return out
}

func (r RtcpReceiverReport) String() string {
	out := fmt.Sprintf("ReceiverReport from %x\n", r.SSRC)
	out += "\tSSRC    \tLost\tLastSequence\n"
	for _, i := range r.Reports {
		out += fmt.Sprintf("\t%x\t%d/%d\t%d\n", i.SSRC, i.FractionLost, i.TotalLost, i.LastSequenceNumber)
	}
	out += fmt.Sprintf("\tProfile Extension Data: %v\n", r.ProfileExtensions)

	return out
}

type RtcpReceptionReport struct {
	SSRC               uint32
	FractionLost       uint8
	TotalLost          uint32
	LastSequenceNumber uint32
	Jitter             uint32
	LastSenderReport   uint32
	Delay              uint32
}

const (
	rtcpReceptionReportLength = 24
	rtcpFractionLostOffset    = 4
	rtcpTotalLostOffset       = 5
	rtcpLastSeqOffset         = 8
	rtcpJitterOffset          = 12
	rtcpLastSROffset          = 16
	rtcpDelayOffset           = 20
)

func (r RtcpReceptionReport) Marshal() ([]byte, error) {

	rawPacket := make([]byte, rtcpReceptionReportLength)

	binary.BigEndian.PutUint32(rawPacket, r.SSRC)

	rawPacket[rtcpFractionLostOffset] = r.FractionLost

	if r.TotalLost >= (1 << 25) {
		return nil, rtcpErrInvalidTotalLost
	}
	tlBytes := rawPacket[rtcpTotalLostOffset:]
	tlBytes[0] = byte(r.TotalLost >> 16)
	tlBytes[1] = byte(r.TotalLost >> 8)
	tlBytes[2] = byte(r.TotalLost)

	binary.BigEndian.PutUint32(rawPacket[rtcpLastSeqOffset:], r.LastSequenceNumber)
	binary.BigEndian.PutUint32(rawPacket[rtcpJitterOffset:], r.Jitter)
	binary.BigEndian.PutUint32(rawPacket[rtcpLastSROffset:], r.LastSenderReport)
	binary.BigEndian.PutUint32(rawPacket[rtcpDelayOffset:], r.Delay)

	return rawPacket, nil
}

func (r *RtcpReceptionReport) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < rtcpReceptionReportLength {
		return rtcpErrPacketTooShort
	}

	r.SSRC = binary.BigEndian.Uint32(rawPacket)
	r.FractionLost = rawPacket[rtcpFractionLostOffset]

	tlBytes := rawPacket[rtcpTotalLostOffset:]
	r.TotalLost = uint32(tlBytes[2]) | uint32(tlBytes[1])<<8 | uint32(tlBytes[0])<<16

	r.LastSequenceNumber = binary.BigEndian.Uint32(rawPacket[rtcpLastSeqOffset:])
	r.Jitter = binary.BigEndian.Uint32(rawPacket[rtcpJitterOffset:])
	r.LastSenderReport = binary.BigEndian.Uint32(rawPacket[rtcpLastSROffset:])
	r.Delay = binary.BigEndian.Uint32(rawPacket[rtcpDelayOffset:])

	return nil
}

func (r *RtcpReceptionReport) len() int {
	return rtcpReceptionReportLength
}

var (
	rtcpErrReportBlockLength   = errors.New("feedback report blocks must be at least 8 bytes")
	rtcpErrIncorrectNumReports = errors.New("feedback report block contains less reports than num_reports")
	rtcpErrMetricBlockLength   = errors.New("feedback report metric blocks must be exactly 2 bytes")
)

type RtcpECN uint8

const (
	RtcpECNNonECT RtcpECN = iota

	RtcpECNECT1

	RtcpECNECT0

	RtcpECNCE
)

func (e RtcpECN) String() string {
	switch e {
	case RtcpECNNonECT:

		return "Non-ECT (00)"
	case RtcpECNECT0:

		return "ECT(0) (01)"
	case RtcpECNECT1:

		return "ECT(1) (10)"
	case RtcpECNCE:

		return "CE (11)"
	}

	return "invalid ECN value"
}

const (
	rtcpReportTimestampLength = 4
	rtcpReportBlockOffset     = 8
)

type RtcpCCFeedbackReport struct {
	SenderSSRC      uint32
	ReportBlocks    []RtcpCCFeedbackReportBlock
	ReportTimestamp uint32
}

func (b RtcpCCFeedbackReport) DestinationSSRC() []uint32 {
	ssrcs := make([]uint32, len(b.ReportBlocks))
	for i, block := range b.ReportBlocks {
		ssrcs[i] = block.MediaSSRC
	}

	return ssrcs
}

func (b *RtcpCCFeedbackReport) Len() int {
	return b.MarshalSize()
}

func (b *RtcpCCFeedbackReport) MarshalSize() int {
	n := 0
	for _, block := range b.ReportBlocks {
		n += block.len()
	}

	return rtcpReportBlockOffset + n + rtcpReportTimestampLength
}

func (b *RtcpCCFeedbackReport) Header() RtcpHeader {
	return RtcpHeader{
		Padding: false,
		Count:   RtcpFormatCCFB,
		Type:    RtcpTypeTransportSpecificFeedback,
		Length:  uint16(b.MarshalSize()/4 - 1),
	}
}

func (b RtcpCCFeedbackReport) Marshal() ([]byte, error) {
	header := b.Header()
	headerBuf, err := header.Marshal()
	if err != nil {
		return nil, err
	}
	length := 4 * (header.Length + 1)
	buf := make([]byte, length)
	copy(buf[:rtcpHeaderLength], headerBuf)
	binary.BigEndian.PutUint32(buf[rtcpHeaderLength:], b.SenderSSRC)
	offset := rtcpReportBlockOffset
	for _, block := range b.ReportBlocks {
		b, err := block.marshal()
		if err != nil {
			return nil, err
		}
		copy(buf[offset:], b)
		offset += block.len()
	}

	binary.BigEndian.PutUint32(buf[offset:], b.ReportTimestamp)

	return buf, nil
}

func (b RtcpCCFeedbackReport) String() string {
	out := fmt.Sprintf("CCFB:\n\tHeader %v\n", b.Header())
	out += fmt.Sprintf("CCFB:\n\tSender SSRC %d\n", b.SenderSSRC)
	out += fmt.Sprintf("\tReport Timestamp %d\n", b.ReportTimestamp)
	out += "\tFeedback Reports \n"
	for _, report := range b.ReportBlocks {
		out += fmt.Sprintf("%v ", report)
	}
	out += "\n"

	return out
}

func (b *RtcpCCFeedbackReport) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < rtcpHeaderLength+rtcpSsrcLength+rtcpReportTimestampLength {
		return rtcpErrPacketTooShort
	}

	var h RtcpHeader
	if err := h.Unmarshal(rawPacket); err != nil {
		return err
	}
	if h.Type != RtcpTypeTransportSpecificFeedback {
		return rtcpErrWrongType
	}

	b.SenderSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength:])

	reportTimestampOffset := len(rawPacket) - rtcpReportTimestampLength
	b.ReportTimestamp = binary.BigEndian.Uint32(rawPacket[reportTimestampOffset:])

	offset := rtcpReportBlockOffset
	b.ReportBlocks = []RtcpCCFeedbackReportBlock{}
	for offset < reportTimestampOffset {
		var block RtcpCCFeedbackReportBlock
		if err := block.unmarshal(rawPacket[offset:]); err != nil {
			return err
		}
		b.ReportBlocks = append(b.ReportBlocks, block)
		offset += block.len()
	}

	return nil
}

const (
	rtcpSsrcOffset          = 0
	rtcpBeginSequenceOffset = 4
	rtcpNumReportsOffset    = 6
	rtcpReportsOffset       = 8

	rtcpMaxMetricBlocks = 16384
)

type RtcpCCFeedbackReportBlock struct {
	MediaSSRC     uint32
	BeginSequence uint16
	MetricBlocks  []RtcpCCFeedbackMetricBlock
}

func (b *RtcpCCFeedbackReportBlock) len() int {
	n := len(b.MetricBlocks)
	if n%2 != 0 {
		n++
	}

	return rtcpReportsOffset + 2*n
}

func (b RtcpCCFeedbackReportBlock) String() string {
	out := fmt.Sprintf("\tReport Block Media SSRC %d\n", b.MediaSSRC)
	out += fmt.Sprintf("\tReport Begin Sequence Nr %d\n", b.BeginSequence)
	out += fmt.Sprintf("\tReport length %d\n\t", len(b.MetricBlocks))
	for i, block := range b.MetricBlocks {

		out += fmt.Sprintf(
			"{nr: %d, rx: %v, ts: %v, ecn: %v} ",
			b.BeginSequence+uint16(i),
			block.Received,
			block.ArrivalTimeOffset,
			block.ECN,
		)
	}
	out += "\n"

	return out
}

func (b RtcpCCFeedbackReportBlock) marshal() ([]byte, error) {
	if len(b.MetricBlocks) > rtcpMaxMetricBlocks {
		return nil, rtcpErrTooManyReports
	}

	buf := make([]byte, b.len())
	binary.BigEndian.PutUint32(buf[rtcpSsrcOffset:], b.MediaSSRC)
	binary.BigEndian.PutUint16(buf[rtcpBeginSequenceOffset:], b.BeginSequence)

	length := uint16(len(b.MetricBlocks))

	binary.BigEndian.PutUint16(buf[rtcpNumReportsOffset:], length)

	for i, block := range b.MetricBlocks {
		b, err := block.marshal()
		if err != nil {
			return nil, err
		}
		copy(buf[rtcpReportsOffset+i*2:], b)
	}

	return buf, nil
}

func (b *RtcpCCFeedbackReportBlock) unmarshal(rawPacket []byte) error {
	if len(rawPacket) < rtcpReportsOffset {
		return rtcpErrReportBlockLength
	}
	b.MediaSSRC = binary.BigEndian.Uint32(rawPacket[:rtcpBeginSequenceOffset])
	b.BeginSequence = binary.BigEndian.Uint16(rawPacket[rtcpBeginSequenceOffset:rtcpNumReportsOffset])
	numReports := int(binary.BigEndian.Uint16(rawPacket[rtcpNumReportsOffset:]))
	if numReports == 0 {
		return nil
	}

	if numReports > math.MaxUint16 {
		return rtcpErrIncorrectNumReports
	}

	if len(rawPacket) < rtcpReportsOffset+numReports*2 {
		return rtcpErrIncorrectNumReports
	}

	b.MetricBlocks = make([]RtcpCCFeedbackMetricBlock, numReports)
	for i := int(0); i < numReports; i++ {
		var mb RtcpCCFeedbackMetricBlock
		offset := rtcpReportsOffset + 2*i
		if err := mb.unmarshal(rawPacket[offset : offset+2]); err != nil {
			return err
		}
		b.MetricBlocks[i] = mb
	}

	return nil
}

const (
	rtcpMetricBlockLength = 2
)

type RtcpCCFeedbackMetricBlock struct {
	Received          bool
	ECN               RtcpECN
	ArrivalTimeOffset uint16
}

func (b RtcpCCFeedbackMetricBlock) marshal() ([]byte, error) {
	buf := make([]byte, 2)
	r := uint16(0)
	if b.Received {
		r = 1
	}
	dst, err := rtcpSetNBitsOfUint16(0, 1, 0, r)
	if err != nil {
		return nil, err
	}
	dst, err = rtcpSetNBitsOfUint16(dst, 2, 1, uint16(b.ECN))
	if err != nil {
		return nil, err
	}
	dst, err = rtcpSetNBitsOfUint16(dst, 13, 3, b.ArrivalTimeOffset)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(buf, dst)

	return buf, nil
}

func (b *RtcpCCFeedbackMetricBlock) unmarshal(rawPacket []byte) error {
	if len(rawPacket) != rtcpMetricBlockLength {
		return rtcpErrMetricBlockLength
	}
	b.Received = rawPacket[0]&0x80 != 0
	if !b.Received {
		b.ECN = RtcpECNNonECT
		b.ArrivalTimeOffset = 0

		return nil
	}
	b.ECN = RtcpECN(rawPacket[0] >> 5 & 0x03)
	b.ArrivalTimeOffset = binary.BigEndian.Uint16(rawPacket) & 0x1FFF

	return nil
}

type RtcpSenderReport struct {
	SSRC              uint32
	NTPTime           uint64
	RTPTime           uint32
	PacketCount       uint32
	OctetCount        uint32
	Reports           []RtcpReceptionReport
	ProfileExtensions []byte
}

const (
	rtcpSrHeaderLength      = 24
	rtcpSrSSRCOffset        = 0
	rtcpSrNTPOffset         = rtcpSrSSRCOffset + rtcpSsrcLength
	rtcpNtpTimeLength       = 8
	rtcpSrRTPOffset         = rtcpSrNTPOffset + rtcpNtpTimeLength
	rtcpRtpTimeLength       = 4
	rtcpSrPacketCountOffset = rtcpSrRTPOffset + rtcpRtpTimeLength
	rtcpSrPacketCountLength = 4
	rtcpSrOctetCountOffset  = rtcpSrPacketCountOffset + rtcpSrPacketCountLength
	rtcpSrOctetCountLength  = 4
	rtcpSrReportOffset      = rtcpSrOctetCountOffset + rtcpSrOctetCountLength
)

func (r RtcpSenderReport) Marshal() ([]byte, error) {

	rawPacket := make([]byte, r.MarshalSize())
	packetBody := rawPacket[rtcpHeaderLength:]

	binary.BigEndian.PutUint32(packetBody[rtcpSrSSRCOffset:], r.SSRC)
	binary.BigEndian.PutUint64(packetBody[rtcpSrNTPOffset:], r.NTPTime)
	binary.BigEndian.PutUint32(packetBody[rtcpSrRTPOffset:], r.RTPTime)
	binary.BigEndian.PutUint32(packetBody[rtcpSrPacketCountOffset:], r.PacketCount)
	binary.BigEndian.PutUint32(packetBody[rtcpSrOctetCountOffset:], r.OctetCount)

	offset := rtcpSrHeaderLength
	for _, rp := range r.Reports {
		data, err := rp.Marshal()
		if err != nil {
			return nil, err
		}
		copy(packetBody[offset:], data)
		offset += rtcpReceptionReportLength
	}

	if len(r.Reports) > rtcpCountMax {
		return nil, rtcpErrTooManyReports
	}

	copy(packetBody[offset:], r.ProfileExtensions)

	hData, err := r.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (r *RtcpSenderReport) Unmarshal(rawPacket []byte) error {

	if len(rawPacket) < (rtcpHeaderLength + rtcpSrHeaderLength) {
		return rtcpErrPacketTooShort
	}

	var header RtcpHeader
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != RtcpTypeSenderReport {
		return rtcpErrWrongType
	}

	packetBody := rawPacket[rtcpHeaderLength:]

	r.SSRC = binary.BigEndian.Uint32(packetBody[rtcpSrSSRCOffset:])
	r.NTPTime = binary.BigEndian.Uint64(packetBody[rtcpSrNTPOffset:])
	r.RTPTime = binary.BigEndian.Uint32(packetBody[rtcpSrRTPOffset:])
	r.PacketCount = binary.BigEndian.Uint32(packetBody[rtcpSrPacketCountOffset:])
	r.OctetCount = binary.BigEndian.Uint32(packetBody[rtcpSrOctetCountOffset:])

	offset := rtcpSrReportOffset
	for i := 0; i < int(header.Count); i++ {
		rrEnd := offset + rtcpReceptionReportLength
		if rrEnd > len(packetBody) {
			return rtcpErrPacketTooShort
		}
		rrBody := packetBody[offset : offset+rtcpReceptionReportLength]
		offset = rrEnd

		var rr RtcpReceptionReport
		if err := rr.Unmarshal(rrBody); err != nil {
			return err
		}
		r.Reports = append(r.Reports, rr)
	}

	if offset < len(packetBody) {
		r.ProfileExtensions = packetBody[offset:]
	}

	if uint8(len(r.Reports)) != header.Count {
		return rtcpErrInvalidHeader
	}

	return nil
}

func (r *RtcpSenderReport) DestinationSSRC() []uint32 {
	out := make([]uint32, len(r.Reports)+1)
	for i, v := range r.Reports {
		out[i] = v.SSRC
	}
	out[len(r.Reports)] = r.SSRC

	return out
}

func (r *RtcpSenderReport) MarshalSize() int {
	repsLength := 0
	for _, rep := range r.Reports {
		repsLength += rep.len()
	}

	return rtcpHeaderLength + rtcpSrHeaderLength + repsLength + len(r.ProfileExtensions)
}

func (r *RtcpSenderReport) Header() RtcpHeader {
	return RtcpHeader{
		Count:  uint8(len(r.Reports)),
		Type:   RtcpTypeSenderReport,
		Length: uint16((r.MarshalSize() / 4) - 1),
	}
}

func (r RtcpSenderReport) String() string {
	out := fmt.Sprintf("SenderReport from %x\n", r.SSRC)
	out += fmt.Sprintf("\tNTPTime:\t%d\n", r.NTPTime)
	out += fmt.Sprintf("\tRTPTIme:\t%d\n", r.RTPTime)
	out += fmt.Sprintf("\tPacketCount:\t%d\n", r.PacketCount)
	out += fmt.Sprintf("\tOctetCount:\t%d\n", r.OctetCount)

	out += "\tSSRC    \tLost\tLastSequence\n"
	for _, i := range r.Reports {
		out += fmt.Sprintf("\t%x\t%d/%d\t%d\n", i.SSRC, i.FractionLost, i.TotalLost, i.LastSequenceNumber)
	}
	out += fmt.Sprintf("\tProfile Extension Data: %v\n", r.ProfileExtensions)

	return out
}

type RtcpSLIEntry struct {
	First   uint16
	Number  uint16
	Picture uint8
}

type RtcpSliceLossIndication struct {
	SenderSSRC uint32
	MediaSSRC  uint32
	SLI        []RtcpSLIEntry
}

const (
	rtcpSliLength = 2
	rtcpSliOffset = 8
)

func (p RtcpSliceLossIndication) Marshal() ([]byte, error) {
	if len(p.SLI)+rtcpSliLength > math.MaxUint8 {
		return nil, rtcpErrTooManyReports
	}

	rawPacket := make([]byte, rtcpSliOffset+(len(p.SLI)*4))
	binary.BigEndian.PutUint32(rawPacket, p.SenderSSRC)
	binary.BigEndian.PutUint32(rawPacket[4:], p.MediaSSRC)
	for i, s := range p.SLI {
		sli := ((uint32(s.First) & 0x1FFF) << 19) |
			((uint32(s.Number) & 0x1FFF) << 6) |
			(uint32(s.Picture) & 0x3F)
		binary.BigEndian.PutUint32(rawPacket[rtcpSliOffset+(4*i):], sli)
	}
	hData, err := p.Header().Marshal()
	if err != nil {
		return nil, err
	}

	return append(hData, rawPacket...), nil
}

func (p *RtcpSliceLossIndication) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (rtcpHeaderLength + rtcpSsrcLength) {
		return rtcpErrPacketTooShort
	}

	var header RtcpHeader
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if len(rawPacket) < (rtcpHeaderLength + int(4*header.Length)) {
		return rtcpErrPacketTooShort
	}

	if header.Type != RtcpTypeTransportSpecificFeedback || header.Count != RtcpFormatSLI {
		return rtcpErrWrongType
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength+rtcpSsrcLength:])
	for i := rtcpHeaderLength + rtcpSliOffset; i < (rtcpHeaderLength + int(header.Length*4)); i += 4 {
		sli := binary.BigEndian.Uint32(rawPacket[i:])
		p.SLI = append(p.SLI, RtcpSLIEntry{
			First:   uint16((sli >> 19) & 0x1FFF),
			Number:  uint16((sli >> 6) & 0x1FFF),
			Picture: uint8(sli & 0x3F),
		})
	}

	return nil
}

func (p *RtcpSliceLossIndication) MarshalSize() int {
	return rtcpHeaderLength + rtcpSliOffset + (len(p.SLI) * 4)
}

func (p *RtcpSliceLossIndication) Header() RtcpHeader {
	return RtcpHeader{
		Count:  RtcpFormatSLI,
		Type:   RtcpTypeTransportSpecificFeedback,
		Length: uint16((p.MarshalSize() / 4) - 1),
	}
}

func (p *RtcpSliceLossIndication) String() string {
	return fmt.Sprintf("SliceLossIndication %x %x %+v", p.SenderSSRC, p.MediaSSRC, p.SLI)
}

func (p *RtcpSliceLossIndication) DestinationSSRC() []uint32 {
	return []uint32{p.MediaSSRC}
}

type RtcpSDESType uint8

const (
	RtcpSDESEnd RtcpSDESType = iota
	RtcpSDESCNAME
	RtcpSDESName
	RtcpSDESEmail
	RtcpSDESPhone
	RtcpSDESLocation
	RtcpSDESTool
	RtcpSDESNote
	RtcpSDESPrivate
)

func (s RtcpSDESType) String() string {
	switch s {
	case RtcpSDESEnd:
		return "END"
	case RtcpSDESCNAME:
		return "CNAME"
	case RtcpSDESName:
		return "NAME"
	case RtcpSDESEmail:
		return "EMAIL"
	case RtcpSDESPhone:
		return "PHONE"
	case RtcpSDESLocation:
		return "LOC"
	case RtcpSDESTool:
		return "TOOL"
	case RtcpSDESNote:
		return "NOTE"
	case RtcpSDESPrivate:
		return "PRIV"
	default:
		return string(s)
	}
}

const (
	rtcpSdesSourceLen        = 4
	rtcpSdesTypeLen          = 1
	rtcpSdesTypeOffset       = 0
	rtcpSdesOctetCountLen    = 1
	rtcpSdesOctetCountOffset = 1
	rtcpSdesMaxOctetCount    = (1 << 8) - 1
	rtcpSdesTextOffset       = 2
)

type RtcpSourceDescription struct {
	Chunks []RtcpSourceDescriptionChunk
}

func (s RtcpSourceDescription) Marshal() ([]byte, error) {

	rawPacket := make([]byte, s.MarshalSize())
	packetBody := rawPacket[rtcpHeaderLength:]

	chunkOffset := 0
	for _, c := range s.Chunks {
		data, err := c.Marshal()
		if err != nil {
			return nil, err
		}
		copy(packetBody[chunkOffset:], data)
		chunkOffset += len(data)
	}

	if len(s.Chunks) > rtcpCountMax {
		return nil, rtcpErrTooManyChunks
	}

	hData, err := s.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (s *RtcpSourceDescription) Unmarshal(rawPacket []byte) error {

	var header RtcpHeader
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != RtcpTypeSourceDescription {
		return rtcpErrWrongType
	}

	for i := rtcpHeaderLength; i < len(rawPacket); {
		var chunk RtcpSourceDescriptionChunk
		if err := chunk.Unmarshal(rawPacket[i:]); err != nil {
			return err
		}
		s.Chunks = append(s.Chunks, chunk)

		i += chunk.len()
	}

	if len(s.Chunks) != int(header.Count) {
		return rtcpErrInvalidHeader
	}

	return nil
}

func (s *RtcpSourceDescription) MarshalSize() int {
	chunksLength := 0
	for _, c := range s.Chunks {
		chunksLength += c.len()
	}

	return rtcpHeaderLength + chunksLength
}

func (s *RtcpSourceDescription) Header() RtcpHeader {
	return RtcpHeader{
		Count:  uint8(len(s.Chunks)),
		Type:   RtcpTypeSourceDescription,
		Length: uint16((s.MarshalSize() / 4) - 1),
	}
}

type RtcpSourceDescriptionChunk struct {
	Source uint32
	Items  []RtcpSourceDescriptionItem
}

func (s RtcpSourceDescriptionChunk) Marshal() ([]byte, error) {

	rawPacket := make([]byte, rtcpSdesSourceLen)
	binary.BigEndian.PutUint32(rawPacket, s.Source)

	for _, it := range s.Items {
		data, err := it.Marshal()
		if err != nil {
			return nil, err
		}
		rawPacket = append(rawPacket, data...)
	}

	rawPacket = append(rawPacket, uint8(RtcpSDESEnd))

	rawPacket = append(rawPacket, make([]byte, rtcpGetPadding(len(rawPacket)))...)

	return rawPacket, nil
}

func (s *RtcpSourceDescriptionChunk) Unmarshal(rawPacket []byte) error {

	if len(rawPacket) < (rtcpSdesSourceLen + rtcpSdesTypeLen) {
		return rtcpErrPacketTooShort
	}

	s.Source = binary.BigEndian.Uint32(rawPacket)

	for i := 4; i < len(rawPacket); {
		if pktType := RtcpSDESType(rawPacket[i]); pktType == RtcpSDESEnd {
			return nil
		}

		var it RtcpSourceDescriptionItem
		if err := it.Unmarshal(rawPacket[i:]); err != nil {
			return err
		}
		s.Items = append(s.Items, it)
		i += it.Len()
	}

	return rtcpErrPacketTooShort
}

func (s RtcpSourceDescriptionChunk) len() int {
	chunkLen := rtcpSdesSourceLen
	for _, it := range s.Items {
		chunkLen += it.Len()
	}
	chunkLen += rtcpSdesTypeLen

	chunkLen += rtcpGetPadding(chunkLen)

	return chunkLen
}

type RtcpSourceDescriptionItem struct {
	Type RtcpSDESType
	Text string
}

func (s RtcpSourceDescriptionItem) Len() int {

	return rtcpSdesTypeLen + rtcpSdesOctetCountLen + len([]byte(s.Text))
}

func (s RtcpSourceDescriptionItem) Marshal() ([]byte, error) {

	if s.Type == RtcpSDESEnd {
		return nil, rtcpErrSDESMissingType
	}

	rawPacket := make([]byte, rtcpSdesTypeLen+rtcpSdesOctetCountLen)

	rawPacket[rtcpSdesTypeOffset] = uint8(s.Type)

	txtBytes := []byte(s.Text)
	octetCount := len(txtBytes)
	if octetCount > rtcpSdesMaxOctetCount {
		return nil, rtcpErrSDESTextTooLong
	}
	rawPacket[rtcpSdesOctetCountOffset] = uint8(octetCount)

	rawPacket = append(rawPacket, txtBytes...)

	return rawPacket, nil
}

func (s *RtcpSourceDescriptionItem) Unmarshal(rawPacket []byte) error {

	if len(rawPacket) < (rtcpSdesTypeLen + rtcpSdesOctetCountLen) {
		return rtcpErrPacketTooShort
	}

	s.Type = RtcpSDESType(rawPacket[rtcpSdesTypeOffset])

	octetCount := int(rawPacket[rtcpSdesOctetCountOffset])
	if rtcpSdesTextOffset+octetCount > len(rawPacket) {
		return rtcpErrPacketTooShort
	}

	txtBytes := rawPacket[rtcpSdesTextOffset : rtcpSdesTextOffset+octetCount]
	s.Text = string(txtBytes)

	return nil
}

func (s *RtcpSourceDescription) DestinationSSRC() []uint32 {
	out := make([]uint32, len(s.Chunks))
	for i, v := range s.Chunks {
		out[i] = v.Source
	}

	return out
}

func (s *RtcpSourceDescription) String() string {
	out := "Source Description:\n"
	for _, c := range s.Chunks {
		out += fmt.Sprintf("\t%x: %s\n", c.Source, c.Items)
	}

	return out
}

const (
	RtcpTypeTCCRunLengthChunk    = 0
	RtcpTypeTCCStatusVectorChunk = 1

	rtcpPacketStatusChunkLength = 2
)

const (
	RtcpTypeTCCPacketNotReceived = uint16(iota)
	RtcpTypeTCCPacketReceivedSmallDelta
	RtcpTypeTCCPacketReceivedLargeDelta

	RtcpTypeTCCPacketReceivedWithoutDelta
)

const (
	RtcpTypeTCCSymbolSizeOneBit = 0
	RtcpTypeTCCSymbolSizeTwoBit = 1
)

func rtcpNumOfBitsOfSymbolSize() map[uint16]uint16 {
	return map[uint16]uint16{
		RtcpTypeTCCSymbolSizeOneBit: 1,
		RtcpTypeTCCSymbolSizeTwoBit: 2,
	}
}

var (
	rtcpErrPacketStatusChunkLength = errors.New("packet status chunk must be 2 bytes")
	rtcpErrDeltaExceedLimit        = errors.New("delta exceed limit")
)

type RtcpPacketStatusChunk interface {
	Marshal() ([]byte, error)
	Unmarshal(rawPacket []byte) error
}

type RtcpRunLengthChunk struct {
	RtcpPacketStatusChunk
	Type               uint16
	PacketStatusSymbol uint16
	RunLength          uint16
}

func (r RtcpRunLengthChunk) Marshal() ([]byte, error) {
	chunk := make([]byte, 2)

	dst, err := rtcpSetNBitsOfUint16(0, 1, 0, 0)
	if err != nil {
		return nil, err
	}

	dst, err = rtcpSetNBitsOfUint16(dst, 2, 1, r.PacketStatusSymbol)
	if err != nil {
		return nil, err
	}

	dst, err = rtcpSetNBitsOfUint16(dst, 13, 3, r.RunLength)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(chunk, dst)

	return chunk, nil
}

func (r *RtcpRunLengthChunk) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) != rtcpPacketStatusChunkLength {
		return rtcpErrPacketStatusChunkLength
	}

	r.Type = RtcpTypeTCCRunLengthChunk

	r.PacketStatusSymbol = rtcpGetNBitsFromByte(rawPacket[0], 1, 2)

	r.RunLength = rtcpGetNBitsFromByte(rawPacket[0], 3, 5)<<8 + uint16(rawPacket[1])

	return nil
}

type RtcpStatusVectorChunk struct {
	RtcpPacketStatusChunk
	Type       uint16
	SymbolSize uint16
	SymbolList []uint16
}

func (r RtcpStatusVectorChunk) Marshal() ([]byte, error) {
	chunk := make([]byte, 2)

	dst, err := rtcpSetNBitsOfUint16(0, 1, 0, 1)
	if err != nil {
		return nil, err
	}

	dst, err = rtcpSetNBitsOfUint16(dst, 1, 1, r.SymbolSize)
	if err != nil {
		return nil, err
	}

	numOfBits := rtcpNumOfBitsOfSymbolSize()[r.SymbolSize]

	for i, s := range r.SymbolList {
		index := numOfBits*uint16(i) + 2
		dst, err = rtcpSetNBitsOfUint16(dst, numOfBits, index, s)
		if err != nil {
			return nil, err
		}
	}

	binary.BigEndian.PutUint16(chunk, dst)

	return chunk, nil
}

func (r *RtcpStatusVectorChunk) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) != rtcpPacketStatusChunkLength {
		return rtcpErrPacketStatusChunkLength
	}

	r.Type = RtcpTypeTCCStatusVectorChunk
	r.SymbolSize = rtcpGetNBitsFromByte(rawPacket[0], 1, 1)

	if r.SymbolSize == RtcpTypeTCCSymbolSizeOneBit {
		for i := uint16(0); i < 6; i++ {
			r.SymbolList = append(r.SymbolList, rtcpGetNBitsFromByte(rawPacket[0], 2+i, 1))
		}
		for i := uint16(0); i < 8; i++ {
			r.SymbolList = append(r.SymbolList, rtcpGetNBitsFromByte(rawPacket[1], i, 1))
		}

		return nil
	}
	if r.SymbolSize == RtcpTypeTCCSymbolSizeTwoBit {
		for i := uint16(0); i < 3; i++ {
			r.SymbolList = append(r.SymbolList, rtcpGetNBitsFromByte(rawPacket[0], 2+i*2, 2))
		}
		for i := uint16(0); i < 4; i++ {
			r.SymbolList = append(r.SymbolList, rtcpGetNBitsFromByte(rawPacket[1], i*2, 2))
		}

		return nil
	}

	r.SymbolSize = rtcpGetNBitsFromByte(rawPacket[0], 2, 6)<<8 + uint16(rawPacket[1])

	return nil
}

const (
	RtcpTypeTCCDeltaScaleFactor = 250
)

type RtcpRecvDelta struct {
	Type  uint16
	Delta int64
}

func (r RtcpRecvDelta) Marshal() ([]byte, error) {
	delta := r.Delta / RtcpTypeTCCDeltaScaleFactor

	if r.Type == RtcpTypeTCCPacketReceivedSmallDelta && delta >= 0 && delta <= math.MaxUint8 {
		deltaChunk := make([]byte, 1)
		deltaChunk[0] = byte(delta)

		return deltaChunk, nil
	}

	if r.Type == RtcpTypeTCCPacketReceivedLargeDelta && delta >= math.MinInt16 && delta <= math.MaxInt16 {
		deltaChunk := make([]byte, 2)
		binary.BigEndian.PutUint16(deltaChunk, uint16(delta))

		return deltaChunk, nil
	}

	return nil, rtcpErrDeltaExceedLimit
}

func (r *RtcpRecvDelta) Unmarshal(rawPacket []byte) error {
	chunkLen := len(rawPacket)

	if chunkLen != 1 && chunkLen != 2 {
		return rtcpErrDeltaExceedLimit
	}

	if chunkLen == 1 {
		r.Type = RtcpTypeTCCPacketReceivedSmallDelta
		r.Delta = RtcpTypeTCCDeltaScaleFactor * int64(rawPacket[0])

		return nil
	}

	r.Type = RtcpTypeTCCPacketReceivedLargeDelta
	r.Delta = RtcpTypeTCCDeltaScaleFactor * int64(int16(binary.BigEndian.Uint16(rawPacket)))

	return nil
}

const (
	rtcpBaseSequenceNumberOffset = 8
	rtcpPacketStatusCountOffset  = 10
	rtcpReferenceTimeOffset      = 12
	rtcpFbPktCountOffset         = 15
	rtcpPacketChunkOffset        = 16
)

type RtcpTransportLayerCC struct {
	Header             RtcpHeader
	SenderSSRC         uint32
	MediaSSRC          uint32
	BaseSequenceNumber uint16
	PacketStatusCount  uint16
	ReferenceTime      uint32
	FbPktCount         uint8
	PacketChunks       []RtcpPacketStatusChunk
	RecvDeltas         []*RtcpRecvDelta
}

func (t *RtcpTransportLayerCC) packetLen() uint16 {

	n := uint16(rtcpHeaderLength + rtcpPacketChunkOffset + len(t.PacketChunks)*2)
	for _, d := range t.RecvDeltas {
		if d.Type == RtcpTypeTCCPacketReceivedSmallDelta {
			n++
		} else {
			n += 2
		}
	}

	return n
}

func (t *RtcpTransportLayerCC) Len() uint16 {
	return uint16(t.MarshalSize())
}

func (t *RtcpTransportLayerCC) MarshalSize() int {
	n := t.packetLen()

	if n%4 != 0 {
		n = (n/4 + 1) * 4
	}

	return int(n)
}

func (t RtcpTransportLayerCC) String() string {
	out := fmt.Sprintf("TransportLayerCC:\n\tHeader %v\n", t.Header)
	out += fmt.Sprintf("TransportLayerCC:\n\tSender Ssrc %d\n", t.SenderSSRC)
	out += fmt.Sprintf("\tMedia Ssrc %d\n", t.MediaSSRC)
	out += fmt.Sprintf("\tBase Sequence Number %d\n", t.BaseSequenceNumber)
	out += fmt.Sprintf("\tStatus Count %d\n", t.PacketStatusCount)
	out += fmt.Sprintf("\tReference Time %d\n", t.ReferenceTime)
	out += fmt.Sprintf("\tFeedback Packet Count %d\n", t.FbPktCount)
	out += "\tPacketChunks "
	for _, chunk := range t.PacketChunks {
		out += fmt.Sprintf("%+v ", chunk)
	}
	out += "\n\tRecvDeltas "
	for _, delta := range t.RecvDeltas {
		out += fmt.Sprintf("%+v ", delta)
	}
	out += "\n"

	return out
}

func (t RtcpTransportLayerCC) Marshal() ([]byte, error) {
	header, err := t.Header.Marshal()
	if err != nil {
		return nil, err
	}

	payload := make([]byte, t.MarshalSize()-rtcpHeaderLength)
	binary.BigEndian.PutUint32(payload, t.SenderSSRC)
	binary.BigEndian.PutUint32(payload[4:], t.MediaSSRC)
	binary.BigEndian.PutUint16(payload[rtcpBaseSequenceNumberOffset:], t.BaseSequenceNumber)
	binary.BigEndian.PutUint16(payload[rtcpPacketStatusCountOffset:], t.PacketStatusCount)
	ReferenceTimeAndFbPktCount := rtcpAppendNBitsToUint32(0, 24, t.ReferenceTime)
	ReferenceTimeAndFbPktCount = rtcpAppendNBitsToUint32(ReferenceTimeAndFbPktCount, 8, uint32(t.FbPktCount))
	binary.BigEndian.PutUint32(payload[rtcpReferenceTimeOffset:], ReferenceTimeAndFbPktCount)

	for i, chunk := range t.PacketChunks {
		b, err := chunk.Marshal()
		if err != nil {
			return nil, err
		}
		copy(payload[rtcpPacketChunkOffset+i*2:], b)
	}

	recvDeltaOffset := rtcpPacketChunkOffset + len(t.PacketChunks)*2
	var i int
	for _, delta := range t.RecvDeltas {
		b, err := delta.Marshal()
		if err == nil {
			copy(payload[recvDeltaOffset+i:], b)
			i++
			if delta.Type == RtcpTypeTCCPacketReceivedLargeDelta {
				i++
			}
		}
	}

	if t.Header.Padding {
		payload[len(payload)-1] = uint8(t.MarshalSize() - int(t.packetLen()))
	}

	return append(header, payload...), nil
}

func (t *RtcpTransportLayerCC) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (rtcpHeaderLength + rtcpSsrcLength) {
		return rtcpErrPacketTooShort
	}

	if err := t.Header.Unmarshal(rawPacket); err != nil {
		return err
	}

	totalLength := 4 * (t.Header.Length + 1)

	if totalLength < rtcpHeaderLength+rtcpPacketChunkOffset {
		return rtcpErrPacketTooShort
	}

	if len(rawPacket) < int(totalLength) {
		return rtcpErrPacketTooShort
	}

	if t.Header.Type != RtcpTypeTransportSpecificFeedback || t.Header.Count != RtcpFormatTCC {
		return rtcpErrWrongType
	}

	t.SenderSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength:])
	t.MediaSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength+rtcpSsrcLength:])
	t.BaseSequenceNumber = binary.BigEndian.Uint16(rawPacket[rtcpHeaderLength+rtcpBaseSequenceNumberOffset:])
	t.PacketStatusCount = binary.BigEndian.Uint16(rawPacket[rtcpHeaderLength+rtcpPacketStatusCountOffset:])
	t.ReferenceTime = rtcpGet24BitsFromBytes(rawPacket[rtcpHeaderLength+rtcpReferenceTimeOffset : rtcpHeaderLength+rtcpReferenceTimeOffset+3])
	t.FbPktCount = rawPacket[rtcpHeaderLength+rtcpFbPktCountOffset]

	packetStatusPos := uint16(rtcpHeaderLength + rtcpPacketChunkOffset)
	var processedPacketNum uint16
	for processedPacketNum < t.PacketStatusCount {
		if packetStatusPos+rtcpPacketStatusChunkLength >= totalLength {
			return rtcpErrPacketTooShort
		}
		typ := rtcpGetNBitsFromByte(rawPacket[packetStatusPos : packetStatusPos+1][0], 0, 1)
		var iPacketStatus RtcpPacketStatusChunk
		switch typ {
		case RtcpTypeTCCRunLengthChunk:
			packetStatus := &RtcpRunLengthChunk{Type: typ}
			iPacketStatus = packetStatus
			err := packetStatus.Unmarshal(rawPacket[packetStatusPos : packetStatusPos+2])
			if err != nil {
				return err
			}

			packetNumberToProcess := rtcpLocalMin(t.PacketStatusCount-processedPacketNum, packetStatus.RunLength)
			if packetStatus.PacketStatusSymbol == RtcpTypeTCCPacketReceivedSmallDelta ||
				packetStatus.PacketStatusSymbol == RtcpTypeTCCPacketReceivedLargeDelta {
				for j := uint16(0); j < packetNumberToProcess; j++ {
					t.RecvDeltas = append(t.RecvDeltas, &RtcpRecvDelta{Type: packetStatus.PacketStatusSymbol})
				}
			}
			processedPacketNum += packetNumberToProcess
		case RtcpTypeTCCStatusVectorChunk:
			packetStatus := &RtcpStatusVectorChunk{Type: typ}
			iPacketStatus = packetStatus
			err := packetStatus.Unmarshal(rawPacket[packetStatusPos : packetStatusPos+2])
			if err != nil {
				return err
			}
			if packetStatus.SymbolSize == RtcpTypeTCCSymbolSizeOneBit {
				for j := 0; j < len(packetStatus.SymbolList); j++ {
					if packetStatus.SymbolList[j] == RtcpTypeTCCPacketReceivedSmallDelta {
						t.RecvDeltas = append(t.RecvDeltas, &RtcpRecvDelta{Type: RtcpTypeTCCPacketReceivedSmallDelta})
					}
				}
			}
			if packetStatus.SymbolSize == RtcpTypeTCCSymbolSizeTwoBit {
				for j := 0; j < len(packetStatus.SymbolList); j++ {
					if packetStatus.SymbolList[j] == RtcpTypeTCCPacketReceivedSmallDelta ||
						packetStatus.SymbolList[j] == RtcpTypeTCCPacketReceivedLargeDelta {
						t.RecvDeltas = append(t.RecvDeltas, &RtcpRecvDelta{Type: packetStatus.SymbolList[j]})
					}
				}
			}
			processedPacketNum += uint16(len(packetStatus.SymbolList))
		}
		packetStatusPos += rtcpPacketStatusChunkLength
		t.PacketChunks = append(t.PacketChunks, iPacketStatus)
	}

	recvDeltasPos := packetStatusPos
	for _, delta := range t.RecvDeltas {
		if delta.Type == RtcpTypeTCCPacketReceivedSmallDelta {
			if recvDeltasPos+1 > totalLength {
				return rtcpErrPacketTooShort
			}
			err := delta.Unmarshal(rawPacket[recvDeltasPos : recvDeltasPos+1])
			if err != nil {
				return err
			}
			recvDeltasPos++
		}
		if delta.Type == RtcpTypeTCCPacketReceivedLargeDelta {
			if recvDeltasPos+2 > totalLength {
				return rtcpErrPacketTooShort
			}
			err := delta.Unmarshal(rawPacket[recvDeltasPos : recvDeltasPos+2])
			if err != nil {
				return err
			}
			recvDeltasPos += 2
		}
	}

	return nil
}

func (t RtcpTransportLayerCC) DestinationSSRC() []uint32 {
	return []uint32{t.MediaSSRC}
}

func rtcpLocalMin(x, y uint16) uint16 {
	if x < y {
		return x
	}

	return y
}

type RtcpPacketBitmap uint16

type RtcpNackPair struct {
	PacketID    uint16
	LostPackets RtcpPacketBitmap
}

type RtcpTransportLayerNack struct {
	SenderSSRC uint32
	MediaSSRC  uint32
	Nacks      []RtcpNackPair
}

func (n *RtcpNackPair) Range(f func(seqno uint16) bool) {
	more := f(n.PacketID)
	if !more {
		return
	}

	b := n.LostPackets
	for i := uint16(0); b != 0; i++ {
		if (b & (1 << i)) != 0 {
			b &^= (1 << i)
			more = f(n.PacketID + i + 1)
			if !more {
				return
			}
		}
	}
}

func (n *RtcpNackPair) PacketList() []uint16 {
	out := make([]uint16, 0, 17)
	n.Range(func(seqno uint16) bool {
		out = append(out, seqno)

		return true
	})

	return out
}

const (
	rtcpTlnLength  = 2
	rtcpNackOffset = 8
)

func (p RtcpTransportLayerNack) Marshal() ([]byte, error) {
	if len(p.Nacks)+rtcpTlnLength > math.MaxUint8 {
		return nil, rtcpErrTooManyReports
	}

	rawPacket := make([]byte, rtcpNackOffset+(len(p.Nacks)*4))
	binary.BigEndian.PutUint32(rawPacket, p.SenderSSRC)
	binary.BigEndian.PutUint32(rawPacket[4:], p.MediaSSRC)
	for i := 0; i < len(p.Nacks); i++ {
		binary.BigEndian.PutUint16(rawPacket[rtcpNackOffset+(4*i):], p.Nacks[i].PacketID)
		binary.BigEndian.PutUint16(rawPacket[rtcpNackOffset+(4*i)+2:], uint16(p.Nacks[i].LostPackets))
	}
	h := p.Header()
	hData, err := h.Marshal()
	if err != nil {
		return nil, err
	}

	return append(hData, rawPacket...), nil
}

func (p *RtcpTransportLayerNack) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (rtcpHeaderLength + rtcpSsrcLength) {
		return rtcpErrPacketTooShort
	}

	var header RtcpHeader
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if len(rawPacket) < (rtcpHeaderLength + int(4*header.Length)) {
		return rtcpErrPacketTooShort
	}

	if header.Type != RtcpTypeTransportSpecificFeedback || header.Count != RtcpFormatTLN {
		return rtcpErrWrongType
	}

	if 4*header.Length <= rtcpNackOffset {
		return rtcpErrBadLength
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[rtcpHeaderLength+rtcpSsrcLength:])
	for i := rtcpHeaderLength + rtcpNackOffset; i < (rtcpHeaderLength + int(header.Length*4)); i += 4 {
		p.Nacks = append(p.Nacks, RtcpNackPair{
			binary.BigEndian.Uint16(rawPacket[i:]),
			RtcpPacketBitmap(binary.BigEndian.Uint16(rawPacket[i+2:])),
		})
	}

	return nil
}

func (p *RtcpTransportLayerNack) MarshalSize() int {
	return rtcpHeaderLength + rtcpNackOffset + (len(p.Nacks) * 4)
}

func (p *RtcpTransportLayerNack) Header() RtcpHeader {
	return RtcpHeader{
		Count:  RtcpFormatTLN,
		Type:   RtcpTypeTransportSpecificFeedback,
		Length: uint16((p.MarshalSize() / 4) - 1),
	}
}

func (p RtcpTransportLayerNack) String() string {
	out := fmt.Sprintf("TransportLayerNack from %x\n", p.SenderSSRC)
	out += fmt.Sprintf("\tMedia Ssrc %x\n", p.MediaSSRC)
	out += "\tID\tLostPackets\n"
	for _, i := range p.Nacks {
		out += fmt.Sprintf("\t%d\t%b\n", i.PacketID, i.LostPackets)
	}

	return out
}

func (p *RtcpTransportLayerNack) DestinationSSRC() []uint32 {
	return []uint32{p.MediaSSRC}
}

func rtcpGetPadding(packetLen int) int {
	if packetLen%4 == 0 {
		return 0
	}

	return 4 - (packetLen % 4)
}

func rtcpSetNBitsOfUint16(src, size, startIndex, val uint16) (uint16, error) {
	if startIndex+size > 16 {
		return 0, rtcpErrInvalidSizeOrStartIndex
	}

	val &= (1 << size) - 1

	return src | (val << (16 - size - startIndex)), nil
}

func rtcpAppendNBitsToUint32(src, n, val uint32) uint32 {
	return (src << n) | (val & (0xFFFFFFFF >> (32 - n)))
}

func rtcpGetNBitsFromByte(b byte, begin, n uint16) uint16 {
	endShift := 8 - (begin + n)
	mask := (0xFF >> begin) & uint8(0xFF<<endShift)

	return uint16(b&mask) >> endShift
}

func rtcpGet24BitsFromBytes(b []byte) uint32 {
	return uint32(b[0])<<16 + uint32(b[1])<<8 + uint32(b[2])
}
