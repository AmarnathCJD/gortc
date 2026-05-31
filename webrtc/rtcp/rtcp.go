// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package rtcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"unsafe"
)

type ApplicationDefined struct {
	SubType uint8
	SSRC    uint32
	Name    string
	Data    []byte
}

func (a ApplicationDefined) DestinationSSRC() []uint32 {
	return []uint32{a.SSRC}
}

func (a ApplicationDefined) Marshal() ([]byte, error) {
	dataLength := len(a.Data)
	if dataLength > 0xFFFF-12 {
		return nil, errAppDefinedDataTooLarge
	}
	if len(a.Name) != 4 {
		return nil, errAppDefinedInvalidName
	}

	paddingSize := 4 - (dataLength % 4)
	if paddingSize == 4 {
		paddingSize = 0
	}

	packetSize := a.MarshalSize()
	header := Header{
		Type:    TypeApplicationDefined,
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

func (a *ApplicationDefined) Unmarshal(rawPacket []byte) error {

	header := Header{}
	err := header.Unmarshal(rawPacket)
	if err != nil {
		return err
	}
	if len(rawPacket) < 12 {
		return errPacketTooShort
	}

	if int(header.Length+1)*4 != len(rawPacket) {
		return errAppDefinedInvalidLength
	}

	a.SubType = header.Count
	a.SSRC = binary.BigEndian.Uint32(rawPacket[4:8])
	a.Name = string(rawPacket[8:12])

	paddingSize := 0
	if header.Padding {
		paddingSize = int(rawPacket[len(rawPacket)-1])
		if paddingSize > len(rawPacket)-12 {
			return errWrongPadding
		}
	}

	a.Data = rawPacket[12 : len(rawPacket)-paddingSize]

	return nil
}

func (a *ApplicationDefined) MarshalSize() int {
	dataLength := len(a.Data)

	paddingSize := 4 - (dataLength % 4)
	if paddingSize == 4 {
		paddingSize = 0
	}

	return 12 + dataLength + paddingSize
}

var (
	errWrongMarshalSize         = errors.New("rtcp: wrong marshal size")
	errInvalidTotalLost         = errors.New("rtcp: invalid total lost count")
	errInvalidHeader            = errors.New("rtcp: invalid header")
	errTooManyReports           = errors.New("rtcp: too many reports")
	errTooManyChunks            = errors.New("rtcp: too many chunks")
	errTooManySources           = errors.New("rtcp: too many sources")
	errPacketTooShort           = errors.New("rtcp: packet too short")
	errWrongType                = errors.New("rtcp: wrong packet type")
	errSDESTextTooLong          = errors.New("rtcp: sdes must be < 255 octets long")
	errSDESMissingType          = errors.New("rtcp: sdes item missing type")
	errReasonTooLong            = errors.New("rtcp: reason must be < 255 octets long")
	errBadVersion               = errors.New("rtcp: invalid packet version")
	errBadLength                = errors.New("rtcp: invalid packet length")
	errWrongPadding             = errors.New("rtcp: invalid padding value")
	errWrongFeedbackType        = errors.New("rtcp: wrong feedback message type")
	errWrongPayloadType         = errors.New("rtcp: wrong payload type")
	errHeaderTooSmall           = errors.New("rtcp: header length is too small")
	errSSRCMustBeZero           = errors.New("rtcp: media SSRC must be 0")
	errMissingREMBidentifier    = errors.New("missing REMB identifier")
	errSSRCNumAndLengthMismatch = errors.New("SSRC num and length do not match")
	errInvalidSizeOrStartIndex  = errors.New("invalid size or startIndex")
	errInvalidBitrate           = errors.New("invalid bitrate")
	errWrongChunkType           = errors.New("rtcp: wrong chunk type")
	errBadStructMemberType      = errors.New("rtcp: struct contains unexpected member type")
	errBadReadParameter         = errors.New("rtcp: cannot read into non-pointer")
	errAppDefinedInvalidLength  = errors.New("rtcp: application defined type invalid length")
	errAppDefinedDataTooLarge   = errors.New("rtcp: application defined data is too large")
	errAppDefinedInvalidName    = errors.New("rtcp: application defined name must be 4 ASCII chars")
)

type ExtendedReport struct {
	SenderSSRC uint32 `fmt:"0x%X"`
	Reports    []ReportBlock
}

type ReportBlock interface {
	DestinationSSRC() []uint32
	setupBlockHeader()
	unpackBlockHeader()
}

type TypeSpecificField uint8

type XRHeader struct {
	BlockType    BlockTypeType
	TypeSpecific TypeSpecificField `fmt:"0x%X"`
	BlockLength  uint16
}

type BlockTypeType uint8

const (
	LossRLEReportBlockType               = 1
	DuplicateRLEReportBlockType          = 2
	PacketReceiptTimesReportBlockType    = 3
	ReceiverReferenceTimeReportBlockType = 4
	DLRRReportBlockType                  = 5
	StatisticsSummaryReportBlockType     = 6
	VoIPMetricsReportBlockType           = 7
)

func (t BlockTypeType) String() string {
	switch t {
	case LossRLEReportBlockType:
		return "LossRLEReportBlockType"
	case DuplicateRLEReportBlockType:
		return "DuplicateRLEReportBlockType"
	case PacketReceiptTimesReportBlockType:
		return "PacketReceiptTimesReportBlockType"
	case ReceiverReferenceTimeReportBlockType:
		return "ReceiverReferenceTimeReportBlockType"
	case DLRRReportBlockType:
		return "DLRRReportBlockType"
	case StatisticsSummaryReportBlockType:
		return "StatisticsSummaryReportBlockType"
	case VoIPMetricsReportBlockType:
		return "VoIPMetricsReportBlockType"
	}

	return fmt.Sprintf("invalid value %d", t)
}

type rleReportBlock struct {
	XRHeader
	T        uint8  `encoding:"omit"`
	SSRC     uint32 `fmt:"0x%X"`
	BeginSeq uint16
	EndSeq   uint16
	Chunks   []Chunk
}

type Chunk uint16

type LossRLEReportBlock rleReportBlock

func (b *LossRLEReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *LossRLEReportBlock) setupBlockHeader() {
	b.XRHeader.BlockType = LossRLEReportBlockType
	b.XRHeader.TypeSpecific = TypeSpecificField(b.T & 0x0F)
	b.XRHeader.BlockLength = uint16(wireSize(b)/4 - 1)
}

func (b *LossRLEReportBlock) unpackBlockHeader() {
	b.T = uint8(b.XRHeader.TypeSpecific) & 0x0F
}

type DuplicateRLEReportBlock rleReportBlock

func (b *DuplicateRLEReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *DuplicateRLEReportBlock) setupBlockHeader() {
	b.XRHeader.BlockType = DuplicateRLEReportBlockType
	b.XRHeader.TypeSpecific = TypeSpecificField(b.T & 0x0F)
	b.XRHeader.BlockLength = uint16(wireSize(b)/4 - 1)
}

func (b *DuplicateRLEReportBlock) unpackBlockHeader() {
	b.T = uint8(b.XRHeader.TypeSpecific) & 0x0F
}

type ChunkType uint8

const (
	RunLengthChunkType       = 0
	BitVectorChunkType       = 1
	TerminatingNullChunkType = 2
)

func (c Chunk) String() string {
	switch c.Type() {
	case RunLengthChunkType:
		runType, _ := c.RunType()

		return fmt.Sprintf("[RunLength type=%d, length=%d]", runType, c.Value())
	case BitVectorChunkType:
		return fmt.Sprintf("[BitVector 0b%015b]", c.Value())
	case TerminatingNullChunkType:
		return "[TerminatingNull]"
	}

	return fmt.Sprintf("[0x%X]", uint16(c))
}

func (c Chunk) Type() ChunkType {
	if c == 0 {
		return TerminatingNullChunkType
	}

	return ChunkType(c >> 15)
}

func (c Chunk) RunType() (uint, error) {
	if c.Type() != RunLengthChunkType {
		return 0, errWrongChunkType
	}

	return uint((c >> 14) & 0x01), nil
}

func (c Chunk) Value() uint {
	switch c.Type() {
	case RunLengthChunkType:
		return uint(c & 0x3FFF)
	case BitVectorChunkType:
		return uint(c & 0x7FFF)
	case TerminatingNullChunkType:
		return 0
	}

	return uint(c)
}

type PacketReceiptTimesReportBlock struct {
	XRHeader
	T           uint8  `encoding:"omit"`
	SSRC        uint32 `fmt:"0x%X"`
	BeginSeq    uint16
	EndSeq      uint16
	ReceiptTime []uint32
}

func (b *PacketReceiptTimesReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *PacketReceiptTimesReportBlock) setupBlockHeader() {
	b.XRHeader.BlockType = PacketReceiptTimesReportBlockType
	b.XRHeader.TypeSpecific = TypeSpecificField(b.T & 0x0F)
	b.XRHeader.BlockLength = uint16(wireSize(b)/4 - 1)
}

func (b *PacketReceiptTimesReportBlock) unpackBlockHeader() {
	b.T = uint8(b.XRHeader.TypeSpecific) & 0x0F
}

type ReceiverReferenceTimeReportBlock struct {
	XRHeader
	NTPTimestamp uint64
}

func (b *ReceiverReferenceTimeReportBlock) DestinationSSRC() []uint32 {
	return []uint32{}
}

func (b *ReceiverReferenceTimeReportBlock) setupBlockHeader() {
	b.XRHeader.BlockType = ReceiverReferenceTimeReportBlockType
	b.XRHeader.TypeSpecific = 0
	b.XRHeader.BlockLength = uint16(wireSize(b)/4 - 1)
}

func (b *ReceiverReferenceTimeReportBlock) unpackBlockHeader() {
}

type DLRRReportBlock struct {
	XRHeader
	Reports []DLRRReport
}

type DLRRReport struct {
	SSRC   uint32 `fmt:"0x%X"`
	LastRR uint32
	DLRR   uint32
}

func (b *DLRRReportBlock) DestinationSSRC() []uint32 {
	ssrc := make([]uint32, len(b.Reports))
	for i, r := range b.Reports {
		ssrc[i] = r.SSRC
	}

	return ssrc
}

func (b *DLRRReportBlock) setupBlockHeader() {
	b.XRHeader.BlockType = DLRRReportBlockType
	b.XRHeader.TypeSpecific = 0
	b.XRHeader.BlockLength = uint16(wireSize(b)/4 - 1)
}

func (b *DLRRReportBlock) unpackBlockHeader() {
}

type StatisticsSummaryReportBlock struct {
	XRHeader
	LossReports      bool              `encoding:"omit"`
	DuplicateReports bool              `encoding:"omit"`
	JitterReports    bool              `encoding:"omit"`
	TTLorHopLimit    TTLorHopLimitType `encoding:"omit"`
	SSRC             uint32            `fmt:"0x%X"`
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

type TTLorHopLimitType uint8

const (
	ToHMissing = 0
	ToHIPv4    = 1
	ToHIPv6    = 2
)

func (t TTLorHopLimitType) String() string {
	switch t {
	case ToHMissing:
		return "[ToH Missing]"
	case ToHIPv4:
		return "[ToH = IPv4]"
	case ToHIPv6:
		return "[ToH = IPv6]"
	}

	return "[ToH Flag is Invalid]"
}

func (b *StatisticsSummaryReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *StatisticsSummaryReportBlock) setupBlockHeader() {
	b.XRHeader.BlockType = StatisticsSummaryReportBlockType
	b.XRHeader.TypeSpecific = 0x00
	if b.LossReports {
		b.XRHeader.TypeSpecific |= 0x80
	}
	if b.DuplicateReports {
		b.XRHeader.TypeSpecific |= 0x40
	}
	if b.JitterReports {
		b.XRHeader.TypeSpecific |= 0x20
	}
	b.XRHeader.TypeSpecific |= TypeSpecificField((b.TTLorHopLimit & 0x03) << 3)
	b.XRHeader.BlockLength = uint16(wireSize(b)/4 - 1)
}

func (b *StatisticsSummaryReportBlock) unpackBlockHeader() {
	b.LossReports = b.XRHeader.TypeSpecific&0x80 != 0
	b.DuplicateReports = b.XRHeader.TypeSpecific&0x40 != 0
	b.JitterReports = b.XRHeader.TypeSpecific&0x20 != 0
	b.TTLorHopLimit = TTLorHopLimitType((b.XRHeader.TypeSpecific & 0x18) >> 3)
}

type VoIPMetricsReportBlock struct {
	XRHeader
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

func (b *VoIPMetricsReportBlock) DestinationSSRC() []uint32 {
	return []uint32{b.SSRC}
}

func (b *VoIPMetricsReportBlock) setupBlockHeader() {
	b.XRHeader.BlockType = VoIPMetricsReportBlockType
	b.XRHeader.TypeSpecific = 0
	b.XRHeader.BlockLength = uint16(wireSize(b)/4 - 1)
}

func (b *VoIPMetricsReportBlock) unpackBlockHeader() {
}

type UnknownReportBlock struct {
	XRHeader
	Bytes []byte
}

func (b *UnknownReportBlock) DestinationSSRC() []uint32 {
	return []uint32{}
}

func (b *UnknownReportBlock) setupBlockHeader() {
	b.XRHeader.BlockLength = uint16(wireSize(b)/4 - 1)
}

func (b *UnknownReportBlock) unpackBlockHeader() {
}

func (x ExtendedReport) MarshalSize() int {
	return wireSize(x)
}

func (x ExtendedReport) Marshal() ([]byte, error) {
	for _, p := range x.Reports {
		p.setupBlockHeader()
	}

	length := wireSize(x)

	header := Header{
		Type:   TypeExtendedReport,
		Length: uint16(length / 4),
	}
	headerBuffer, err := header.Marshal()
	if err != nil {
		return []byte{}, err
	}
	length += len(headerBuffer)

	rawPacket := make([]byte, length)
	buffer := packetBuffer{bytes: rawPacket}

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

func (x *ExtendedReport) Unmarshal(b []byte) error {
	var header Header
	if err := header.Unmarshal(b); err != nil {
		return err
	}
	if header.Type != TypeExtendedReport {
		return errWrongType
	}

	buffer := packetBuffer{bytes: b[headerLength:]}
	err := buffer.read(&x.SenderSSRC)
	if err != nil {
		return err
	}

	for len(buffer.bytes) > 0 {
		var block ReportBlock

		headerBuffer := buffer
		xrHeader := XRHeader{}
		err = headerBuffer.read(&xrHeader)
		if err != nil {
			return err
		}

		switch xrHeader.BlockType {
		case LossRLEReportBlockType:
			block = new(LossRLEReportBlock)
		case DuplicateRLEReportBlockType:
			block = new(DuplicateRLEReportBlock)
		case PacketReceiptTimesReportBlockType:
			block = new(PacketReceiptTimesReportBlock)
		case ReceiverReferenceTimeReportBlockType:
			block = new(ReceiverReferenceTimeReportBlock)
		case DLRRReportBlockType:
			block = new(DLRRReportBlock)
		case StatisticsSummaryReportBlockType:
			block = new(StatisticsSummaryReportBlock)
		case VoIPMetricsReportBlockType:
			block = new(VoIPMetricsReportBlock)
		default:
			block = new(UnknownReportBlock)
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

func (x *ExtendedReport) DestinationSSRC() []uint32 {
	ssrc := make([]uint32, 0, len(x.Reports)+1)
	ssrc = append(ssrc, x.SenderSSRC)
	for _, p := range x.Reports {
		ssrc = append(ssrc, p.DestinationSSRC()...)
	}

	return ssrc
}

func (x *ExtendedReport) String() string {
	return stringify(x)
}

type FIREntry struct {
	SSRC           uint32
	SequenceNumber uint8
}

type FullIntraRequest struct {
	SenderSSRC uint32
	MediaSSRC  uint32
	FIR        []FIREntry
}

const (
	firOffset = 8
)

var _ Packet = (*FullIntraRequest)(nil)

func (p FullIntraRequest) Marshal() ([]byte, error) {
	rawPacket := make([]byte, firOffset+(len(p.FIR)*8))
	binary.BigEndian.PutUint32(rawPacket, p.SenderSSRC)
	binary.BigEndian.PutUint32(rawPacket[4:], p.MediaSSRC)
	for i, fir := range p.FIR {
		binary.BigEndian.PutUint32(rawPacket[firOffset+8*i:], fir.SSRC)
		rawPacket[firOffset+8*i+4] = fir.SequenceNumber
	}
	h := p.Header()
	hData, err := h.Marshal()
	if err != nil {
		return nil, err
	}

	return append(hData, rawPacket...), nil
}

func (p *FullIntraRequest) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (headerLength + ssrcLength) {
		return errPacketTooShort
	}

	var header Header
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if len(rawPacket) < (headerLength + int(4*header.Length)) {
		return errPacketTooShort
	}

	if header.Type != TypePayloadSpecificFeedback || header.Count != FormatFIR {
		return errWrongType
	}

	if 4*header.Length-firOffset <= 0 || (4*header.Length)%8 != 0 {
		return errBadLength
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[headerLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[headerLength+ssrcLength:])
	for i := headerLength + firOffset; i < (headerLength + int(header.Length*4)); i += 8 {
		p.FIR = append(p.FIR, FIREntry{
			binary.BigEndian.Uint32(rawPacket[i:]),
			rawPacket[i+4],
		})
	}

	return nil
}

func (p *FullIntraRequest) Header() Header {
	return Header{
		Count:  FormatFIR,
		Type:   TypePayloadSpecificFeedback,
		Length: uint16((p.MarshalSize() / 4) - 1),
	}
}

func (p *FullIntraRequest) MarshalSize() int {
	return headerLength + firOffset + len(p.FIR)*8
}

func (p *FullIntraRequest) String() string {
	out := fmt.Sprintf("FullIntraRequest %x %x",
		p.SenderSSRC, p.MediaSSRC)
	for _, e := range p.FIR {
		out += fmt.Sprintf(" (%x %v)", e.SSRC, e.SequenceNumber)
	}

	return out
}

func (p *FullIntraRequest) DestinationSSRC() []uint32 {
	ssrcs := make([]uint32, 0, len(p.FIR))
	for _, entry := range p.FIR {
		ssrcs = append(ssrcs, entry.SSRC)
	}

	return ssrcs
}

type Goodbye struct {
	Sources []uint32
	Reason  string
}

func (g Goodbye) Marshal() ([]byte, error) {

	rawPacket := make([]byte, g.MarshalSize())
	packetBody := rawPacket[headerLength:]

	if len(g.Sources) > countMax {
		return nil, errTooManySources
	}

	for i, s := range g.Sources {
		binary.BigEndian.PutUint32(packetBody[i*ssrcLength:], s)
	}

	if g.Reason != "" {
		reason := []byte(g.Reason)

		if len(reason) > sdesMaxOctetCount {
			return nil, errReasonTooLong
		}

		reasonOffset := len(g.Sources) * ssrcLength
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

func (g *Goodbye) Unmarshal(rawPacket []byte) error {

	var header Header
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != TypeGoodbye {
		return errWrongType
	}

	if getPadding(len(rawPacket)) != 0 {
		return errPacketTooShort
	}

	g.Sources = make([]uint32, header.Count)

	reasonOffset := int(headerLength + header.Count*ssrcLength)
	if reasonOffset > len(rawPacket) {
		return errPacketTooShort
	}

	for i := 0; i < int(header.Count); i++ {
		offset := headerLength + i*ssrcLength

		g.Sources[i] = binary.BigEndian.Uint32(rawPacket[offset:])
	}

	if reasonOffset < len(rawPacket) {
		reasonLen := int(rawPacket[reasonOffset])
		reasonEnd := reasonOffset + 1 + reasonLen

		if reasonEnd > len(rawPacket) {
			return errPacketTooShort
		}

		g.Reason = string(rawPacket[reasonOffset+1 : reasonEnd])
	}

	return nil
}

func (g *Goodbye) Header() Header {
	return Header{
		Padding: false,
		Count:   uint8(len(g.Sources)),
		Type:    TypeGoodbye,
		Length:  uint16((g.MarshalSize() / 4) - 1),
	}
}

func (g *Goodbye) MarshalSize() int {
	srcsLength := len(g.Sources) * ssrcLength

	reasonLength := len(g.Reason)
	if reasonLength > 0 {
		reasonLength++
	}

	l := headerLength + srcsLength + reasonLength

	return l + getPadding(l)
}

func (g *Goodbye) DestinationSSRC() []uint32 {
	out := make([]uint32, len(g.Sources))
	copy(out, g.Sources)

	return out
}

func (g Goodbye) String() string {
	out := "Goodbye\n"
	for i, s := range g.Sources {
		out += fmt.Sprintf("\tSource %d: %x\n", i, s)
	}
	out += fmt.Sprintf("\tReason: %s\n", g.Reason)

	return out
}

type PacketType uint8

const (
	TypeSenderReport              PacketType = 200
	TypeReceiverReport            PacketType = 201
	TypeSourceDescription         PacketType = 202
	TypeGoodbye                   PacketType = 203
	TypeApplicationDefined        PacketType = 204
	TypeTransportSpecificFeedback PacketType = 205
	TypePayloadSpecificFeedback   PacketType = 206
	TypeExtendedReport            PacketType = 207
)

const (
	FormatSLI  uint8 = 2
	FormatPLI  uint8 = 1
	FormatFIR  uint8 = 4
	FormatTLN  uint8 = 1
	FormatRRR  uint8 = 5
	FormatCCFB uint8 = 11
	FormatREMB uint8 = 15

	FormatTCC uint8 = 15
)

func (p PacketType) String() string {
	switch p {
	case TypeSenderReport:
		return "SR"
	case TypeReceiverReport:
		return "RR"
	case TypeSourceDescription:
		return "SDES"
	case TypeGoodbye:
		return "BYE"
	case TypeApplicationDefined:
		return "APP"
	case TypeTransportSpecificFeedback:
		return "TSFB"
	case TypePayloadSpecificFeedback:
		return "PSFB"
	case TypeExtendedReport:
		return "XR"
	default:
		return string(p)
	}
}

const rtpVersion = 2

type Header struct {
	Padding bool
	Count   uint8
	Type    PacketType
	Length  uint16
}

const (
	headerLength = 4
	versionShift = 6
	versionMask  = 0x3
	paddingShift = 5
	paddingMask  = 0x1
	countShift   = 0
	countMask    = 0x1f
	countMax     = (1 << 5) - 1
)

func (h Header) Marshal() ([]byte, error) {

	rawPacket := make([]byte, headerLength)

	rawPacket[0] |= rtpVersion << versionShift

	if h.Padding {
		rawPacket[0] |= 1 << paddingShift
	}

	if h.Count > 31 {
		return nil, errInvalidHeader
	}
	rawPacket[0] |= h.Count << countShift

	rawPacket[1] = uint8(h.Type)

	binary.BigEndian.PutUint16(rawPacket[2:], h.Length)

	return rawPacket, nil
}

func (h *Header) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < headerLength {
		return errPacketTooShort
	}

	version := rawPacket[0] >> versionShift & versionMask
	if version != rtpVersion {
		return errBadVersion
	}

	h.Padding = (rawPacket[0] >> paddingShift & paddingMask) > 0
	h.Count = rawPacket[0] >> countShift & countMask

	h.Type = PacketType(rawPacket[1])

	h.Length = binary.BigEndian.Uint16(rawPacket[2:])

	return nil
}

type Packet interface {
	DestinationSSRC() []uint32
	Marshal() ([]byte, error)
	Unmarshal(rawPacket []byte) error
	MarshalSize() int
}

func Unmarshal(rawData []byte) ([]Packet, error) {
	var packets []Packet
	for len(rawData) != 0 {
		p, processed, err := unmarshal(rawData)
		if err != nil {
			return nil, err
		}

		packets = append(packets, p)
		rawData = rawData[processed:]
	}

	switch len(packets) {

	case 0:
		return nil, errInvalidHeader

	default:
		return packets, nil
	}
}

func Marshal(packets []Packet) ([]byte, error) {
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

func unmarshal(rawData []byte) (packet Packet, bytesprocessed int, err error) {
	var header Header

	err = header.Unmarshal(rawData)
	if err != nil {
		return nil, 0, err
	}

	bytesprocessed = int(header.Length+1) * 4
	if bytesprocessed > len(rawData) {
		return nil, 0, errPacketTooShort
	}
	inPacket := rawData[:bytesprocessed]

	switch header.Type {
	case TypeSenderReport:
		packet = new(SenderReport)

	case TypeReceiverReport:
		packet = new(ReceiverReport)

	case TypeSourceDescription:
		packet = new(SourceDescription)

	case TypeGoodbye:
		packet = new(Goodbye)

	case TypeTransportSpecificFeedback:
		switch header.Count {
		case FormatTLN:
			packet = new(TransportLayerNack)
		case FormatRRR:
			packet = new(RapidResynchronizationRequest)
		case FormatTCC:
			packet = new(TransportLayerCC)
		case FormatCCFB:
			packet = new(CCFeedbackReport)
		default:
			packet = new(RawPacket)
		}

	case TypePayloadSpecificFeedback:
		switch header.Count {
		case FormatPLI:
			packet = new(PictureLossIndication)
		case FormatSLI:
			packet = new(SliceLossIndication)
		case FormatREMB:
			packet = new(ReceiverEstimatedMaximumBitrate)
		case FormatFIR:
			packet = new(FullIntraRequest)
		default:
			packet = new(RawPacket)
		}

	case TypeExtendedReport:
		packet = new(ExtendedReport)

	case TypeApplicationDefined:
		packet = new(ApplicationDefined)

	default:
		packet = new(RawPacket)
	}

	err = packet.Unmarshal(inPacket)

	return packet, bytesprocessed, err
}

type packetBuffer struct {
	bytes []byte
}

const omit = "omit"

func (b *packetBuffer) write(v any) error {
	value := reflect.ValueOf(v)

	value = reflect.Indirect(value)

	switch value.Kind() {
	case reflect.Uint8:
		if len(b.bytes) < 1 {
			return errWrongMarshalSize
		}
		if value.CanInterface() {
			b.bytes[0] = byte(value.Uint())
		}
		b.bytes = b.bytes[1:]
	case reflect.Uint16:
		if len(b.bytes) < 2 {
			return errWrongMarshalSize
		}
		if value.CanInterface() {
			binary.BigEndian.PutUint16(b.bytes, uint16(value.Uint()))
		}
		b.bytes = b.bytes[2:]
	case reflect.Uint32:
		if len(b.bytes) < 4 {
			return errWrongMarshalSize
		}
		if value.CanInterface() {
			binary.BigEndian.PutUint32(b.bytes, uint32(value.Uint()))
		}
		b.bytes = b.bytes[4:]
	case reflect.Uint64:
		if len(b.bytes) < 8 {
			return errWrongMarshalSize
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
			if encoding == omit {
				continue
			}
			if value.Field(i).CanInterface() {
				if err := b.write(value.Field(i).Interface()); err != nil {
					return err
				}
			} else {
				advance := int(value.Field(i).Type().Size())
				if len(b.bytes) < advance {
					return errWrongMarshalSize
				}
				b.bytes = b.bytes[advance:]
			}
		}
	default:
		return errBadStructMemberType
	}

	return nil
}

func (b *packetBuffer) read(v any) error {
	ptr := reflect.ValueOf(v)
	if ptr.Kind() != reflect.Ptr {
		return errBadReadParameter
	}
	value := reflect.Indirect(ptr)

	if value.Kind() == reflect.Interface {
		value = reflect.ValueOf(value.Interface())
	}
	value = reflect.Indirect(value)

	switch value.Kind() {
	case reflect.Uint8:
		if len(b.bytes) < 1 {
			return errWrongMarshalSize
		}
		value.SetUint(uint64(b.bytes[0]))
		b.bytes = b.bytes[1:]

	case reflect.Uint16:
		if len(b.bytes) < 2 {
			return errWrongMarshalSize
		}
		value.SetUint(uint64(binary.BigEndian.Uint16(b.bytes)))
		b.bytes = b.bytes[2:]

	case reflect.Uint32:
		if len(b.bytes) < 4 {
			return errWrongMarshalSize
		}
		value.SetUint(uint64(binary.BigEndian.Uint32(b.bytes)))
		b.bytes = b.bytes[4:]

	case reflect.Uint64:
		if len(b.bytes) < 8 {
			return errWrongMarshalSize
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
			if encoding == omit {
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
					return errWrongMarshalSize
				}
				b.bytes = b.bytes[advance:]
			}
		}

	default:
		return errBadStructMemberType
	}

	return nil
}

func (b *packetBuffer) split(size int) packetBuffer {
	if size > len(b.bytes) {
		size = len(b.bytes)
	}
	newBuffer := packetBuffer{bytes: b.bytes[:size]}

	b.bytes = b.bytes[size:]

	return newBuffer
}

func wireSize(v any) int {
	value := reflect.ValueOf(v)

	value = reflect.Indirect(value)
	size := int(0)

	switch value.Kind() {
	case reflect.Slice:
		for i := 0; i < value.Len(); i++ {
			if value.Index(i).CanInterface() {
				size += wireSize(value.Index(i).Interface())
			} else {
				size += int(value.Index(i).Type().Size())
			}
		}

	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			encoding := value.Type().Field(i).Tag.Get("encoding")
			if encoding == omit {
				continue
			}
			if value.Field(i).CanInterface() {
				size += wireSize(value.Field(i).Interface())
			} else {
				size += int(value.Field(i).Type().Size())
			}
		}

	default:
		size = int(value.Type().Size())
	}

	return size
}

func stringify(p Packet) string {
	value := reflect.Indirect(reflect.ValueOf(p))

	return formatField(value.Type().String(), "", p, "")
}

func formatField(name string, format string, f any, indent string) string {
	out := indent
	value := reflect.ValueOf(f)

	if !value.IsValid() {
		return fmt.Sprintf("%s%s: <nil>\n", out, name)
	}

	isPacket := reflect.TypeOf(f).Implements(reflect.TypeOf((*Packet)(nil)).Elem())

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
				out += formatField(value.Type().Field(i).Name, format, value.Field(i).Interface(), indent+"\t")
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
					out += formatField(childName, format, value.Index(i).Interface(), indent+"\t")
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

type PictureLossIndication struct {
	SenderSSRC uint32
	MediaSSRC  uint32
}

const (
	pliLength = 2
)

func (p PictureLossIndication) Marshal() ([]byte, error) {

	rawPacket := make([]byte, p.MarshalSize())
	packetBody := rawPacket[headerLength:]

	binary.BigEndian.PutUint32(packetBody, p.SenderSSRC)
	binary.BigEndian.PutUint32(packetBody[4:], p.MediaSSRC)

	h := Header{
		Count:  FormatPLI,
		Type:   TypePayloadSpecificFeedback,
		Length: pliLength,
	}
	hData, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (p *PictureLossIndication) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (headerLength + (ssrcLength * 2)) {
		return errPacketTooShort
	}

	var h Header
	if err := h.Unmarshal(rawPacket); err != nil {
		return err
	}

	if h.Type != TypePayloadSpecificFeedback || h.Count != FormatPLI {
		return errWrongType
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[headerLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[headerLength+ssrcLength:])

	return nil
}

func (p *PictureLossIndication) Header() Header {
	return Header{
		Count:  FormatPLI,
		Type:   TypePayloadSpecificFeedback,
		Length: pliLength,
	}
}

func (p *PictureLossIndication) MarshalSize() int {
	return headerLength + ssrcLength*2
}

func (p *PictureLossIndication) String() string {
	return fmt.Sprintf("PictureLossIndication %x %x", p.SenderSSRC, p.MediaSSRC)
}

func (p *PictureLossIndication) DestinationSSRC() []uint32 {
	return []uint32{p.MediaSSRC}
}

type RapidResynchronizationRequest struct {
	SenderSSRC uint32
	MediaSSRC  uint32
}

type RapidResynchronisationRequest = RapidResynchronizationRequest

const (
	rrrLength       = 2
	rrrHeaderLength = ssrcLength * 2
	rrrMediaOffset  = 4
)

func (p RapidResynchronizationRequest) Marshal() ([]byte, error) {

	rawPacket := make([]byte, p.MarshalSize())
	packetBody := rawPacket[headerLength:]

	binary.BigEndian.PutUint32(packetBody, p.SenderSSRC)
	binary.BigEndian.PutUint32(packetBody[rrrMediaOffset:], p.MediaSSRC)

	hData, err := p.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (p *RapidResynchronizationRequest) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (headerLength + (ssrcLength * 2)) {
		return errPacketTooShort
	}

	var h Header
	if err := h.Unmarshal(rawPacket); err != nil {
		return err
	}

	if h.Type != TypeTransportSpecificFeedback || h.Count != FormatRRR {
		return errWrongType
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[headerLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[headerLength+ssrcLength:])

	return nil
}

func (p *RapidResynchronizationRequest) MarshalSize() int {
	return headerLength + rrrHeaderLength
}

func (p *RapidResynchronizationRequest) Header() Header {
	return Header{
		Count:  FormatRRR,
		Type:   TypeTransportSpecificFeedback,
		Length: rrrLength,
	}
}

func (p *RapidResynchronizationRequest) DestinationSSRC() []uint32 {
	return []uint32{p.MediaSSRC}
}

func (p *RapidResynchronizationRequest) String() string {
	return fmt.Sprintf("RapidResynchronizationRequest %x %x", p.SenderSSRC, p.MediaSSRC)
}

type RawPacket []byte

func (r RawPacket) Marshal() ([]byte, error) {
	return r, nil
}

func (r *RawPacket) Unmarshal(b []byte) error {
	if len(b) < (headerLength) {
		return errPacketTooShort
	}
	*r = b

	var h Header

	return h.Unmarshal(b)
}

func (r RawPacket) Header() Header {
	var h Header
	if err := h.Unmarshal(r); err != nil {
		return Header{}
	}

	return h
}

func (r *RawPacket) DestinationSSRC() []uint32 {
	return []uint32{}
}

func (r RawPacket) String() string {
	out := fmt.Sprintf("RawPacket: %v", ([]byte)(r))

	return out
}

func (r RawPacket) MarshalSize() int {
	return len(r)
}

type ReceiverEstimatedMaximumBitrate struct {
	SenderSSRC uint32
	Bitrate    float32
	SSRCs      []uint32
}

func (p ReceiverEstimatedMaximumBitrate) Marshal() (buf []byte, err error) {

	buf = make([]byte, p.MarshalSize())

	n, err := p.MarshalTo(buf)
	if err != nil {
		return nil, err
	}

	if n != len(buf) {
		return nil, errWrongMarshalSize
	}

	return buf, nil
}

func (p ReceiverEstimatedMaximumBitrate) MarshalSize() int {
	return 20 + 4*len(p.SSRCs)
}

func (p ReceiverEstimatedMaximumBitrate) MarshalTo(buf []byte) (n int, err error) {
	const bitratemax = 0x3FFFFp+63

	size := p.MarshalSize()
	if len(buf) < size {
		return 0, errPacketTooShort
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
		return 0, errInvalidBitrate
	}

	for bitrate >= (1 << 18) {
		bitrate /= 2.0
		exp++
	}

	if exp >= (1 << 6) {
		return 0, errInvalidBitrate
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

func (p *ReceiverEstimatedMaximumBitrate) Unmarshal(buf []byte) (err error) {
	const mantissamax = 0x7FFFFF

	if len(buf) < 20 {
		return errPacketTooShort
	}

	version := buf[0] >> 6
	if version != 2 {
		return fmt.Errorf("%w expected(2) actual(%d)", errBadVersion, version)
	}

	padding := (buf[0] >> 5) & 1
	if padding != 0 {
		return fmt.Errorf("%w expected(0) actual(%d)", errWrongPadding, padding)
	}

	fmtVal := buf[0] & 31
	if fmtVal != 15 {
		return fmt.Errorf("%w expected(15) actual(%d)", errWrongFeedbackType, fmtVal)
	}

	if buf[1] != 206 {
		return fmt.Errorf("%w expected(206) actual(%d)", errWrongPayloadType, buf[1])
	}

	length := binary.BigEndian.Uint16(buf[2:4])
	size := int((length + 1) * 4)

	if size < 20 {
		return errHeaderTooSmall
	}

	if len(buf) < size {
		return errPacketTooShort
	}

	p.SenderSSRC = binary.BigEndian.Uint32(buf[4:8])

	media := binary.BigEndian.Uint32(buf[8:12])
	if media != 0 {
		return errSSRCMustBeZero
	}

	if !bytes.Equal(buf[12:16], []byte{'R', 'E', 'M', 'B'}) {
		return errMissingREMBidentifier
	}

	num := int(buf[16])

	if size != 20+4*num {
		return errSSRCNumAndLengthMismatch
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

func (p *ReceiverEstimatedMaximumBitrate) Header() Header {
	return Header{
		Count:  FormatREMB,
		Type:   TypePayloadSpecificFeedback,
		Length: uint16((p.MarshalSize() / 4) - 1),
	}
}

func (p *ReceiverEstimatedMaximumBitrate) String() string {

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

func (p *ReceiverEstimatedMaximumBitrate) DestinationSSRC() []uint32 {
	return p.SSRCs
}

type ReceiverReport struct {
	SSRC              uint32
	Reports           []ReceptionReport
	ProfileExtensions []byte
}

const (
	ssrcLength     = 4
	rrSSRCOffset   = headerLength
	rrReportOffset = rrSSRCOffset + ssrcLength
)

func (r ReceiverReport) Marshal() ([]byte, error) {

	rawPacket := make([]byte, r.MarshalSize())
	packetBody := rawPacket[headerLength:]

	binary.BigEndian.PutUint32(packetBody, r.SSRC)

	for i, rp := range r.Reports {
		data, err := rp.Marshal()
		if err != nil {
			return nil, err
		}
		offset := ssrcLength + receptionReportLength*i
		copy(packetBody[offset:], data)
	}

	if len(r.Reports) > countMax {
		return nil, errTooManyReports
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

func (r *ReceiverReport) Unmarshal(rawPacket []byte) error {

	if len(rawPacket) < (headerLength + ssrcLength) {
		return errPacketTooShort
	}

	var header Header
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != TypeReceiverReport {
		return errWrongType
	}

	r.SSRC = binary.BigEndian.Uint32(rawPacket[rrSSRCOffset:])

	for i := rrReportOffset; i < len(rawPacket) && len(r.Reports) < int(header.Count); i += receptionReportLength {
		var rr ReceptionReport
		if err := rr.Unmarshal(rawPacket[i:]); err != nil {
			return err
		}
		r.Reports = append(r.Reports, rr)
	}
	r.ProfileExtensions = rawPacket[rrReportOffset+(len(r.Reports)*receptionReportLength):]

	if uint8(len(r.Reports)) != header.Count {
		return errInvalidHeader
	}

	return nil
}

func (r *ReceiverReport) MarshalSize() int {
	repsLength := 0
	for _, rep := range r.Reports {
		repsLength += rep.len()
	}

	return headerLength + ssrcLength + repsLength
}

func (r *ReceiverReport) Header() Header {
	return Header{
		Count:  uint8(len(r.Reports)),
		Type:   TypeReceiverReport,
		Length: uint16((r.MarshalSize()/4)-1) + uint16(getPadding(len(r.ProfileExtensions))),
	}
}

func (r *ReceiverReport) DestinationSSRC() []uint32 {
	out := make([]uint32, len(r.Reports))
	for i, v := range r.Reports {
		out[i] = v.SSRC
	}

	return out
}

func (r ReceiverReport) String() string {
	out := fmt.Sprintf("ReceiverReport from %x\n", r.SSRC)
	out += "\tSSRC    \tLost\tLastSequence\n"
	for _, i := range r.Reports {
		out += fmt.Sprintf("\t%x\t%d/%d\t%d\n", i.SSRC, i.FractionLost, i.TotalLost, i.LastSequenceNumber)
	}
	out += fmt.Sprintf("\tProfile Extension Data: %v\n", r.ProfileExtensions)

	return out
}

type ReceptionReport struct {
	SSRC               uint32
	FractionLost       uint8
	TotalLost          uint32
	LastSequenceNumber uint32
	Jitter             uint32
	LastSenderReport   uint32
	Delay              uint32
}

const (
	receptionReportLength = 24
	fractionLostOffset    = 4
	totalLostOffset       = 5
	lastSeqOffset         = 8
	jitterOffset          = 12
	lastSROffset          = 16
	delayOffset           = 20
)

func (r ReceptionReport) Marshal() ([]byte, error) {

	rawPacket := make([]byte, receptionReportLength)

	binary.BigEndian.PutUint32(rawPacket, r.SSRC)

	rawPacket[fractionLostOffset] = r.FractionLost

	if r.TotalLost >= (1 << 25) {
		return nil, errInvalidTotalLost
	}
	tlBytes := rawPacket[totalLostOffset:]
	tlBytes[0] = byte(r.TotalLost >> 16)
	tlBytes[1] = byte(r.TotalLost >> 8)
	tlBytes[2] = byte(r.TotalLost)

	binary.BigEndian.PutUint32(rawPacket[lastSeqOffset:], r.LastSequenceNumber)
	binary.BigEndian.PutUint32(rawPacket[jitterOffset:], r.Jitter)
	binary.BigEndian.PutUint32(rawPacket[lastSROffset:], r.LastSenderReport)
	binary.BigEndian.PutUint32(rawPacket[delayOffset:], r.Delay)

	return rawPacket, nil
}

func (r *ReceptionReport) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < receptionReportLength {
		return errPacketTooShort
	}

	r.SSRC = binary.BigEndian.Uint32(rawPacket)
	r.FractionLost = rawPacket[fractionLostOffset]

	tlBytes := rawPacket[totalLostOffset:]
	r.TotalLost = uint32(tlBytes[2]) | uint32(tlBytes[1])<<8 | uint32(tlBytes[0])<<16

	r.LastSequenceNumber = binary.BigEndian.Uint32(rawPacket[lastSeqOffset:])
	r.Jitter = binary.BigEndian.Uint32(rawPacket[jitterOffset:])
	r.LastSenderReport = binary.BigEndian.Uint32(rawPacket[lastSROffset:])
	r.Delay = binary.BigEndian.Uint32(rawPacket[delayOffset:])

	return nil
}

func (r *ReceptionReport) len() int {
	return receptionReportLength
}

var (
	errReportBlockLength   = errors.New("feedback report blocks must be at least 8 bytes")
	errIncorrectNumReports = errors.New("feedback report block contains less reports than num_reports")
	errMetricBlockLength   = errors.New("feedback report metric blocks must be exactly 2 bytes")
)

type ECN uint8

const (
	ECNNonECT ECN = iota

	ECNECT1

	ECNECT0

	ECNCE
)

func (e ECN) String() string {
	switch e {
	case ECNNonECT:

		return "Non-ECT (00)"
	case ECNECT0:

		return "ECT(0) (01)"
	case ECNECT1:

		return "ECT(1) (10)"
	case ECNCE:

		return "CE (11)"
	}

	return "invalid ECN value"
}

const (
	reportTimestampLength = 4
	reportBlockOffset     = 8
)

type CCFeedbackReport struct {
	SenderSSRC      uint32
	ReportBlocks    []CCFeedbackReportBlock
	ReportTimestamp uint32
}

func (b CCFeedbackReport) DestinationSSRC() []uint32 {
	ssrcs := make([]uint32, len(b.ReportBlocks))
	for i, block := range b.ReportBlocks {
		ssrcs[i] = block.MediaSSRC
	}

	return ssrcs
}

func (b *CCFeedbackReport) Len() int {
	return b.MarshalSize()
}

func (b *CCFeedbackReport) MarshalSize() int {
	n := 0
	for _, block := range b.ReportBlocks {
		n += block.len()
	}

	return reportBlockOffset + n + reportTimestampLength
}

func (b *CCFeedbackReport) Header() Header {
	return Header{
		Padding: false,
		Count:   FormatCCFB,
		Type:    TypeTransportSpecificFeedback,
		Length:  uint16(b.MarshalSize()/4 - 1),
	}
}

func (b CCFeedbackReport) Marshal() ([]byte, error) {
	header := b.Header()
	headerBuf, err := header.Marshal()
	if err != nil {
		return nil, err
	}
	length := 4 * (header.Length + 1)
	buf := make([]byte, length)
	copy(buf[:headerLength], headerBuf)
	binary.BigEndian.PutUint32(buf[headerLength:], b.SenderSSRC)
	offset := reportBlockOffset
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

func (b CCFeedbackReport) String() string {
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

func (b *CCFeedbackReport) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < headerLength+ssrcLength+reportTimestampLength {
		return errPacketTooShort
	}

	var h Header
	if err := h.Unmarshal(rawPacket); err != nil {
		return err
	}
	if h.Type != TypeTransportSpecificFeedback {
		return errWrongType
	}

	b.SenderSSRC = binary.BigEndian.Uint32(rawPacket[headerLength:])

	reportTimestampOffset := len(rawPacket) - reportTimestampLength
	b.ReportTimestamp = binary.BigEndian.Uint32(rawPacket[reportTimestampOffset:])

	offset := reportBlockOffset
	b.ReportBlocks = []CCFeedbackReportBlock{}
	for offset < reportTimestampOffset {
		var block CCFeedbackReportBlock
		if err := block.unmarshal(rawPacket[offset:]); err != nil {
			return err
		}
		b.ReportBlocks = append(b.ReportBlocks, block)
		offset += block.len()
	}

	return nil
}

const (
	ssrcOffset          = 0
	beginSequenceOffset = 4
	numReportsOffset    = 6
	reportsOffset       = 8

	maxMetricBlocks = 16384
)

type CCFeedbackReportBlock struct {
	MediaSSRC     uint32
	BeginSequence uint16
	MetricBlocks  []CCFeedbackMetricBlock
}

func (b *CCFeedbackReportBlock) len() int {
	n := len(b.MetricBlocks)
	if n%2 != 0 {
		n++
	}

	return reportsOffset + 2*n
}

func (b CCFeedbackReportBlock) String() string {
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

func (b CCFeedbackReportBlock) marshal() ([]byte, error) {
	if len(b.MetricBlocks) > maxMetricBlocks {
		return nil, errTooManyReports
	}

	buf := make([]byte, b.len())
	binary.BigEndian.PutUint32(buf[ssrcOffset:], b.MediaSSRC)
	binary.BigEndian.PutUint16(buf[beginSequenceOffset:], b.BeginSequence)

	length := uint16(len(b.MetricBlocks))

	binary.BigEndian.PutUint16(buf[numReportsOffset:], length)

	for i, block := range b.MetricBlocks {
		b, err := block.marshal()
		if err != nil {
			return nil, err
		}
		copy(buf[reportsOffset+i*2:], b)
	}

	return buf, nil
}

func (b *CCFeedbackReportBlock) unmarshal(rawPacket []byte) error {
	if len(rawPacket) < reportsOffset {
		return errReportBlockLength
	}
	b.MediaSSRC = binary.BigEndian.Uint32(rawPacket[:beginSequenceOffset])
	b.BeginSequence = binary.BigEndian.Uint16(rawPacket[beginSequenceOffset:numReportsOffset])
	numReports := int(binary.BigEndian.Uint16(rawPacket[numReportsOffset:]))
	if numReports == 0 {
		return nil
	}

	if numReports > math.MaxUint16 {
		return errIncorrectNumReports
	}

	if len(rawPacket) < reportsOffset+numReports*2 {
		return errIncorrectNumReports
	}

	b.MetricBlocks = make([]CCFeedbackMetricBlock, numReports)
	for i := int(0); i < numReports; i++ {
		var mb CCFeedbackMetricBlock
		offset := reportsOffset + 2*i
		if err := mb.unmarshal(rawPacket[offset : offset+2]); err != nil {
			return err
		}
		b.MetricBlocks[i] = mb
	}

	return nil
}

const (
	metricBlockLength = 2
)

type CCFeedbackMetricBlock struct {
	Received          bool
	ECN               ECN
	ArrivalTimeOffset uint16
}

func (b CCFeedbackMetricBlock) marshal() ([]byte, error) {
	buf := make([]byte, 2)
	r := uint16(0)
	if b.Received {
		r = 1
	}
	dst, err := setNBitsOfUint16(0, 1, 0, r)
	if err != nil {
		return nil, err
	}
	dst, err = setNBitsOfUint16(dst, 2, 1, uint16(b.ECN))
	if err != nil {
		return nil, err
	}
	dst, err = setNBitsOfUint16(dst, 13, 3, b.ArrivalTimeOffset)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(buf, dst)

	return buf, nil
}

func (b *CCFeedbackMetricBlock) unmarshal(rawPacket []byte) error {
	if len(rawPacket) != metricBlockLength {
		return errMetricBlockLength
	}
	b.Received = rawPacket[0]&0x80 != 0
	if !b.Received {
		b.ECN = ECNNonECT
		b.ArrivalTimeOffset = 0

		return nil
	}
	b.ECN = ECN(rawPacket[0] >> 5 & 0x03)
	b.ArrivalTimeOffset = binary.BigEndian.Uint16(rawPacket) & 0x1FFF

	return nil
}

type SenderReport struct {
	SSRC              uint32
	NTPTime           uint64
	RTPTime           uint32
	PacketCount       uint32
	OctetCount        uint32
	Reports           []ReceptionReport
	ProfileExtensions []byte
}

const (
	srHeaderLength      = 24
	srSSRCOffset        = 0
	srNTPOffset         = srSSRCOffset + ssrcLength
	ntpTimeLength       = 8
	srRTPOffset         = srNTPOffset + ntpTimeLength
	rtpTimeLength       = 4
	srPacketCountOffset = srRTPOffset + rtpTimeLength
	srPacketCountLength = 4
	srOctetCountOffset  = srPacketCountOffset + srPacketCountLength
	srOctetCountLength  = 4
	srReportOffset      = srOctetCountOffset + srOctetCountLength
)

func (r SenderReport) Marshal() ([]byte, error) {

	rawPacket := make([]byte, r.MarshalSize())
	packetBody := rawPacket[headerLength:]

	binary.BigEndian.PutUint32(packetBody[srSSRCOffset:], r.SSRC)
	binary.BigEndian.PutUint64(packetBody[srNTPOffset:], r.NTPTime)
	binary.BigEndian.PutUint32(packetBody[srRTPOffset:], r.RTPTime)
	binary.BigEndian.PutUint32(packetBody[srPacketCountOffset:], r.PacketCount)
	binary.BigEndian.PutUint32(packetBody[srOctetCountOffset:], r.OctetCount)

	offset := srHeaderLength
	for _, rp := range r.Reports {
		data, err := rp.Marshal()
		if err != nil {
			return nil, err
		}
		copy(packetBody[offset:], data)
		offset += receptionReportLength
	}

	if len(r.Reports) > countMax {
		return nil, errTooManyReports
	}

	copy(packetBody[offset:], r.ProfileExtensions)

	hData, err := r.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (r *SenderReport) Unmarshal(rawPacket []byte) error {

	if len(rawPacket) < (headerLength + srHeaderLength) {
		return errPacketTooShort
	}

	var header Header
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != TypeSenderReport {
		return errWrongType
	}

	packetBody := rawPacket[headerLength:]

	r.SSRC = binary.BigEndian.Uint32(packetBody[srSSRCOffset:])
	r.NTPTime = binary.BigEndian.Uint64(packetBody[srNTPOffset:])
	r.RTPTime = binary.BigEndian.Uint32(packetBody[srRTPOffset:])
	r.PacketCount = binary.BigEndian.Uint32(packetBody[srPacketCountOffset:])
	r.OctetCount = binary.BigEndian.Uint32(packetBody[srOctetCountOffset:])

	offset := srReportOffset
	for i := 0; i < int(header.Count); i++ {
		rrEnd := offset + receptionReportLength
		if rrEnd > len(packetBody) {
			return errPacketTooShort
		}
		rrBody := packetBody[offset : offset+receptionReportLength]
		offset = rrEnd

		var rr ReceptionReport
		if err := rr.Unmarshal(rrBody); err != nil {
			return err
		}
		r.Reports = append(r.Reports, rr)
	}

	if offset < len(packetBody) {
		r.ProfileExtensions = packetBody[offset:]
	}

	if uint8(len(r.Reports)) != header.Count {
		return errInvalidHeader
	}

	return nil
}

func (r *SenderReport) DestinationSSRC() []uint32 {
	out := make([]uint32, len(r.Reports)+1)
	for i, v := range r.Reports {
		out[i] = v.SSRC
	}
	out[len(r.Reports)] = r.SSRC

	return out
}

func (r *SenderReport) MarshalSize() int {
	repsLength := 0
	for _, rep := range r.Reports {
		repsLength += rep.len()
	}

	return headerLength + srHeaderLength + repsLength + len(r.ProfileExtensions)
}

func (r *SenderReport) Header() Header {
	return Header{
		Count:  uint8(len(r.Reports)),
		Type:   TypeSenderReport,
		Length: uint16((r.MarshalSize() / 4) - 1),
	}
}

func (r SenderReport) String() string {
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

type SLIEntry struct {
	First   uint16
	Number  uint16
	Picture uint8
}

type SliceLossIndication struct {
	SenderSSRC uint32
	MediaSSRC  uint32
	SLI        []SLIEntry
}

const (
	sliLength = 2
	sliOffset = 8
)

func (p SliceLossIndication) Marshal() ([]byte, error) {
	if len(p.SLI)+sliLength > math.MaxUint8 {
		return nil, errTooManyReports
	}

	rawPacket := make([]byte, sliOffset+(len(p.SLI)*4))
	binary.BigEndian.PutUint32(rawPacket, p.SenderSSRC)
	binary.BigEndian.PutUint32(rawPacket[4:], p.MediaSSRC)
	for i, s := range p.SLI {
		sli := ((uint32(s.First) & 0x1FFF) << 19) |
			((uint32(s.Number) & 0x1FFF) << 6) |
			(uint32(s.Picture) & 0x3F)
		binary.BigEndian.PutUint32(rawPacket[sliOffset+(4*i):], sli)
	}
	hData, err := p.Header().Marshal()
	if err != nil {
		return nil, err
	}

	return append(hData, rawPacket...), nil
}

func (p *SliceLossIndication) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (headerLength + ssrcLength) {
		return errPacketTooShort
	}

	var header Header
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if len(rawPacket) < (headerLength + int(4*header.Length)) {
		return errPacketTooShort
	}

	if header.Type != TypeTransportSpecificFeedback || header.Count != FormatSLI {
		return errWrongType
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[headerLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[headerLength+ssrcLength:])
	for i := headerLength + sliOffset; i < (headerLength + int(header.Length*4)); i += 4 {
		sli := binary.BigEndian.Uint32(rawPacket[i:])
		p.SLI = append(p.SLI, SLIEntry{
			First:   uint16((sli >> 19) & 0x1FFF),
			Number:  uint16((sli >> 6) & 0x1FFF),
			Picture: uint8(sli & 0x3F),
		})
	}

	return nil
}

func (p *SliceLossIndication) MarshalSize() int {
	return headerLength + sliOffset + (len(p.SLI) * 4)
}

func (p *SliceLossIndication) Header() Header {
	return Header{
		Count:  FormatSLI,
		Type:   TypeTransportSpecificFeedback,
		Length: uint16((p.MarshalSize() / 4) - 1),
	}
}

func (p *SliceLossIndication) String() string {
	return fmt.Sprintf("SliceLossIndication %x %x %+v", p.SenderSSRC, p.MediaSSRC, p.SLI)
}

func (p *SliceLossIndication) DestinationSSRC() []uint32 {
	return []uint32{p.MediaSSRC}
}

type SDESType uint8

const (
	SDESEnd SDESType = iota
	SDESCNAME
	SDESName
	SDESEmail
	SDESPhone
	SDESLocation
	SDESTool
	SDESNote
	SDESPrivate
)

func (s SDESType) String() string {
	switch s {
	case SDESEnd:
		return "END"
	case SDESCNAME:
		return "CNAME"
	case SDESName:
		return "NAME"
	case SDESEmail:
		return "EMAIL"
	case SDESPhone:
		return "PHONE"
	case SDESLocation:
		return "LOC"
	case SDESTool:
		return "TOOL"
	case SDESNote:
		return "NOTE"
	case SDESPrivate:
		return "PRIV"
	default:
		return string(s)
	}
}

const (
	sdesSourceLen        = 4
	sdesTypeLen          = 1
	sdesTypeOffset       = 0
	sdesOctetCountLen    = 1
	sdesOctetCountOffset = 1
	sdesMaxOctetCount    = (1 << 8) - 1
	sdesTextOffset       = 2
)

type SourceDescription struct {
	Chunks []SourceDescriptionChunk
}

func (s SourceDescription) Marshal() ([]byte, error) {

	rawPacket := make([]byte, s.MarshalSize())
	packetBody := rawPacket[headerLength:]

	chunkOffset := 0
	for _, c := range s.Chunks {
		data, err := c.Marshal()
		if err != nil {
			return nil, err
		}
		copy(packetBody[chunkOffset:], data)
		chunkOffset += len(data)
	}

	if len(s.Chunks) > countMax {
		return nil, errTooManyChunks
	}

	hData, err := s.Header().Marshal()
	if err != nil {
		return nil, err
	}
	copy(rawPacket, hData)

	return rawPacket, nil
}

func (s *SourceDescription) Unmarshal(rawPacket []byte) error {

	var header Header
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if header.Type != TypeSourceDescription {
		return errWrongType
	}

	for i := headerLength; i < len(rawPacket); {
		var chunk SourceDescriptionChunk
		if err := chunk.Unmarshal(rawPacket[i:]); err != nil {
			return err
		}
		s.Chunks = append(s.Chunks, chunk)

		i += chunk.len()
	}

	if len(s.Chunks) != int(header.Count) {
		return errInvalidHeader
	}

	return nil
}

func (s *SourceDescription) MarshalSize() int {
	chunksLength := 0
	for _, c := range s.Chunks {
		chunksLength += c.len()
	}

	return headerLength + chunksLength
}

func (s *SourceDescription) Header() Header {
	return Header{
		Count:  uint8(len(s.Chunks)),
		Type:   TypeSourceDescription,
		Length: uint16((s.MarshalSize() / 4) - 1),
	}
}

type SourceDescriptionChunk struct {
	Source uint32
	Items  []SourceDescriptionItem
}

func (s SourceDescriptionChunk) Marshal() ([]byte, error) {

	rawPacket := make([]byte, sdesSourceLen)
	binary.BigEndian.PutUint32(rawPacket, s.Source)

	for _, it := range s.Items {
		data, err := it.Marshal()
		if err != nil {
			return nil, err
		}
		rawPacket = append(rawPacket, data...)
	}

	rawPacket = append(rawPacket, uint8(SDESEnd))

	rawPacket = append(rawPacket, make([]byte, getPadding(len(rawPacket)))...)

	return rawPacket, nil
}

func (s *SourceDescriptionChunk) Unmarshal(rawPacket []byte) error {

	if len(rawPacket) < (sdesSourceLen + sdesTypeLen) {
		return errPacketTooShort
	}

	s.Source = binary.BigEndian.Uint32(rawPacket)

	for i := 4; i < len(rawPacket); {
		if pktType := SDESType(rawPacket[i]); pktType == SDESEnd {
			return nil
		}

		var it SourceDescriptionItem
		if err := it.Unmarshal(rawPacket[i:]); err != nil {
			return err
		}
		s.Items = append(s.Items, it)
		i += it.Len()
	}

	return errPacketTooShort
}

func (s SourceDescriptionChunk) len() int {
	chunkLen := sdesSourceLen
	for _, it := range s.Items {
		chunkLen += it.Len()
	}
	chunkLen += sdesTypeLen

	chunkLen += getPadding(chunkLen)

	return chunkLen
}

type SourceDescriptionItem struct {
	Type SDESType
	Text string
}

func (s SourceDescriptionItem) Len() int {

	return sdesTypeLen + sdesOctetCountLen + len([]byte(s.Text))
}

func (s SourceDescriptionItem) Marshal() ([]byte, error) {

	if s.Type == SDESEnd {
		return nil, errSDESMissingType
	}

	rawPacket := make([]byte, sdesTypeLen+sdesOctetCountLen)

	rawPacket[sdesTypeOffset] = uint8(s.Type)

	txtBytes := []byte(s.Text)
	octetCount := len(txtBytes)
	if octetCount > sdesMaxOctetCount {
		return nil, errSDESTextTooLong
	}
	rawPacket[sdesOctetCountOffset] = uint8(octetCount)

	rawPacket = append(rawPacket, txtBytes...)

	return rawPacket, nil
}

func (s *SourceDescriptionItem) Unmarshal(rawPacket []byte) error {

	if len(rawPacket) < (sdesTypeLen + sdesOctetCountLen) {
		return errPacketTooShort
	}

	s.Type = SDESType(rawPacket[sdesTypeOffset])

	octetCount := int(rawPacket[sdesOctetCountOffset])
	if sdesTextOffset+octetCount > len(rawPacket) {
		return errPacketTooShort
	}

	txtBytes := rawPacket[sdesTextOffset : sdesTextOffset+octetCount]
	s.Text = string(txtBytes)

	return nil
}

func (s *SourceDescription) DestinationSSRC() []uint32 {
	out := make([]uint32, len(s.Chunks))
	for i, v := range s.Chunks {
		out[i] = v.Source
	}

	return out
}

func (s *SourceDescription) String() string {
	out := "Source Description:\n"
	for _, c := range s.Chunks {
		out += fmt.Sprintf("\t%x: %s\n", c.Source, c.Items)
	}

	return out
}

const (
	TypeTCCRunLengthChunk    = 0
	TypeTCCStatusVectorChunk = 1

	packetStatusChunkLength = 2
)

const (
	TypeTCCPacketNotReceived = uint16(iota)
	TypeTCCPacketReceivedSmallDelta
	TypeTCCPacketReceivedLargeDelta

	TypeTCCPacketReceivedWithoutDelta
)

const (
	TypeTCCSymbolSizeOneBit = 0
	TypeTCCSymbolSizeTwoBit = 1
)

func numOfBitsOfSymbolSize() map[uint16]uint16 {
	return map[uint16]uint16{
		TypeTCCSymbolSizeOneBit: 1,
		TypeTCCSymbolSizeTwoBit: 2,
	}
}

var (
	errPacketStatusChunkLength = errors.New("packet status chunk must be 2 bytes")
	errDeltaExceedLimit        = errors.New("delta exceed limit")
)

type PacketStatusChunk interface {
	Marshal() ([]byte, error)
	Unmarshal(rawPacket []byte) error
}

type RunLengthChunk struct {
	PacketStatusChunk
	Type               uint16
	PacketStatusSymbol uint16
	RunLength          uint16
}

func (r RunLengthChunk) Marshal() ([]byte, error) {
	chunk := make([]byte, 2)

	dst, err := setNBitsOfUint16(0, 1, 0, 0)
	if err != nil {
		return nil, err
	}

	dst, err = setNBitsOfUint16(dst, 2, 1, r.PacketStatusSymbol)
	if err != nil {
		return nil, err
	}

	dst, err = setNBitsOfUint16(dst, 13, 3, r.RunLength)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(chunk, dst)

	return chunk, nil
}

func (r *RunLengthChunk) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) != packetStatusChunkLength {
		return errPacketStatusChunkLength
	}

	r.Type = TypeTCCRunLengthChunk

	r.PacketStatusSymbol = getNBitsFromByte(rawPacket[0], 1, 2)

	r.RunLength = getNBitsFromByte(rawPacket[0], 3, 5)<<8 + uint16(rawPacket[1])

	return nil
}

type StatusVectorChunk struct {
	PacketStatusChunk
	Type       uint16
	SymbolSize uint16
	SymbolList []uint16
}

func (r StatusVectorChunk) Marshal() ([]byte, error) {
	chunk := make([]byte, 2)

	dst, err := setNBitsOfUint16(0, 1, 0, 1)
	if err != nil {
		return nil, err
	}

	dst, err = setNBitsOfUint16(dst, 1, 1, r.SymbolSize)
	if err != nil {
		return nil, err
	}

	numOfBits := numOfBitsOfSymbolSize()[r.SymbolSize]

	for i, s := range r.SymbolList {
		index := numOfBits*uint16(i) + 2
		dst, err = setNBitsOfUint16(dst, numOfBits, index, s)
		if err != nil {
			return nil, err
		}
	}

	binary.BigEndian.PutUint16(chunk, dst)

	return chunk, nil
}

func (r *StatusVectorChunk) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) != packetStatusChunkLength {
		return errPacketStatusChunkLength
	}

	r.Type = TypeTCCStatusVectorChunk
	r.SymbolSize = getNBitsFromByte(rawPacket[0], 1, 1)

	if r.SymbolSize == TypeTCCSymbolSizeOneBit {
		for i := uint16(0); i < 6; i++ {
			r.SymbolList = append(r.SymbolList, getNBitsFromByte(rawPacket[0], 2+i, 1))
		}
		for i := uint16(0); i < 8; i++ {
			r.SymbolList = append(r.SymbolList, getNBitsFromByte(rawPacket[1], i, 1))
		}

		return nil
	}
	if r.SymbolSize == TypeTCCSymbolSizeTwoBit {
		for i := uint16(0); i < 3; i++ {
			r.SymbolList = append(r.SymbolList, getNBitsFromByte(rawPacket[0], 2+i*2, 2))
		}
		for i := uint16(0); i < 4; i++ {
			r.SymbolList = append(r.SymbolList, getNBitsFromByte(rawPacket[1], i*2, 2))
		}

		return nil
	}

	r.SymbolSize = getNBitsFromByte(rawPacket[0], 2, 6)<<8 + uint16(rawPacket[1])

	return nil
}

const (
	TypeTCCDeltaScaleFactor = 250
)

type RecvDelta struct {
	Type  uint16
	Delta int64
}

func (r RecvDelta) Marshal() ([]byte, error) {
	delta := r.Delta / TypeTCCDeltaScaleFactor

	if r.Type == TypeTCCPacketReceivedSmallDelta && delta >= 0 && delta <= math.MaxUint8 {
		deltaChunk := make([]byte, 1)
		deltaChunk[0] = byte(delta)

		return deltaChunk, nil
	}

	if r.Type == TypeTCCPacketReceivedLargeDelta && delta >= math.MinInt16 && delta <= math.MaxInt16 {
		deltaChunk := make([]byte, 2)
		binary.BigEndian.PutUint16(deltaChunk, uint16(delta))

		return deltaChunk, nil
	}

	return nil, errDeltaExceedLimit
}

func (r *RecvDelta) Unmarshal(rawPacket []byte) error {
	chunkLen := len(rawPacket)

	if chunkLen != 1 && chunkLen != 2 {
		return errDeltaExceedLimit
	}

	if chunkLen == 1 {
		r.Type = TypeTCCPacketReceivedSmallDelta
		r.Delta = TypeTCCDeltaScaleFactor * int64(rawPacket[0])

		return nil
	}

	r.Type = TypeTCCPacketReceivedLargeDelta
	r.Delta = TypeTCCDeltaScaleFactor * int64(int16(binary.BigEndian.Uint16(rawPacket)))

	return nil
}

const (
	baseSequenceNumberOffset = 8
	packetStatusCountOffset  = 10
	referenceTimeOffset      = 12
	fbPktCountOffset         = 15
	packetChunkOffset        = 16
)

type TransportLayerCC struct {
	Header             Header
	SenderSSRC         uint32
	MediaSSRC          uint32
	BaseSequenceNumber uint16
	PacketStatusCount  uint16
	ReferenceTime      uint32
	FbPktCount         uint8
	PacketChunks       []PacketStatusChunk
	RecvDeltas         []*RecvDelta
}

func (t *TransportLayerCC) packetLen() uint16 {

	n := uint16(headerLength + packetChunkOffset + len(t.PacketChunks)*2)
	for _, d := range t.RecvDeltas {
		if d.Type == TypeTCCPacketReceivedSmallDelta {
			n++
		} else {
			n += 2
		}
	}

	return n
}

func (t *TransportLayerCC) Len() uint16 {
	return uint16(t.MarshalSize())
}

func (t *TransportLayerCC) MarshalSize() int {
	n := t.packetLen()

	if n%4 != 0 {
		n = (n/4 + 1) * 4
	}

	return int(n)
}

func (t TransportLayerCC) String() string {
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

func (t TransportLayerCC) Marshal() ([]byte, error) {
	header, err := t.Header.Marshal()
	if err != nil {
		return nil, err
	}

	payload := make([]byte, t.MarshalSize()-headerLength)
	binary.BigEndian.PutUint32(payload, t.SenderSSRC)
	binary.BigEndian.PutUint32(payload[4:], t.MediaSSRC)
	binary.BigEndian.PutUint16(payload[baseSequenceNumberOffset:], t.BaseSequenceNumber)
	binary.BigEndian.PutUint16(payload[packetStatusCountOffset:], t.PacketStatusCount)
	ReferenceTimeAndFbPktCount := appendNBitsToUint32(0, 24, t.ReferenceTime)
	ReferenceTimeAndFbPktCount = appendNBitsToUint32(ReferenceTimeAndFbPktCount, 8, uint32(t.FbPktCount))
	binary.BigEndian.PutUint32(payload[referenceTimeOffset:], ReferenceTimeAndFbPktCount)

	for i, chunk := range t.PacketChunks {
		b, err := chunk.Marshal()
		if err != nil {
			return nil, err
		}
		copy(payload[packetChunkOffset+i*2:], b)
	}

	recvDeltaOffset := packetChunkOffset + len(t.PacketChunks)*2
	var i int
	for _, delta := range t.RecvDeltas {
		b, err := delta.Marshal()
		if err == nil {
			copy(payload[recvDeltaOffset+i:], b)
			i++
			if delta.Type == TypeTCCPacketReceivedLargeDelta {
				i++
			}
		}
	}

	if t.Header.Padding {
		payload[len(payload)-1] = uint8(t.MarshalSize() - int(t.packetLen()))
	}

	return append(header, payload...), nil
}

func (t *TransportLayerCC) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (headerLength + ssrcLength) {
		return errPacketTooShort
	}

	if err := t.Header.Unmarshal(rawPacket); err != nil {
		return err
	}

	totalLength := 4 * (t.Header.Length + 1)

	if totalLength < headerLength+packetChunkOffset {
		return errPacketTooShort
	}

	if len(rawPacket) < int(totalLength) {
		return errPacketTooShort
	}

	if t.Header.Type != TypeTransportSpecificFeedback || t.Header.Count != FormatTCC {
		return errWrongType
	}

	t.SenderSSRC = binary.BigEndian.Uint32(rawPacket[headerLength:])
	t.MediaSSRC = binary.BigEndian.Uint32(rawPacket[headerLength+ssrcLength:])
	t.BaseSequenceNumber = binary.BigEndian.Uint16(rawPacket[headerLength+baseSequenceNumberOffset:])
	t.PacketStatusCount = binary.BigEndian.Uint16(rawPacket[headerLength+packetStatusCountOffset:])
	t.ReferenceTime = get24BitsFromBytes(rawPacket[headerLength+referenceTimeOffset : headerLength+referenceTimeOffset+3])
	t.FbPktCount = rawPacket[headerLength+fbPktCountOffset]

	packetStatusPos := uint16(headerLength + packetChunkOffset)
	var processedPacketNum uint16
	for processedPacketNum < t.PacketStatusCount {
		if packetStatusPos+packetStatusChunkLength >= totalLength {
			return errPacketTooShort
		}
		typ := getNBitsFromByte(rawPacket[packetStatusPos : packetStatusPos+1][0], 0, 1)
		var iPacketStatus PacketStatusChunk
		switch typ {
		case TypeTCCRunLengthChunk:
			packetStatus := &RunLengthChunk{Type: typ}
			iPacketStatus = packetStatus
			err := packetStatus.Unmarshal(rawPacket[packetStatusPos : packetStatusPos+2])
			if err != nil {
				return err
			}

			packetNumberToProcess := localMin(t.PacketStatusCount-processedPacketNum, packetStatus.RunLength)
			if packetStatus.PacketStatusSymbol == TypeTCCPacketReceivedSmallDelta ||
				packetStatus.PacketStatusSymbol == TypeTCCPacketReceivedLargeDelta {
				for j := uint16(0); j < packetNumberToProcess; j++ {
					t.RecvDeltas = append(t.RecvDeltas, &RecvDelta{Type: packetStatus.PacketStatusSymbol})
				}
			}
			processedPacketNum += packetNumberToProcess
		case TypeTCCStatusVectorChunk:
			packetStatus := &StatusVectorChunk{Type: typ}
			iPacketStatus = packetStatus
			err := packetStatus.Unmarshal(rawPacket[packetStatusPos : packetStatusPos+2])
			if err != nil {
				return err
			}
			if packetStatus.SymbolSize == TypeTCCSymbolSizeOneBit {
				for j := 0; j < len(packetStatus.SymbolList); j++ {
					if packetStatus.SymbolList[j] == TypeTCCPacketReceivedSmallDelta {
						t.RecvDeltas = append(t.RecvDeltas, &RecvDelta{Type: TypeTCCPacketReceivedSmallDelta})
					}
				}
			}
			if packetStatus.SymbolSize == TypeTCCSymbolSizeTwoBit {
				for j := 0; j < len(packetStatus.SymbolList); j++ {
					if packetStatus.SymbolList[j] == TypeTCCPacketReceivedSmallDelta ||
						packetStatus.SymbolList[j] == TypeTCCPacketReceivedLargeDelta {
						t.RecvDeltas = append(t.RecvDeltas, &RecvDelta{Type: packetStatus.SymbolList[j]})
					}
				}
			}
			processedPacketNum += uint16(len(packetStatus.SymbolList))
		}
		packetStatusPos += packetStatusChunkLength
		t.PacketChunks = append(t.PacketChunks, iPacketStatus)
	}

	recvDeltasPos := packetStatusPos
	for _, delta := range t.RecvDeltas {
		if delta.Type == TypeTCCPacketReceivedSmallDelta {
			if recvDeltasPos+1 > totalLength {
				return errPacketTooShort
			}
			err := delta.Unmarshal(rawPacket[recvDeltasPos : recvDeltasPos+1])
			if err != nil {
				return err
			}
			recvDeltasPos++
		}
		if delta.Type == TypeTCCPacketReceivedLargeDelta {
			if recvDeltasPos+2 > totalLength {
				return errPacketTooShort
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

func (t TransportLayerCC) DestinationSSRC() []uint32 {
	return []uint32{t.MediaSSRC}
}

func localMin(x, y uint16) uint16 {
	if x < y {
		return x
	}

	return y
}

type PacketBitmap uint16

type NackPair struct {
	PacketID    uint16
	LostPackets PacketBitmap
}

type TransportLayerNack struct {
	SenderSSRC uint32
	MediaSSRC  uint32
	Nacks      []NackPair
}

func NackPairsFromSequenceNumbers(sequenceNumbers []uint16) (pairs []NackPair) {
	if len(sequenceNumbers) == 0 {
		return []NackPair{}
	}

	nackPair := &NackPair{PacketID: sequenceNumbers[0]}
	for i := 1; i < len(sequenceNumbers); i++ {
		m := sequenceNumbers[i]

		if m-nackPair.PacketID > 16 {
			pairs = append(pairs, *nackPair)
			nackPair = &NackPair{PacketID: m}

			continue
		}

		nackPair.LostPackets |= 1 << (m - nackPair.PacketID - 1)
	}
	pairs = append(pairs, *nackPair)

	return
}

func (n *NackPair) Range(f func(seqno uint16) bool) {
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

func (n *NackPair) PacketList() []uint16 {
	out := make([]uint16, 0, 17)
	n.Range(func(seqno uint16) bool {
		out = append(out, seqno)

		return true
	})

	return out
}

const (
	tlnLength  = 2
	nackOffset = 8
)

func (p TransportLayerNack) Marshal() ([]byte, error) {
	if len(p.Nacks)+tlnLength > math.MaxUint8 {
		return nil, errTooManyReports
	}

	rawPacket := make([]byte, nackOffset+(len(p.Nacks)*4))
	binary.BigEndian.PutUint32(rawPacket, p.SenderSSRC)
	binary.BigEndian.PutUint32(rawPacket[4:], p.MediaSSRC)
	for i := 0; i < len(p.Nacks); i++ {
		binary.BigEndian.PutUint16(rawPacket[nackOffset+(4*i):], p.Nacks[i].PacketID)
		binary.BigEndian.PutUint16(rawPacket[nackOffset+(4*i)+2:], uint16(p.Nacks[i].LostPackets))
	}
	h := p.Header()
	hData, err := h.Marshal()
	if err != nil {
		return nil, err
	}

	return append(hData, rawPacket...), nil
}

func (p *TransportLayerNack) Unmarshal(rawPacket []byte) error {
	if len(rawPacket) < (headerLength + ssrcLength) {
		return errPacketTooShort
	}

	var header Header
	if err := header.Unmarshal(rawPacket); err != nil {
		return err
	}

	if len(rawPacket) < (headerLength + int(4*header.Length)) {
		return errPacketTooShort
	}

	if header.Type != TypeTransportSpecificFeedback || header.Count != FormatTLN {
		return errWrongType
	}

	if 4*header.Length <= nackOffset {
		return errBadLength
	}

	p.SenderSSRC = binary.BigEndian.Uint32(rawPacket[headerLength:])
	p.MediaSSRC = binary.BigEndian.Uint32(rawPacket[headerLength+ssrcLength:])
	for i := headerLength + nackOffset; i < (headerLength + int(header.Length*4)); i += 4 {
		p.Nacks = append(p.Nacks, NackPair{
			binary.BigEndian.Uint16(rawPacket[i:]),
			PacketBitmap(binary.BigEndian.Uint16(rawPacket[i+2:])),
		})
	}

	return nil
}

func (p *TransportLayerNack) MarshalSize() int {
	return headerLength + nackOffset + (len(p.Nacks) * 4)
}

func (p *TransportLayerNack) Header() Header {
	return Header{
		Count:  FormatTLN,
		Type:   TypeTransportSpecificFeedback,
		Length: uint16((p.MarshalSize() / 4) - 1),
	}
}

func (p TransportLayerNack) String() string {
	out := fmt.Sprintf("TransportLayerNack from %x\n", p.SenderSSRC)
	out += fmt.Sprintf("\tMedia Ssrc %x\n", p.MediaSSRC)
	out += "\tID\tLostPackets\n"
	for _, i := range p.Nacks {
		out += fmt.Sprintf("\t%d\t%b\n", i.PacketID, i.LostPackets)
	}

	return out
}

func (p *TransportLayerNack) DestinationSSRC() []uint32 {
	return []uint32{p.MediaSSRC}
}

func getPadding(packetLen int) int {
	if packetLen%4 == 0 {
		return 0
	}

	return 4 - (packetLen % 4)
}

func setNBitsOfUint16(src, size, startIndex, val uint16) (uint16, error) {
	if startIndex+size > 16 {
		return 0, errInvalidSizeOrStartIndex
	}

	val &= (1 << size) - 1

	return src | (val << (16 - size - startIndex)), nil
}

func appendNBitsToUint32(src, n, val uint32) uint32 {
	return (src << n) | (val & (0xFFFFFFFF >> (32 - n)))
}

func getNBitsFromByte(b byte, begin, n uint16) uint16 {
	endShift := 8 - (begin + n)
	mask := (0xFF >> begin) & uint8(0xFF<<endShift)

	return uint16(b&mask) >> endShift
}

func get24BitsFromBytes(b []byte) uint32 {
	return uint32(b[0])<<16 + uint32(b[1])<<8 + uint32(b[2])
}
