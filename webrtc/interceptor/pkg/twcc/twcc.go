// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package twcc

import (
	"errors"
	"github.com/amarnathcjd/gortc/webrtc"
	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/logging"
	"github.com/amarnathcjd/gortc/webrtc/rtcp"
	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"math"
	"math/rand"
	"sync"
	"time"
)

const (
	minCapacity        = 128
	maxNumberOfPackets = 1 << 15
)

type packetArrivalTimeMap struct {
	arrivalTimes                           []int64
	beginSequenceNumber, endSequenceNumber int64
}

func (m *packetArrivalTimeMap) AddPacket(sequenceNumber int64, arrivalTime int64) {
	if m.arrivalTimes == nil {

		m.reallocate(minCapacity)
		m.beginSequenceNumber = sequenceNumber
		m.endSequenceNumber = sequenceNumber + 1
		m.arrivalTimes[m.index(sequenceNumber)] = arrivalTime

		return
	}

	if sequenceNumber >= m.beginSequenceNumber && sequenceNumber < m.endSequenceNumber {

		m.arrivalTimes[m.index(sequenceNumber)] = arrivalTime

		return
	}

	if sequenceNumber < m.beginSequenceNumber {

		newSize := int(m.endSequenceNumber - sequenceNumber)
		if newSize > maxNumberOfPackets {

			return
		}
		m.adjustToSize(newSize)
		m.arrivalTimes[m.index(sequenceNumber)] = arrivalTime
		m.setNotReceived(sequenceNumber+1, m.beginSequenceNumber)
		m.beginSequenceNumber = sequenceNumber

		return
	}

	newEndSequenceNumber := sequenceNumber + 1

	if newEndSequenceNumber >= m.endSequenceNumber+maxNumberOfPackets {

		m.beginSequenceNumber = sequenceNumber
		m.endSequenceNumber = newEndSequenceNumber
		m.arrivalTimes[m.index(sequenceNumber)] = arrivalTime

		return
	}

	if m.beginSequenceNumber < newEndSequenceNumber-maxNumberOfPackets {

		m.beginSequenceNumber = newEndSequenceNumber - maxNumberOfPackets
	}

	m.adjustToSize(int(newEndSequenceNumber - m.beginSequenceNumber))

	m.setNotReceived(m.endSequenceNumber, sequenceNumber)
	m.endSequenceNumber = newEndSequenceNumber
	m.arrivalTimes[m.index(sequenceNumber)] = arrivalTime
}

func (m *packetArrivalTimeMap) setNotReceived(startInclusive, endExclusive int64) {
	for sn := startInclusive; sn < endExclusive; sn++ {
		m.arrivalTimes[m.index(sn)] = -1
	}
}

func (m *packetArrivalTimeMap) BeginSequenceNumber() int64 {
	return m.beginSequenceNumber
}

func (m *packetArrivalTimeMap) EndSequenceNumber() int64 {
	return m.endSequenceNumber
}

func (m *packetArrivalTimeMap) FindNextAtOrAfter(sequenceNumber int64) (
	int64, int64, bool,
) {
	for seq := m.Clamp(sequenceNumber); seq < m.endSequenceNumber; seq++ {
		if arrivalTime := m.get(seq); arrivalTime >= 0 {
			return seq, arrivalTime, true
		}
	}

	return -1, -1, false
}

func (m *packetArrivalTimeMap) EraseTo(sequenceNumber int64) {
	if sequenceNumber < m.beginSequenceNumber {
		return
	}
	if sequenceNumber >= m.endSequenceNumber {

		m.beginSequenceNumber = m.endSequenceNumber

		return
	}

	m.beginSequenceNumber = sequenceNumber
	m.adjustToSize(int(m.endSequenceNumber - m.beginSequenceNumber))
}

func (m *packetArrivalTimeMap) RemoveOldPackets(sequenceNumber int64, arrivalTimeLimit int64) {
	checkTo := min(sequenceNumber, m.endSequenceNumber)
	for m.beginSequenceNumber < checkTo && m.get(m.beginSequenceNumber) <= arrivalTimeLimit {
		m.beginSequenceNumber++
	}
	m.adjustToSize(int(m.endSequenceNumber - m.beginSequenceNumber))
}

func (m *packetArrivalTimeMap) HasReceived(sequenceNumber int64) bool {
	return m.get(sequenceNumber) >= 0
}

func (m *packetArrivalTimeMap) Clamp(sequenceNumber int64) int64 {
	if sequenceNumber < m.beginSequenceNumber {
		return m.beginSequenceNumber
	}
	if m.endSequenceNumber < sequenceNumber {
		return m.endSequenceNumber
	}

	return sequenceNumber
}

func (m *packetArrivalTimeMap) get(sequenceNumber int64) int64 {
	if sequenceNumber < m.beginSequenceNumber || sequenceNumber >= m.endSequenceNumber {
		return -1
	}

	return m.arrivalTimes[m.index(sequenceNumber)]
}

func (m *packetArrivalTimeMap) index(sequenceNumber int64) int {

	return int(sequenceNumber & int64(m.capacity()-1))
}

func (m *packetArrivalTimeMap) adjustToSize(newSize int) {
	if newSize > m.capacity() {
		newCapacity := m.capacity()
		for newCapacity < newSize {
			newCapacity *= 2
		}
		m.reallocate(newCapacity)
	}
	if m.capacity() > max(minCapacity, newSize*4) {
		newCapacity := m.capacity()
		for newCapacity >= 2*max(newSize, minCapacity) {
			newCapacity /= 2
		}
		m.reallocate(newCapacity)
	}
}

func (m *packetArrivalTimeMap) capacity() int {
	return len(m.arrivalTimes)
}

func (m *packetArrivalTimeMap) reallocate(newCapacity int) {
	newBuffer := make([]int64, newCapacity)
	for sn := m.beginSequenceNumber; sn < m.endSequenceNumber; sn++ {
		newBuffer[int(sn&(int64(newCapacity-1)))] = m.get(sn)
	}
	m.arrivalTimes = newBuffer
}

type SenderInterceptorFactory struct {
	opts []Option
}

const transportCCURI = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"

var errClosed = errors.New("interceptor is closed")

func (s *SenderInterceptorFactory) NewInterceptor(_ string) (interceptor.Interceptor, error) {
	senderInterceptor := &SenderInterceptor{
		packetChan: make(chan packet),
		close:      make(chan struct{}),
		interval:   100 * time.Millisecond,
		startTime:  time.Now(),
	}

	for _, opt := range s.opts {
		err := opt(senderInterceptor)
		if err != nil {
			return nil, err
		}
	}

	if senderInterceptor.loggerFactory == nil {
		senderInterceptor.loggerFactory = logging.NewDefaultLoggerFactory()
	}
	if senderInterceptor.log == nil {
		senderInterceptor.log = senderInterceptor.loggerFactory.NewLogger("twcc_sender_interceptor")
	}

	return senderInterceptor, nil
}

func NewSenderInterceptor(opts ...Option) (*SenderInterceptorFactory, error) {
	return &SenderInterceptorFactory{opts: opts}, nil
}

type SenderInterceptor struct {
	interceptor.NoOp
	log           logging.LeveledLogger
	loggerFactory logging.LoggerFactory
	m             sync.Mutex
	wg            sync.WaitGroup
	close         chan struct{}
	interval      time.Duration
	startTime     time.Time
	recorder      *Recorder
	packetChan    chan packet
}

type Option func(*SenderInterceptor) error

func WithLoggerFactory(loggerFactory logging.LoggerFactory) Option {
	return func(s *SenderInterceptor) error {
		s.loggerFactory = loggerFactory

		return nil
	}
}

func (s *SenderInterceptor) BindRTCPWriter(writer interceptor.RTCPWriter) interceptor.RTCPWriter {
	s.m.Lock()
	defer s.m.Unlock()

	s.recorder = NewRecorder(rand.Uint32())

	if s.isClosed() {
		return writer
	}

	s.wg.Add(1)

	go s.loop(writer)

	return writer
}

type packet struct {
	hdr            *rtp.Header
	sequenceNumber uint16
	arrivalTime    int64
	ssrc           uint32
}

func (s *SenderInterceptor) BindRemoteStream(
	info *interceptor.StreamInfo, reader interceptor.RTPReader,
) interceptor.RTPReader {
	var hdrExtID uint8
	for _, e := range info.RTPHeaderExtensions {
		if e.URI == transportCCURI {
			hdrExtID = uint8(e.ID)

			break
		}
	}
	if hdrExtID == 0 {
		return reader
	}

	return interceptor.RTPReaderFunc(
		func(buf []byte, attributes interceptor.Attributes) (int, interceptor.Attributes, error) {
			i, attr, err := reader.Read(buf, attributes)
			if err != nil {
				return 0, nil, err
			}

			if attr == nil {
				attr = make(interceptor.Attributes)
			}
			header, err := attr.GetRTPHeader(buf[:i])
			if err != nil {
				return 0, nil, err
			}
			var tccExt rtp.TransportCCExtension
			if ext := header.GetExtension(hdrExtID); ext != nil {
				err = tccExt.Unmarshal(ext)
				if err != nil {
					return 0, nil, err
				}

				p := packet{
					hdr:            header,
					sequenceNumber: tccExt.TransportSequence,
					arrivalTime:    time.Since(s.startTime).Microseconds(),
					ssrc:           info.SSRC,
				}
				select {
				case <-s.close:
					return 0, nil, errClosed
				case s.packetChan <- p:
				}
			}

			return i, attr, nil
		},
	)
}

func (s *SenderInterceptor) Close() error {
	defer s.wg.Wait()
	s.m.Lock()
	defer s.m.Unlock()

	if !s.isClosed() {
		close(s.close)
	}

	return nil
}

func (s *SenderInterceptor) isClosed() bool {
	select {
	case <-s.close:
		return true
	default:
		return false
	}
}

func (s *SenderInterceptor) loop(writer interceptor.RTCPWriter) {
	defer s.wg.Done()

	select {
	case <-s.close:
		return
	case p := <-s.packetChan:
		s.recorder.Record(p.ssrc, p.sequenceNumber, p.arrivalTime)
	}

	ticker := time.NewTicker(s.interval)
	for {
		select {
		case <-s.close:
			ticker.Stop()

			return
		case p := <-s.packetChan:
			s.recorder.Record(p.ssrc, p.sequenceNumber, p.arrivalTime)

		case <-ticker.C:

			pkts := s.recorder.BuildFeedbackPacket()
			if len(pkts) == 0 {
				continue
			}
			if _, err := writer.Write(pkts, nil); err != nil {
				s.log.Error(err.Error())
			}
		}
	}
}

const (
	packetWindowMicroseconds  = 500_000
	maxMissingSequenceNumbers = 0x7FFE
)

type Recorder struct {
	arrivalTimeMap      packetArrivalTimeMap
	sequenceUnwrapper   webrtc.SeqUnwrapper
	startSequenceNumber *int64
	senderSSRC          uint32
	mediaSSRC           uint32
	fbPktCnt            uint8
	packetsHeld         int
}

func NewRecorder(senderSSRC uint32) *Recorder {
	return &Recorder{
		senderSSRC: senderSSRC,
	}
}

func (r *Recorder) Record(mediaSSRC uint32, sequenceNumber uint16, arrivalTime int64) {
	r.mediaSSRC = mediaSSRC

	unwrappedSN := r.sequenceUnwrapper.Unwrap(sequenceNumber)
	r.maybeCullOldPackets(unwrappedSN, arrivalTime)
	if r.startSequenceNumber == nil || unwrappedSN < *r.startSequenceNumber {
		r.startSequenceNumber = &unwrappedSN
	}

	if r.arrivalTimeMap.HasReceived(unwrappedSN) {
		return
	}

	r.arrivalTimeMap.AddPacket(unwrappedSN, arrivalTime)
	r.packetsHeld++

	if *r.startSequenceNumber < r.arrivalTimeMap.BeginSequenceNumber() {
		sn := r.arrivalTimeMap.BeginSequenceNumber()
		r.startSequenceNumber = &sn
	}
}

func (r *Recorder) maybeCullOldPackets(sequenceNumber int64, arrivalTime int64) {
	if r.startSequenceNumber != nil && *r.startSequenceNumber >= r.arrivalTimeMap.EndSequenceNumber() &&
		arrivalTime >= packetWindowMicroseconds {
		r.arrivalTimeMap.RemoveOldPackets(sequenceNumber, arrivalTime-packetWindowMicroseconds)
	}
}

func (r *Recorder) PacketsHeld() int {
	return r.packetsHeld
}

func (r *Recorder) BuildFeedbackPacket() []rtcp.Packet {
	if r.startSequenceNumber == nil {
		return nil
	}

	endSN := r.arrivalTimeMap.EndSequenceNumber()
	var feedbacks []rtcp.Packet
	for *r.startSequenceNumber < endSN {
		feedback := r.maybeBuildFeedbackPacket(*r.startSequenceNumber, endSN)
		if feedback == nil {
			break
		}
		feedbacks = append(feedbacks, feedback.getRTCP())

	}
	r.packetsHeld = 0

	return feedbacks
}

func (r *Recorder) maybeBuildFeedbackPacket(beginSeqNumInclusive, endSeqNumExclusive int64) *feedback {

	startSNInclusive, endSNExclusive := r.arrivalTimeMap.Clamp(beginSeqNumInclusive), r.arrivalTimeMap.Clamp(endSeqNumExclusive)

	var fb *feedback

	nextSequenceNumber := beginSeqNumInclusive

	for seq := startSNInclusive; seq < endSNExclusive; seq++ {
		foundSeq, arrivalTime, ok := r.arrivalTimeMap.FindNextAtOrAfter(seq)
		seq = foundSeq
		if !ok || seq >= endSNExclusive {
			break
		}

		if fb == nil {
			fb = newFeedback(r.senderSSRC, r.mediaSSRC, r.fbPktCnt)
			r.fbPktCnt++

			baseSequenceNumber := max(beginSeqNumInclusive, seq-maxMissingSequenceNumbers)

			fb.setBase(uint16(baseSequenceNumber), arrivalTime)

			if !fb.addReceived(uint16(seq), arrivalTime) {

				r.startSequenceNumber = &seq

				return nil
			}
		} else if !fb.addReceived(uint16(seq), arrivalTime) {

			break
		}

		nextSequenceNumber = seq + 1
	}

	r.startSequenceNumber = &nextSequenceNumber

	return fb
}

type feedback struct {
	rtcp                *rtcp.TransportLayerCC
	baseSequenceNumber  uint16
	refTimestamp64MS    int64
	lastTimestampUS     int64
	nextSequenceNumber  uint16
	sequenceNumberCount uint16
	len                 int
	lastChunk           chunk
	chunks              []rtcp.PacketStatusChunk
	deltas              []*rtcp.RecvDelta
}

func newFeedback(senderSSRC, mediaSSRC uint32, count uint8) *feedback {
	return &feedback{
		rtcp: &rtcp.TransportLayerCC{
			SenderSSRC: senderSSRC,
			MediaSSRC:  mediaSSRC,
			FbPktCount: count,
		},
	}
}

func (f *feedback) setBase(sequenceNumber uint16, timeUS int64) {
	f.baseSequenceNumber = sequenceNumber
	f.nextSequenceNumber = f.baseSequenceNumber
	f.refTimestamp64MS = timeUS / 64e3
	f.lastTimestampUS = f.refTimestamp64MS * 64e3
}

func (f *feedback) getRTCP() *rtcp.TransportLayerCC {
	f.rtcp.PacketStatusCount = f.sequenceNumberCount
	f.rtcp.ReferenceTime = uint32(f.refTimestamp64MS)
	f.rtcp.BaseSequenceNumber = f.baseSequenceNumber
	for len(f.lastChunk.deltas) > 0 {
		f.chunks = append(f.chunks, f.lastChunk.encode())
	}
	f.rtcp.PacketChunks = append(f.rtcp.PacketChunks, f.chunks...)
	f.rtcp.RecvDeltas = f.deltas

	padLen := 20 + len(f.rtcp.PacketChunks)*2 + f.len
	padding := padLen%4 != 0
	for padLen%4 != 0 {
		padLen++
	}
	f.rtcp.Header = rtcp.Header{
		Count:   rtcp.FormatTCC,
		Type:    rtcp.TypeTransportSpecificFeedback,
		Padding: padding,
		Length:  uint16((padLen / 4) - 1),
	}

	return f.rtcp
}

func (f *feedback) addReceived(sequenceNumber uint16, timestampUS int64) bool {
	deltaUS := timestampUS - f.lastTimestampUS
	var delta250US int64
	if deltaUS >= 0 {
		delta250US = (deltaUS + rtcp.TypeTCCDeltaScaleFactor/2) / rtcp.TypeTCCDeltaScaleFactor
	} else {
		delta250US = (deltaUS - rtcp.TypeTCCDeltaScaleFactor/2) / rtcp.TypeTCCDeltaScaleFactor
	}

	if delta250US < math.MinInt16 || delta250US > math.MaxInt16 {
		return false
	}
	deltaUSRounded := delta250US * rtcp.TypeTCCDeltaScaleFactor

	for ; f.nextSequenceNumber != sequenceNumber; f.nextSequenceNumber++ {
		if !f.lastChunk.canAdd(rtcp.TypeTCCPacketNotReceived) {
			f.chunks = append(f.chunks, f.lastChunk.encode())
		}
		f.lastChunk.add(rtcp.TypeTCCPacketNotReceived)
		f.sequenceNumberCount++
	}

	var recvDelta uint16
	switch {
	case delta250US >= 0 && delta250US <= 0xff:
		f.len++
		recvDelta = rtcp.TypeTCCPacketReceivedSmallDelta
	default:
		f.len += 2
		recvDelta = rtcp.TypeTCCPacketReceivedLargeDelta
	}

	if !f.lastChunk.canAdd(recvDelta) {
		f.chunks = append(f.chunks, f.lastChunk.encode())
	}
	f.lastChunk.add(recvDelta)
	f.deltas = append(f.deltas, &rtcp.RecvDelta{
		Type:  recvDelta,
		Delta: deltaUSRounded,
	})
	f.lastTimestampUS += deltaUSRounded
	f.sequenceNumberCount++
	f.nextSequenceNumber++

	return true
}

const (
	maxRunLengthCap = 0x1fff
	maxOneBitCap    = 14
	maxTwoBitCap    = 7
)

type chunk struct {
	hasLargeDelta     bool
	hasDifferentTypes bool
	deltas            []uint16
}

func (c *chunk) canAdd(delta uint16) bool {
	if len(c.deltas) < maxTwoBitCap {
		return true
	}
	if len(c.deltas) < maxOneBitCap && !c.hasLargeDelta && delta != rtcp.TypeTCCPacketReceivedLargeDelta {
		return true
	}
	if len(c.deltas) < maxRunLengthCap && !c.hasDifferentTypes && delta == c.deltas[0] {
		return true
	}

	return false
}

func (c *chunk) add(delta uint16) {
	c.deltas = append(c.deltas, delta)
	c.hasLargeDelta = c.hasLargeDelta || delta == rtcp.TypeTCCPacketReceivedLargeDelta
	c.hasDifferentTypes = c.hasDifferentTypes || delta != c.deltas[0]
}

func (c *chunk) encode() rtcp.PacketStatusChunk {
	if !c.hasDifferentTypes {
		defer c.reset()

		return &rtcp.RunLengthChunk{
			PacketStatusSymbol: c.deltas[0],
			RunLength:          uint16(len(c.deltas)),
		}
	}
	if len(c.deltas) == maxOneBitCap {
		defer c.reset()

		return &rtcp.StatusVectorChunk{
			SymbolSize: rtcp.TypeTCCSymbolSizeOneBit,
			SymbolList: c.deltas,
		}
	}

	minCap := min(maxTwoBitCap, len(c.deltas))
	svc := &rtcp.StatusVectorChunk{
		SymbolSize: rtcp.TypeTCCSymbolSizeTwoBit,
		SymbolList: c.deltas[:minCap],
	}
	c.deltas = c.deltas[minCap:]
	c.hasDifferentTypes = false
	c.hasLargeDelta = false

	if len(c.deltas) > 0 {
		tmp := c.deltas[0]
		for _, d := range c.deltas {
			if tmp != d {
				c.hasDifferentTypes = true
			}
			if d == rtcp.TypeTCCPacketReceivedLargeDelta {
				c.hasLargeDelta = true
			}
		}
	}

	return svc
}

func (c *chunk) reset() {
	c.deltas = []uint16{}
	c.hasLargeDelta = false
	c.hasDifferentTypes = false
}
