package report

import (
	"github.com/amarnathcjd/gortc/webrtc"
	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/logging"
	"github.com/amarnathcjd/gortc/webrtc/rtcp"
	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"math/rand"
	"sync"
	"time"
)

type ReceiverInterceptorFactory struct {
	opts []ReceiverOption
}

func (r *ReceiverInterceptorFactory) NewInterceptor(_ string) (interceptor.Interceptor, error) {
	receiverInterceptor := &ReceiverInterceptor{
		interval: 1 * time.Second,
		now:      time.Now,
		close:    make(chan struct{}),
	}

	for _, opt := range r.opts {
		if err := opt(receiverInterceptor); err != nil {
			return nil, err
		}
	}

	if receiverInterceptor.loggerFactory == nil {
		receiverInterceptor.loggerFactory = logging.NewDefaultLoggerFactory()
	}
	if receiverInterceptor.log == nil {
		receiverInterceptor.log = receiverInterceptor.loggerFactory.NewLogger("receiver_interceptor")
	}

	return receiverInterceptor, nil
}

func NewReceiverInterceptor(opts ...ReceiverOption) (*ReceiverInterceptorFactory, error) {
	return &ReceiverInterceptorFactory{opts}, nil
}

type ReceiverInterceptor struct {
	interceptor.NoOp
	interval      time.Duration
	now           func() time.Time
	streams       sync.Map
	log           logging.LeveledLogger
	loggerFactory logging.LoggerFactory
	m             sync.Mutex
	wg            sync.WaitGroup
	close         chan struct{}
}

func (r *ReceiverInterceptor) isClosed() bool {
	select {
	case <-r.close:
		return true
	default:
		return false
	}
}

func (r *ReceiverInterceptor) Close() error {
	defer r.wg.Wait()
	r.m.Lock()
	defer r.m.Unlock()

	if !r.isClosed() {
		close(r.close)
	}

	return nil
}

func (r *ReceiverInterceptor) BindRTCPWriter(writer interceptor.RTCPWriter) interceptor.RTCPWriter {
	r.m.Lock()
	defer r.m.Unlock()

	if r.isClosed() {
		return writer
	}

	r.wg.Add(1)

	go r.loop(writer)

	return writer
}

func (r *ReceiverInterceptor) loop(rtcpWriter interceptor.RTCPWriter) {
	defer r.wg.Done()

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := r.now()
			r.streams.Range(func(_, value any) bool {
				if stream, ok := value.(*receiverStream); !ok {
					r.log.Warnf("failed to cast ReceiverInterceptor stream")
				} else if _, err := rtcpWriter.Write(
					[]rtcp.Packet{stream.generateReport(now)}, interceptor.Attributes{},
				); err != nil {
					r.log.Warnf("failed sending: %+v", err)
				}

				return true
			})

		case <-r.close:
			return
		}
	}
}

func (r *ReceiverInterceptor) BindRemoteStream(
	info *interceptor.StreamInfo, reader interceptor.RTPReader,
) interceptor.RTPReader {
	stream := newReceiverStream(info.SSRC, info.ClockRate)
	r.streams.Store(info.SSRC, stream)

	return interceptor.RTPReaderFunc(func(b []byte, a interceptor.Attributes) (int, interceptor.Attributes, error) {
		i, attr, err := reader.Read(b, a)
		if err != nil {
			return 0, nil, err
		}

		if attr == nil {
			attr = make(interceptor.Attributes)
		}
		header, err := attr.GetRTPHeader(b[:i])
		if err != nil {
			return 0, nil, err
		}

		stream.processRTP(r.now(), header)

		return i, attr, nil
	})
}

func (r *ReceiverInterceptor) UnbindRemoteStream(info *interceptor.StreamInfo) {
	r.streams.Delete(info.SSRC)
}

func (r *ReceiverInterceptor) BindRTCPReader(reader interceptor.RTCPReader) interceptor.RTCPReader {
	return interceptor.RTCPReaderFunc(func(b []byte, a interceptor.Attributes) (int, interceptor.Attributes, error) {
		i, attr, err := reader.Read(b, a)
		if err != nil {
			return 0, nil, err
		}

		if attr == nil {
			attr = make(interceptor.Attributes)
		}
		pkts, err := attr.GetRTCPPackets(b[:i])
		if err != nil {
			return 0, nil, err
		}

		for _, pkt := range pkts {
			if sr, ok := (pkt).(*rtcp.SenderReport); ok {
				value, ok := r.streams.Load(sr.SSRC)
				if !ok {
					continue
				}

				if stream, ok := value.(*receiverStream); !ok {
					r.log.Warnf("failed to cast ReceiverInterceptor stream")
				} else {
					stream.processSenderReport(r.now(), sr)
				}
			}
		}

		return i, attr, nil
	})
}

type ReceiverOption func(r *ReceiverInterceptor) error

func WithReceiverLoggerFactory(loggerFactory logging.LoggerFactory) ReceiverOption {
	return func(r *ReceiverInterceptor) error {
		r.loggerFactory = loggerFactory

		return nil
	}
}

const (
	packetsPerHistoryEntry = 64
)

type receiverStream struct {
	ssrc                 uint32
	receiverSSRC         uint32
	clockRate            float64
	m                    sync.Mutex
	size                 uint16
	packets              []uint64
	started              bool
	seqnumCycles         uint16
	lastSeqnum           uint16
	lastReportSeqnum     uint16
	lastRTPTimeRTP       uint32
	lastRTPTimeTime      time.Time
	jitter               float64
	lastSenderReport     uint32
	lastSenderReportTime time.Time
	totalLost            uint32
}

func newReceiverStream(ssrc uint32, clockRate uint32) *receiverStream {
	receiverSSRC := rand.Uint32()

	return &receiverStream{
		ssrc:         ssrc,
		receiverSSRC: receiverSSRC,
		clockRate:    float64(clockRate),
		size:         128,
		packets:      make([]uint64, 128),
	}
}

func (stream *receiverStream) processRTP(now time.Time, pktHeader *rtp.Header) {
	stream.m.Lock()
	defer stream.m.Unlock()

	if !stream.started {
		stream.started = true
		stream.setReceived(pktHeader.SequenceNumber)
		stream.lastSeqnum = pktHeader.SequenceNumber
		stream.lastReportSeqnum = pktHeader.SequenceNumber - 1
		stream.lastRTPTimeRTP = pktHeader.Timestamp
		stream.lastRTPTimeTime = now
	} else {
		stream.setReceived(pktHeader.SequenceNumber)

		diff := pktHeader.SequenceNumber - stream.lastSeqnum
		if diff > 0 && diff < (1<<15) {

			if pktHeader.SequenceNumber < stream.lastSeqnum {
				stream.seqnumCycles++
			}

			for i := stream.lastSeqnum + 1; i != pktHeader.SequenceNumber; i++ {
				stream.delReceived(i)
			}

			stream.lastSeqnum = pktHeader.SequenceNumber
		}

		D := now.Sub(stream.lastRTPTimeTime).Seconds()*stream.clockRate -
			(float64(pktHeader.Timestamp) - float64(stream.lastRTPTimeRTP))
		if D < 0 {
			D = -D
		}
		stream.jitter += (D - stream.jitter) / 16
		stream.lastRTPTimeRTP = pktHeader.Timestamp
		stream.lastRTPTimeTime = now
	}
}

func (stream *receiverStream) setReceived(seq uint16) {
	pos := seq % (stream.size * packetsPerHistoryEntry)
	stream.packets[pos/packetsPerHistoryEntry] |= 1 << (pos % packetsPerHistoryEntry)
}

func (stream *receiverStream) delReceived(seq uint16) {
	pos := seq % (stream.size * packetsPerHistoryEntry)
	stream.packets[pos/packetsPerHistoryEntry] &^= 1 << (pos % packetsPerHistoryEntry)
}

func (stream *receiverStream) getReceived(seq uint16) bool {
	pos := seq % (stream.size * packetsPerHistoryEntry)

	return (stream.packets[pos/packetsPerHistoryEntry] & (1 << (pos % packetsPerHistoryEntry))) != 0
}

func (stream *receiverStream) processSenderReport(now time.Time, sr *rtcp.SenderReport) {
	stream.m.Lock()
	defer stream.m.Unlock()

	stream.lastSenderReport = uint32(sr.NTPTime >> 16)
	stream.lastSenderReportTime = now
}

func (stream *receiverStream) generateReport(now time.Time) *rtcp.ReceiverReport {
	stream.m.Lock()
	defer stream.m.Unlock()

	totalSinceReport := stream.lastSeqnum - stream.lastReportSeqnum
	totalLostSinceReport := func() uint32 {
		if stream.lastSeqnum == stream.lastReportSeqnum {
			return 0
		}

		ret := uint32(0)
		for i := stream.lastReportSeqnum + 1; i != stream.lastSeqnum; i++ {
			if !stream.getReceived(i) {
				ret++
			}
		}

		return ret
	}()
	stream.totalLost += totalLostSinceReport

	if totalLostSinceReport > 0xFFFFFF {
		totalLostSinceReport = 0xFFFFFF
	}
	if stream.totalLost > 0xFFFFFF {
		stream.totalLost = 0xFFFFFF
	}

	receiverReport := &rtcp.ReceiverReport{
		SSRC: stream.receiverSSRC,
		Reports: []rtcp.ReceptionReport{
			{
				SSRC:               stream.ssrc,
				LastSequenceNumber: uint32(stream.seqnumCycles)<<16 | uint32(stream.lastSeqnum),
				LastSenderReport:   stream.lastSenderReport,
				FractionLost:       uint8(float64(totalLostSinceReport*256) / float64(totalSinceReport)),
				TotalLost:          stream.totalLost,
				Delay: func() uint32 {
					if stream.lastSenderReportTime.IsZero() {
						return 0
					}

					return uint32(now.Sub(stream.lastSenderReportTime).Seconds() * 65536)
				}(),
				Jitter: uint32(stream.jitter),
			},
		},
	}

	stream.lastReportSeqnum = stream.lastSeqnum

	return receiverReport
}

type TickerFactory func(d time.Duration) Ticker

type SenderInterceptorFactory struct {
	opts []SenderOption
}

func (s *SenderInterceptorFactory) NewInterceptor(_ string) (interceptor.Interceptor, error) {
	senderInterceptor := &SenderInterceptor{
		interval: 1 * time.Second,
		now:      time.Now,
		newTicker: func(d time.Duration) Ticker {
			return &timeTicker{time.NewTicker(d)}
		},
		close: make(chan struct{}),
	}

	for _, opt := range s.opts {
		if err := opt(senderInterceptor); err != nil {
			return nil, err
		}
	}

	if senderInterceptor.loggerFactory == nil {
		senderInterceptor.loggerFactory = logging.NewDefaultLoggerFactory()
	}
	if senderInterceptor.log == nil {
		senderInterceptor.log = senderInterceptor.loggerFactory.NewLogger("sender_interceptor")
	}

	return senderInterceptor, nil
}

func NewSenderInterceptor(opts ...SenderOption) (*SenderInterceptorFactory, error) {
	return &SenderInterceptorFactory{opts}, nil
}

type SenderInterceptor struct {
	interceptor.NoOp
	interval        time.Duration
	now             func() time.Time
	newTicker       TickerFactory
	streams         sync.Map
	log             logging.LeveledLogger
	loggerFactory   logging.LoggerFactory
	m               sync.Mutex
	wg              sync.WaitGroup
	close           chan struct{}
	started         chan struct{}
	useLatestPacket bool
}

func (s *SenderInterceptor) isClosed() bool {
	select {
	case <-s.close:
		return true
	default:
		return false
	}
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

func (s *SenderInterceptor) BindRTCPWriter(writer interceptor.RTCPWriter) interceptor.RTCPWriter {
	s.m.Lock()
	defer s.m.Unlock()

	if s.isClosed() {
		return writer
	}

	s.wg.Add(1)

	go s.loop(writer)

	return writer
}

func (s *SenderInterceptor) loop(rtcpWriter interceptor.RTCPWriter) {
	defer s.wg.Done()

	ticker := s.newTicker(s.interval)
	defer ticker.Stop()
	if s.started != nil {

		close(s.started)
	}
	for {
		select {
		case <-ticker.Ch():
			now := s.now()
			s.streams.Range(func(_, value any) bool {
				if stream, ok := value.(*senderStream); !ok {
					s.log.Warnf("failed to cast SenderInterceptor stream")
				} else if _, err := rtcpWriter.Write(
					[]rtcp.Packet{stream.generateReport(now)}, interceptor.Attributes{},
				); err != nil {
					s.log.Warnf("failed sending: %+v", err)
				}

				return true
			})

		case <-s.close:
			return
		}
	}
}

func (s *SenderInterceptor) BindLocalStream(
	info *interceptor.StreamInfo, writer interceptor.RTPWriter,
) interceptor.RTPWriter {
	stream := newSenderStream(info.SSRC, info.ClockRate, s.useLatestPacket)
	s.streams.Store(info.SSRC, stream)

	return interceptor.RTPWriterFunc(func(header *rtp.Header, payload []byte, a interceptor.Attributes) (int, error) {
		stream.processRTP(s.now(), header, payload)

		return writer.Write(header, payload, a)
	})
}

func (s *SenderInterceptor) UnbindLocalStream(info *interceptor.StreamInfo) {
	s.streams.Delete(info.SSRC)
}

type SenderOption func(r *SenderInterceptor) error

func WithSenderLoggerFactory(loggerFactory logging.LoggerFactory) SenderOption {
	return func(r *SenderInterceptor) error {
		r.loggerFactory = loggerFactory

		return nil
	}
}

type senderStream struct {
	ssrc            uint32
	clockRate       float64
	m               sync.Mutex
	useLatestPacket bool
	lastRTPTimeRTP  uint32
	lastRTPTimeTime time.Time
	lastRTPSN       uint16
	packetCount     uint32
	octetCount      uint32
}

func newSenderStream(ssrc uint32, clockRate uint32, useLatestPacket bool) *senderStream {
	return &senderStream{
		ssrc:            ssrc,
		clockRate:       float64(clockRate),
		useLatestPacket: useLatestPacket,
	}
}

func (stream *senderStream) processRTP(now time.Time, header *rtp.Header, payload []byte) {
	stream.m.Lock()
	defer stream.m.Unlock()

	diff := header.SequenceNumber - stream.lastRTPSN
	if stream.useLatestPacket || stream.packetCount == 0 || (diff > 0 && diff < (1<<15)) {

		stream.lastRTPSN = header.SequenceNumber

		if header.Timestamp != stream.lastRTPTimeRTP {
			stream.lastRTPTimeRTP = header.Timestamp
			stream.lastRTPTimeTime = now
		}
	}

	stream.packetCount++
	stream.octetCount += uint32(len(payload))
}

func (stream *senderStream) generateReport(now time.Time) *rtcp.SenderReport {
	stream.m.Lock()
	defer stream.m.Unlock()

	return &rtcp.SenderReport{
		SSRC:        stream.ssrc,
		NTPTime:     webrtc.NTPTimestamp(now),
		RTPTime:     stream.lastRTPTimeRTP + uint32(now.Sub(stream.lastRTPTimeTime).Seconds()*stream.clockRate),
		PacketCount: stream.packetCount,
		OctetCount:  stream.octetCount,
	}
}

type Ticker interface {
	Ch() <-chan time.Time
	Stop()
}

type timeTicker struct {
	*time.Ticker
}

func (t *timeTicker) Ch() <-chan time.Time {
	return t.C
}
