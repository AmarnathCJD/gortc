package nack

import (
	"fmt"
	"math/rand"
	"slices"
	"sync"
	"time"

	"github.com/amarnathcjd/gortc/webrtc/interceptor"
	"github.com/amarnathcjd/gortc/webrtc/interceptor/internal/rtpbuffer"
	"github.com/amarnathcjd/gortc/webrtc/logging"
	"github.com/amarnathcjd/gortc/webrtc/rtcp"
	"github.com/amarnathcjd/gortc/webrtc/rtp"
)

var ErrInvalidSize = rtpbuffer.ErrInvalidSize

func streamSupportNack(info *interceptor.StreamInfo) bool {
	for _, fb := range info.RTCPFeedback {
		if fb.Type == "nack" && fb.Parameter == "" {
			return true
		}
	}

	return false
}

type GeneratorOption func(r *GeneratorInterceptor) error

func WithGeneratorLoggerFactory(loggerFactory logging.LoggerFactory) GeneratorOption {
	return func(r *GeneratorInterceptor) error {
		r.loggerFactory = loggerFactory

		return nil
	}
}

type ResponderOption func(s *ResponderInterceptor) error

func WithResponderLoggerFactory(loggerFactory logging.LoggerFactory) ResponderOption {
	return func(r *ResponderInterceptor) error {
		r.loggerFactory = loggerFactory

		return nil
	}
}

type GeneratorInterceptorFactory struct {
	opts []GeneratorOption
}

func (g *GeneratorInterceptorFactory) NewInterceptor(_ string) (interceptor.Interceptor, error) {
	generatorInterceptor := &GeneratorInterceptor{
		streamsFilter:     streamSupportNack,
		size:              512,
		skipLastN:         0,
		maxNacksPerPacket: 0,
		interval:          time.Millisecond * 100,
		receiveLogs:       map[uint32]*receiveLog{},
		nackCountLogs:     map[uint32]map[uint16]uint16{},
		close:             make(chan struct{}),
	}

	for _, opt := range g.opts {
		if err := opt(generatorInterceptor); err != nil {
			return nil, err
		}
	}

	if generatorInterceptor.loggerFactory == nil {
		generatorInterceptor.loggerFactory = logging.NewDefaultLoggerFactory()
	}
	if generatorInterceptor.log == nil {
		generatorInterceptor.log = generatorInterceptor.loggerFactory.NewLogger("nack_generator")
	}

	if _, err := newReceiveLog(generatorInterceptor.size); err != nil {
		return nil, err
	}

	return generatorInterceptor, nil
}

type GeneratorInterceptor struct {
	interceptor.NoOp
	streamsFilter     func(info *interceptor.StreamInfo) bool
	size              uint16
	skipLastN         uint16
	maxNacksPerPacket uint16
	interval          time.Duration
	m                 sync.Mutex
	wg                sync.WaitGroup
	close             chan struct{}
	log               logging.LeveledLogger
	loggerFactory     logging.LoggerFactory
	nackCountLogs     map[uint32]map[uint16]uint16
	receiveLogs       map[uint32]*receiveLog
	receiveLogsMu     sync.Mutex
}

func NewGeneratorInterceptor(opts ...GeneratorOption) (*GeneratorInterceptorFactory, error) {
	return &GeneratorInterceptorFactory{opts}, nil
}

func (n *GeneratorInterceptor) BindRTCPWriter(writer interceptor.RTCPWriter) interceptor.RTCPWriter {
	n.m.Lock()
	defer n.m.Unlock()

	if n.isClosed() {
		return writer
	}

	n.wg.Add(1)

	go n.loop(writer)

	return writer
}

func (n *GeneratorInterceptor) BindRemoteStream(
	info *interceptor.StreamInfo, reader interceptor.RTPReader,
) interceptor.RTPReader {
	if !n.streamsFilter(info) {
		return reader
	}

	receiveLog, _ := newReceiveLog(n.size)
	n.receiveLogsMu.Lock()
	n.receiveLogs[info.SSRC] = receiveLog
	n.receiveLogsMu.Unlock()

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
		receiveLog.add(header.SequenceNumber)

		return i, attr, nil
	})
}

func (n *GeneratorInterceptor) UnbindRemoteStream(info *interceptor.StreamInfo) {
	n.receiveLogsMu.Lock()
	delete(n.receiveLogs, info.SSRC)

	delete(n.nackCountLogs, info.SSRC)
	n.receiveLogsMu.Unlock()
}

func (n *GeneratorInterceptor) Close() error {
	defer n.wg.Wait()
	n.m.Lock()
	defer n.m.Unlock()

	if !n.isClosed() {
		close(n.close)
	}

	return nil
}

func (n *GeneratorInterceptor) loop(rtcpWriter interceptor.RTCPWriter) {
	defer n.wg.Done()

	senderSSRC := rand.Uint32()

	missingPacketSeqNums := make([]uint16, n.size)
	filteredMissingPacket := make([]uint16, n.size)

	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:

			var toSend []rtcp.Packet

			n.receiveLogsMu.Lock()
			for ssrc, receiveLog := range n.receiveLogs {
				missing := receiveLog.missingSeqNumbers(n.skipLastN, missingPacketSeqNums)

				if len(missing) == 0 || n.nackCountLogs[ssrc] == nil {
					n.nackCountLogs[ssrc] = map[uint16]uint16{}
				}
				if len(missing) == 0 {
					continue
				}

				var nack *rtcp.TransportLayerNack

				count := 0
				if n.maxNacksPerPacket > 0 {
					for _, missingSeq := range missing {
						if n.nackCountLogs[ssrc][missingSeq] < n.maxNacksPerPacket {
							filteredMissingPacket[count] = missingSeq
							count++
						}
						n.nackCountLogs[ssrc][missingSeq]++
					}

					if count == 0 {
						continue
					}

					nack = &rtcp.TransportLayerNack{
						SenderSSRC: senderSSRC,
						MediaSSRC:  ssrc,
						Nacks:      rtcp.NackPairsFromSequenceNumbers(filteredMissingPacket[:count]),
					}
				} else {
					nack = &rtcp.TransportLayerNack{
						SenderSSRC: senderSSRC,
						MediaSSRC:  ssrc,
						Nacks:      rtcp.NackPairsFromSequenceNumbers(missing),
					}
				}

				for nackSeq := range n.nackCountLogs[ssrc] {
					if !slices.Contains(missing, nackSeq) {
						delete(n.nackCountLogs[ssrc], nackSeq)
					}
				}

				if len(n.nackCountLogs[ssrc]) == 0 {
					delete(n.nackCountLogs, ssrc)
				}

				toSend = append(toSend, nack)
			}
			n.receiveLogsMu.Unlock()

			for _, pkt := range toSend {
				if _, err := rtcpWriter.Write([]rtcp.Packet{pkt}, interceptor.Attributes{}); err != nil {
					n.log.Warnf("failed sending nack: %+v", err)
				}
			}

		case <-n.close:
			return
		}
	}
}

func (n *GeneratorInterceptor) isClosed() bool {
	select {
	case <-n.close:
		return true
	default:
		return false
	}
}

type ResponderInterceptorFactory struct {
	opts []ResponderOption
}

func (r *ResponderInterceptorFactory) NewInterceptor(_ string) (interceptor.Interceptor, error) {
	responderInterceptor := &ResponderInterceptor{
		streamsFilter: streamSupportNack,
		size:          1024,
		streams:       map[uint32]*localStream{},
	}

	for _, opt := range r.opts {
		if err := opt(responderInterceptor); err != nil {
			return nil, err
		}
	}

	if responderInterceptor.loggerFactory == nil {
		responderInterceptor.loggerFactory = logging.NewDefaultLoggerFactory()
	}
	if responderInterceptor.log == nil {
		responderInterceptor.log = responderInterceptor.loggerFactory.NewLogger("nack_responder")
	}
	if responderInterceptor.packetFactory == nil {
		responderInterceptor.packetFactory = rtpbuffer.NewPacketFactoryCopy()
	}

	if _, err := rtpbuffer.NewRTPBuffer(responderInterceptor.size); err != nil {
		return nil, err
	}

	return responderInterceptor, nil
}

type ResponderInterceptor struct {
	interceptor.NoOp
	streamsFilter func(info *interceptor.StreamInfo) bool
	size          uint16
	log           logging.LeveledLogger
	loggerFactory logging.LoggerFactory
	packetFactory rtpbuffer.PacketFactory
	streams       map[uint32]*localStream
	streamsMu     sync.Mutex
}

type localStream struct {
	rtpBuffer      *rtpbuffer.RTPBuffer
	rtpBufferMutex sync.RWMutex
	rtpWriter      interceptor.RTPWriter
}

func NewResponderInterceptor(opts ...ResponderOption) (*ResponderInterceptorFactory, error) {
	return &ResponderInterceptorFactory{opts}, nil
}

func (n *ResponderInterceptor) BindRTCPReader(reader interceptor.RTCPReader) interceptor.RTCPReader {
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
		for _, rtcpPacket := range pkts {
			nack, ok := rtcpPacket.(*rtcp.TransportLayerNack)
			if !ok {
				continue
			}

			go n.resendPackets(nack)
		}

		return i, attr, err
	})
}

func (n *ResponderInterceptor) BindLocalStream(
	info *interceptor.StreamInfo, writer interceptor.RTPWriter,
) interceptor.RTPWriter {
	if !n.streamsFilter(info) {
		return writer
	}

	rtpBuffer, _ := rtpbuffer.NewRTPBuffer(n.size)
	stream := &localStream{
		rtpBuffer: rtpBuffer,
		rtpWriter: writer,
	}
	n.streamsMu.Lock()
	n.streams[info.SSRC] = stream
	n.streamsMu.Unlock()

	return interceptor.RTPWriterFunc(
		func(header *rtp.Header, payload []byte, attributes interceptor.Attributes) (int, error) {

			if header.SSRC != info.SSRC {
				return writer.Write(header, payload, attributes)
			}

			pkt, err := n.packetFactory.NewPacket(header, payload, info.SSRCRetransmission, info.PayloadTypeRetransmission)
			if err != nil {
				return 0, err
			}

			stream.rtpBufferMutex.Lock()
			stream.rtpBuffer.Add(pkt)
			stream.rtpBufferMutex.Unlock()

			return writer.Write(header, payload, attributes)
		},
	)
}

func (n *ResponderInterceptor) UnbindLocalStream(info *interceptor.StreamInfo) {
	n.streamsMu.Lock()
	stream, ok := n.streams[info.SSRC]
	delete(n.streams, info.SSRC)
	n.streamsMu.Unlock()

	if ok {
		stream.rtpBufferMutex.Lock()
		stream.rtpBuffer.Clear()
		stream.rtpBufferMutex.Unlock()
	}
}

func (n *ResponderInterceptor) Close() error {
	n.streamsMu.Lock()
	streams := n.streams
	n.streams = map[uint32]*localStream{}
	n.streamsMu.Unlock()

	for _, stream := range streams {
		stream.rtpBufferMutex.Lock()
		stream.rtpBuffer.Clear()
		stream.rtpBufferMutex.Unlock()
	}

	return nil
}

func (n *ResponderInterceptor) resendPackets(nack *rtcp.TransportLayerNack) {
	n.streamsMu.Lock()
	stream, ok := n.streams[nack.MediaSSRC]
	n.streamsMu.Unlock()
	if !ok {
		return
	}

	for i := range nack.Nacks {
		nack.Nacks[i].Range(func(seq uint16) bool {

			stream.rtpBufferMutex.Lock()
			p := stream.rtpBuffer.Get(seq)
			stream.rtpBufferMutex.Unlock()

			if p != nil {

				if _, err := stream.rtpWriter.Write(p.Header(), p.Payload(), interceptor.Attributes{}); err != nil {
					n.log.Warnf("failed resending nacked packet: %+v", err)
				}
				p.Release()
			}

			return true
		})
	}
}

type receiveLog struct {
	packets         []uint64
	size            uint16
	end             uint16
	started         bool
	lastConsecutive uint16
	m               sync.RWMutex
}

func newReceiveLog(size uint16) (*receiveLog, error) {
	allowedSizes := make([]uint16, 0)
	correctSize := false
	for i := 6; i < 16; i++ {
		if size == 1<<i {
			correctSize = true

			break
		}
		allowedSizes = append(allowedSizes, 1<<i)
	}

	if !correctSize {
		return nil, fmt.Errorf("%w: %d is not a valid size, allowed sizes: %v", ErrInvalidSize, size, allowedSizes)
	}

	return &receiveLog{
		packets: make([]uint64, size/64),
		size:    size,
	}, nil
}

func (s *receiveLog) add(seq uint16) {
	s.m.Lock()
	defer s.m.Unlock()

	if !s.started {
		s.setReceived(seq)
		s.end = seq
		s.started = true
		s.lastConsecutive = seq

		return
	}

	diff := seq - s.end
	switch {
	case diff == 0:
		return
	case diff < rtpbuffer.Uint16SizeHalf:

		for i := s.end + 1; i != seq; i++ {

			s.delReceived(i)
		}
		s.end = seq

		if s.lastConsecutive+1 == seq {
			s.lastConsecutive = seq
		} else if seq-s.lastConsecutive > s.size {
			s.lastConsecutive = seq - s.size
			s.fixLastConsecutive()
		}
	case s.lastConsecutive+1 == seq:

		s.lastConsecutive = seq
		s.fixLastConsecutive()
	}

	s.setReceived(seq)
}

func (s *receiveLog) missingSeqNumbers(skipLastN uint16, missingPacketSeqNums []uint16) []uint16 {
	s.m.RLock()
	defer s.m.RUnlock()

	until := s.end - skipLastN
	if until-s.lastConsecutive >= rtpbuffer.Uint16SizeHalf {

		return nil
	}

	c := 0
	for i := s.lastConsecutive + 1; i != until+1; i++ {
		if !s.getReceived(i) {
			missingPacketSeqNums[c] = i
			c++
		}
	}

	return missingPacketSeqNums[:c]
}

func (s *receiveLog) setReceived(seq uint16) {
	pos := seq % s.size
	s.packets[pos/64] |= 1 << (pos % 64)
}

func (s *receiveLog) delReceived(seq uint16) {
	pos := seq % s.size
	s.packets[pos/64] &^= 1 << (pos % 64)
}

func (s *receiveLog) getReceived(seq uint16) bool {
	pos := seq % s.size

	return (s.packets[pos/64] & (1 << (pos % 64))) != 0
}

func (s *receiveLog) fixLastConsecutive() {
	i := s.lastConsecutive + 1
	for ; i != s.end+1 && s.getReceived(i); i++ {

	}

	s.lastConsecutive = i - 1
}
