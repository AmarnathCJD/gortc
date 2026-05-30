package rtpbuffer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"github.com/amarnathcjd/gortc/webrtc/rtp"
	"sync"
)

var ErrInvalidSize = errors.New("invalid buffer size")

var (
	errPacketReleased          = errors.New("could not retain packet, already released")
	errFailedToCastHeaderPool  = errors.New("could not access header pool, failed cast")
	errFailedToCastPayloadPool = errors.New("could not access payload pool, failed cast")
	errPaddingOverflow         = errors.New("padding size exceeds payload size")
)

const rtxSsrcByteLength = 2

type PacketFactory interface {
	NewPacket(header *rtp.Header, payload []byte, rtxSsrc uint32, rtxPayloadType uint8) (*RetainablePacket, error)
}

type PacketFactoryCopy struct {
	headerPool   *sync.Pool
	payloadPool  *sync.Pool
	rtxSequencer rtp.Sequencer
}

func NewPacketFactoryCopy() *PacketFactoryCopy {
	return &PacketFactoryCopy{
		headerPool: &sync.Pool{
			New: func() any {
				return &rtp.Header{}
			},
		},
		payloadPool: &sync.Pool{
			New: func() any {
				buf := make([]byte, maxPayloadLen)

				return &buf
			},
		},
		rtxSequencer: rtp.NewRandomSequencer(),
	}
}

func (m *PacketFactoryCopy) NewPacket(
	header *rtp.Header, payload []byte, rtxSsrc uint32, rtxPayloadType uint8,
) (*RetainablePacket, error) {
	if len(payload) > maxPayloadLen {
		return nil, io.ErrShortBuffer
	}

	retainablePacket := &RetainablePacket{
		onRelease:      m.releasePacket,
		sequenceNumber: header.SequenceNumber,

		count: 1,
	}

	var ok bool
	retainablePacket.header, ok = m.headerPool.Get().(*rtp.Header)
	if !ok {
		return nil, errFailedToCastHeaderPool
	}

	*retainablePacket.header = header.Clone()

	if payload != nil {
		retainablePacket.buffer, ok = m.payloadPool.Get().(*[]byte)
		if !ok {
			return nil, errFailedToCastPayloadPool
		}
		if rtxSsrc != 0 && rtxPayloadType != 0 {
			size := copy((*retainablePacket.buffer)[rtxSsrcByteLength:], payload)
			retainablePacket.payload = (*retainablePacket.buffer)[:size+rtxSsrcByteLength]
		} else {
			size := copy(*retainablePacket.buffer, payload)
			retainablePacket.payload = (*retainablePacket.buffer)[:size]
		}
	}

	if rtxSsrc != 0 && rtxPayloadType != 0 {
		if payload == nil {
			retainablePacket.buffer, ok = m.payloadPool.Get().(*[]byte)
			if !ok {
				return nil, errFailedToCastPayloadPool
			}
			retainablePacket.payload = (*retainablePacket.buffer)[:rtxSsrcByteLength]
		}

		binary.BigEndian.PutUint16(retainablePacket.payload, retainablePacket.header.SequenceNumber)

		retainablePacket.header.SSRC = rtxSsrc

		retainablePacket.header.PayloadType = rtxPayloadType

		retainablePacket.header.SequenceNumber = m.rtxSequencer.NextSequenceNumber()

		if retainablePacket.header.Padding {

			if retainablePacket.header.PaddingSize == 0 && len(retainablePacket.payload) > 0 {
				paddingLength := int(retainablePacket.payload[len(retainablePacket.payload)-1])
				if paddingLength > len(retainablePacket.payload) {
					return nil, errPaddingOverflow
				}
				retainablePacket.payload = (*retainablePacket.buffer)[:len(retainablePacket.payload)-paddingLength]
			}

			retainablePacket.header.Padding = false
			retainablePacket.header.PaddingSize = 0
		}
	}

	return retainablePacket, nil
}

func (m *PacketFactoryCopy) releasePacket(header *rtp.Header, payload *[]byte) {
	m.headerPool.Put(header)
	if payload != nil {
		m.payloadPool.Put(payload)
	}
}

type RetainablePacket struct {
	onRelease      func(*rtp.Header, *[]byte)
	countMu        sync.Mutex
	count          int
	header         *rtp.Header
	buffer         *[]byte
	payload        []byte
	sequenceNumber uint16
}

func (p *RetainablePacket) Header() *rtp.Header {
	return p.header
}

func (p *RetainablePacket) Payload() []byte {
	return p.payload
}

func (p *RetainablePacket) Retain() error {
	p.countMu.Lock()
	defer p.countMu.Unlock()
	if p.count == 0 {

		return errPacketReleased
	}
	p.count++

	return nil
}

func (p *RetainablePacket) Release() {
	p.countMu.Lock()
	defer p.countMu.Unlock()
	p.count--

	if p.count == 0 {

		p.onRelease(p.header, p.buffer)
		p.header = nil
		p.buffer = nil
		p.payload = nil
	}
}

const (
	Uint16SizeHalf = 1 << 15

	maxPayloadLen = 1460
)

type RTPBuffer struct {
	packets      []*RetainablePacket
	size         uint16
	highestAdded uint16
	started      bool
}

func NewRTPBuffer(size uint16) (*RTPBuffer, error) {
	allowedSizes := make([]uint16, 0)
	correctSize := false
	for i := range 16 {
		if size == 1<<i {
			correctSize = true

			break
		}
		allowedSizes = append(allowedSizes, 1<<i)
	}

	if !correctSize {
		return nil, fmt.Errorf("%w: %d is not a valid size, allowed sizes: %v", ErrInvalidSize, size, allowedSizes)
	}

	return &RTPBuffer{
		packets: make([]*RetainablePacket, size),
		size:    size,
	}, nil
}

func (r *RTPBuffer) Add(packet *RetainablePacket) {
	seq := packet.sequenceNumber
	if !r.started {
		r.packets[seq%r.size] = packet
		r.highestAdded = seq
		r.started = true

		return
	}

	diff := seq - r.highestAdded
	if diff == 0 {
		return
	} else if diff < Uint16SizeHalf {
		for i := r.highestAdded + 1; i != seq; i++ {
			idx := i % r.size
			prevPacket := r.packets[idx]
			if prevPacket != nil {
				prevPacket.Release()
			}
			r.packets[idx] = nil
		}
		r.highestAdded = seq
	}

	idx := seq % r.size
	prevPacket := r.packets[idx]
	if prevPacket != nil {
		prevPacket.Release()
	}
	r.packets[idx] = packet
}

func (r *RTPBuffer) Clear() {
	for i, pkt := range r.packets {
		if pkt != nil {
			pkt.Release()
			r.packets[i] = nil
		}
	}
	r.started = false
}

func (r *RTPBuffer) Get(seq uint16) *RetainablePacket {
	diff := r.highestAdded - seq
	if diff >= Uint16SizeHalf {
		return nil
	}

	if diff >= r.size {
		return nil
	}

	pkt := r.packets[seq%r.size]
	if pkt != nil {
		if pkt.sequenceNumber != seq {
			return nil
		}

		if err := pkt.Retain(); err != nil {
			return nil
		}
	}

	return pkt
}
