// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package webrtc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wlynxg/anet"
)

var (
	TransportErrNoAddressAssigned = errors.New("no address assigned")
	TransportErrInterfaceNotFound = errors.New("interface not found")
)

type TransportNet interface {
	ListenPacket(network string, address string) (net.PacketConn, error)
	ListenUDP(network string, locAddr *net.UDPAddr) (TransportUDPConn, error)
	ListenTCP(network string, laddr *net.TCPAddr) (TransportTCPListener, error)
	Dial(network, address string) (net.Conn, error)
	DialUDP(network string, laddr, raddr *net.UDPAddr) (TransportUDPConn, error)
	DialTCP(network string, laddr, raddr *net.TCPAddr) (TransportTCPConn, error)
	ResolveIPAddr(network, address string) (*net.IPAddr, error)
	ResolveUDPAddr(network, address string) (*net.UDPAddr, error)
	ResolveTCPAddr(network, address string) (*net.TCPAddr, error)
	Interfaces() ([]*TransportInterface, error)
	InterfaceByIndex(index int) (*TransportInterface, error)
	InterfaceByName(name string) (*TransportInterface, error)
	CreateDialer(dialer *net.Dialer) TransportDialer
	CreateListenConfig(listenerConfig *net.ListenConfig) TransportListenConfig
}

type TransportDialer interface {
	Dial(network, address string) (net.Conn, error)
}

type TransportListenConfig interface {
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

type TransportUDPConn interface {
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
	Read(b []byte) (n int, err error)
	ReadFrom(p []byte) (n int, addr net.Addr, err error)
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	Write(b []byte) (n int, err error)
	WriteTo(p []byte, addr net.Addr) (n int, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

type TransportTCPConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
	ReadFrom(r io.Reader) (int64, error)
	SetLinger(sec int) error
	SetKeepAlive(keepalive bool) error
	SetKeepAlivePeriod(d time.Duration) error
	SetNoDelay(noDelay bool) error
	SetWriteBuffer(bytes int) error
	SetReadBuffer(bytes int) error
}

type TransportTCPListener interface {
	net.Listener
	AcceptTCP() (TransportTCPConn, error)
	SetDeadline(t time.Time) error
}

type TransportInterface struct {
	net.Interface
	addrs []net.Addr
}

func TransportNewInterface(ifc net.Interface) *TransportInterface {
	return &TransportInterface{
		Interface: ifc,
		addrs:     nil,
	}
}

func (ifc *TransportInterface) AddAddress(addr net.Addr) {
	ifc.addrs = append(ifc.addrs, addr)
}

func (ifc *TransportInterface) Addrs() ([]net.Addr, error) {
	if len(ifc.addrs) == 0 {
		return nil, TransportErrNoAddressAssigned
	}

	return ifc.addrs, nil
}

type transportDeadlineState uint8

const (
	transportDeadlineStopped transportDeadlineState = iota
	transportDeadlineStarted
	transportDeadlineExceeded
)

var _ context.Context = (*TransportDeadline)(nil)

type TransportDeadline struct {
	mu       sync.RWMutex
	timer    transportTimer
	done     chan struct{}
	deadline time.Time
	state    transportDeadlineState
	pending  uint8
}

func TransportNewDeadline() *TransportDeadline {
	return &TransportDeadline{
		done: make(chan struct{}),
	}
}

func (d *TransportDeadline) timeout() {
	d.mu.Lock()
	if d.pending--; d.pending != 0 || d.state != transportDeadlineStarted {
		d.mu.Unlock()

		return
	}

	d.state = transportDeadlineExceeded
	done := d.done
	d.mu.Unlock()

	close(done)
}

func (d *TransportDeadline) Set(setTo time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.state == transportDeadlineStarted && d.timer.Stop() {
		d.pending--
	}

	d.deadline = setTo
	d.pending++

	if d.state == transportDeadlineExceeded {
		d.done = make(chan struct{})
	}

	if setTo.IsZero() {
		d.pending--
		d.state = transportDeadlineStopped

		return
	}

	if dur := time.Until(setTo); dur > 0 {
		d.state = transportDeadlineStarted
		if d.timer == nil {
			d.timer = transportAfterFunc(dur, d.timeout)
		} else {
			d.timer.Reset(dur)
		}

		return
	}

	d.pending--
	d.state = transportDeadlineExceeded
	close(d.done)
}

func (d *TransportDeadline) Done() <-chan struct{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.done
}

func (d *TransportDeadline) Err() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.state == transportDeadlineExceeded {
		return context.DeadlineExceeded
	}

	return nil
}

func (d *TransportDeadline) Deadline() (time.Time, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.deadline.IsZero() {
		return d.deadline, false
	}

	return d.deadline, true
}

func (d *TransportDeadline) Value(any) any {
	return nil
}

type transportTimer interface {
	Stop() bool
	Reset(time.Duration) bool
}

func transportAfterFunc(d time.Duration, f func()) transportTimer {
	return time.AfterFunc(d, f)
}

var TransportErrClosing = errors.New("use of closed network connection")
var transportVeryOld = time.Unix(0, 1)

type TransportReaderFrom interface {
	ReadFromContext(context.Context, []byte) (int, net.Addr, error)
}

type TransportWriterTo interface {
	WriteToContext(context.Context, []byte, net.Addr) (int, error)
}

type TransportPacketConn interface {
	TransportReaderFrom
	TransportWriterTo
	io.Closer
	LocalAddr() net.Addr
	Conn() net.PacketConn
}

type transportPacketConn struct {
	nextConn  net.PacketConn
	closed    chan struct{}
	closeOnce sync.Once
	readMu    sync.Mutex
	writeMu   sync.Mutex
}

func TransportNewPacketConn(pconn net.PacketConn) TransportPacketConn {
	p := &transportPacketConn{
		nextConn: pconn,
		closed:   make(chan struct{}),
	}

	return p
}

func (p *transportPacketConn) ReadFromContext(ctx context.Context, b []byte) (int, net.Addr, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()

	select {
	case <-p.closed:
		return 0, nil, net.ErrClosed
	default:
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	var errSetDeadline atomic.Value
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():

			if err := p.nextConn.SetReadDeadline(transportVeryOld); err != nil {
				errSetDeadline.Store(err)

				return
			}
			<-done
			if err := p.nextConn.SetReadDeadline(time.Time{}); err != nil {
				errSetDeadline.Store(err)
			}
		case <-done:
		}
	}()

	n, raddr, err := p.nextConn.ReadFrom(b)

	close(done)
	wg.Wait()
	if e := ctx.Err(); e != nil && n == 0 {
		err = e
	}
	if err2, ok := errSetDeadline.Load().(error); ok && err == nil && err2 != nil {
		err = err2
	}

	return n, raddr, err
}

func (p *transportPacketConn) WriteToContext(ctx context.Context, b []byte, raddr net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	select {
	case <-p.closed:
		return 0, TransportErrClosing
	default:
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	var errSetDeadline atomic.Value
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():

			if err := p.nextConn.SetWriteDeadline(transportVeryOld); err != nil {
				errSetDeadline.Store(err)

				return
			}
			<-done
			if err := p.nextConn.SetWriteDeadline(time.Time{}); err != nil {
				errSetDeadline.Store(err)
			}
		case <-done:
		}
	}()

	n, err := p.nextConn.WriteTo(b, raddr)

	close(done)
	wg.Wait()
	if e := ctx.Err(); e != nil && n == 0 {
		err = e
	}
	if err2, ok := errSetDeadline.Load().(error); ok && err == nil && err2 != nil {
		err = err2
	}

	return n, err
}

func (p *transportPacketConn) Close() error {
	err := p.nextConn.Close()
	p.closeOnce.Do(func() {
		p.writeMu.Lock()
		p.readMu.Lock()
		close(p.closed)
		p.readMu.Unlock()
		p.writeMu.Unlock()
	})

	return err
}

func (p *transportPacketConn) LocalAddr() net.Addr {
	return p.nextConn.LocalAddr()
}

func (p *transportPacketConn) Conn() net.PacketConn {
	return p.nextConn
}

var transportErrPacketTooBig = errors.New("packet too big")

var (
	TransportErrFull = errors.New("packetio.Buffer is full, discarding write")

	TransportErrTimeout = errors.New("i/o timeout")
)

type transportNetError struct {
	error
	timeout, temporary bool
}

func (e *transportNetError) Timeout() bool {
	return e.timeout
}

func (e *transportNetError) Temporary() bool {
	return e.temporary
}

type TransportBufferPacketType int

const (
	TransportRTPBufferPacket TransportBufferPacketType = 1

	TransportRTCPBufferPacket TransportBufferPacketType = 2
)

type TransportBuffer struct {
	mutex        sync.Mutex
	data         []byte
	head, tail   int
	notify       chan struct{}
	closed       bool
	limitSize    int
	readDeadline *TransportDeadline
}

const (
	transportMinSize    = 2048
	transportCutoffSize = 128 * 1024
	transportMaxSize    = 4 * 1024 * 1024
)

func TransportNewBuffer() *TransportBuffer {
	return &TransportBuffer{
		notify:       make(chan struct{}, 1),
		readDeadline: TransportNewDeadline(),
	}
}

func (b *TransportBuffer) available(size int) bool {
	available := b.head - b.tail
	if available <= 0 {
		available += len(b.data)
	}

	if size+2+1 > available {
		return false
	}

	return true
}

func (b *TransportBuffer) grow() error {
	var newSize int
	if len(b.data) < transportCutoffSize {
		newSize = 2 * len(b.data)
	} else {
		newSize = 5 * len(b.data) / 4
	}
	if newSize < transportMinSize {
		newSize = transportMinSize
	}
	if b.limitSize <= 0 && newSize > transportMaxSize {
		newSize = transportMaxSize
	}

	if b.limitSize > 0 && newSize > b.limitSize+1 {
		newSize = b.limitSize + 1
	}

	if newSize <= len(b.data) {
		return TransportErrFull
	}

	newData := make([]byte, newSize)

	var n int
	if b.head <= b.tail {

		n = copy(newData, b.data[b.head:b.tail])
	} else {

		n = copy(newData, b.data[b.head:])
		n += copy(newData[n:], b.data[:b.tail])
	}
	b.head = 0
	b.tail = n
	b.data = newData

	return nil
}

func (b *TransportBuffer) Write(packet []byte) (int, error) {
	if len(packet) >= 0x10000 {
		return 0, transportErrPacketTooBig
	}

	b.mutex.Lock()

	if b.closed {
		b.mutex.Unlock()

		return 0, io.ErrClosedPipe
	}

	if b.limitSize > 0 && b.size()+2+len(packet) > b.limitSize {
		b.mutex.Unlock()

		return 0, TransportErrFull
	}

	for !b.available(len(packet)) {
		err := b.grow()
		if err != nil {
			b.mutex.Unlock()

			return 0, err
		}
	}

	b.data[b.tail] = uint8(len(packet) >> 8)
	b.tail++
	if b.tail >= len(b.data) {
		b.tail = 0
	}
	b.data[b.tail] = uint8(len(packet))
	b.tail++
	if b.tail >= len(b.data) {
		b.tail = 0
	}

	n := copy(b.data[b.tail:], packet)
	b.tail += n
	if b.tail >= len(b.data) {

		m := copy(b.data, packet[n:])
		b.tail = m
	}

	select {
	case b.notify <- struct{}{}:
	default:
	}
	b.mutex.Unlock()

	return len(packet), nil
}

func (b *TransportBuffer) Read(packet []byte) (n int, err error) {

	select {
	case <-b.readDeadline.Done():
		return 0, &transportNetError{TransportErrTimeout, true, true}
	default:
	}

	for {
		b.mutex.Lock()

		if b.head != b.tail {

			n1 := b.data[b.head]
			b.head++
			if b.head >= len(b.data) {
				b.head = 0
			}
			n2 := b.data[b.head]
			b.head++
			if b.head >= len(b.data) {
				b.head = 0
			}
			count := int((uint16(n1) << 8) | uint16(n2))

			copied := count
			if copied > len(packet) {
				copied = len(packet)
			}

			if b.head+copied < len(b.data) {
				copy(packet, b.data[b.head:b.head+copied])
			} else {
				k := copy(packet, b.data[b.head:])
				copy(packet[k:], b.data[:copied-k])
			}

			b.head += count
			if b.head >= len(b.data) {
				b.head -= len(b.data)
			}

			if b.head == b.tail {

				b.head = 0
				b.tail = 0
			}

			b.mutex.Unlock()

			if copied < count {
				return copied, io.ErrShortBuffer
			}

			return copied, nil
		}

		if b.closed {
			b.mutex.Unlock()

			return 0, io.EOF
		}
		b.mutex.Unlock()

		select {
		case <-b.readDeadline.Done():
			return 0, &transportNetError{TransportErrTimeout, true, true}
		case <-b.notify:
		}
	}
}

func (b *TransportBuffer) Close() (err error) {
	b.mutex.Lock()

	if b.closed {
		b.mutex.Unlock()

		return nil
	}

	b.closed = true
	close(b.notify)
	b.mutex.Unlock()

	return nil
}

func (b *TransportBuffer) size() int {
	size := b.tail - b.head
	if size < 0 {
		size += len(b.data)
	}

	return size
}

func (b *TransportBuffer) SetLimitSize(limit int) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.limitSize = limit
}

func (b *TransportBuffer) SetReadDeadline(t time.Time) error {
	b.readDeadline.Set(t)

	return nil
}

type TransportReplayDetector interface {
	Check(seq uint64) (accept func() bool, ok bool)
}

func transportNop() bool {
	return false
}

type transportSlidingWindowDetector struct {
	latestSeq  uint64
	maxSeq     uint64
	windowSize uint
	mask       *transportFixedBigInt
}

func TransportNewReplayDetector(windowSize uint, maxSeq uint64) TransportReplayDetector {
	return &transportSlidingWindowDetector{
		maxSeq:     maxSeq,
		windowSize: windowSize,
		mask:       transportNewFixedBigInt(windowSize),
	}
}

func (d *transportSlidingWindowDetector) Check(seq uint64) (func() bool, bool) {
	if seq > d.maxSeq {
		return transportNop, false
	}

	if seq <= d.latestSeq {
		if d.latestSeq >= uint64(d.windowSize)+seq {
			return transportNop, false
		}
		if d.mask.Bit(uint(d.latestSeq-seq)) != 0 {
			return transportNop, false
		}
	}

	return func() bool {
		latest := seq == 0
		if seq > d.latestSeq {
			d.mask.Lsh(uint(seq - d.latestSeq))
			d.latestSeq = seq
			latest = true
		}
		diff := (d.latestSeq - seq) % d.maxSeq
		d.mask.SetBit(uint(diff))

		return latest
	}, true
}

type transportFixedBigInt struct {
	bits    []uint64
	n       uint
	msbMask uint64
}

func transportNewFixedBigInt(n uint) *transportFixedBigInt {
	chunkSize := (n + 63) / 64
	if chunkSize == 0 {
		chunkSize = 1
	}

	return &transportFixedBigInt{
		bits:    make([]uint64, chunkSize),
		n:       n,
		msbMask: (1 << (64 - n%64)) - 1,
	}
}

func (s *transportFixedBigInt) Lsh(n uint) {
	if n == 0 {
		return
	}
	nChunk := int(n / 64)
	nN := n % 64

	for i := len(s.bits) - 1; i >= 0; i-- {
		var carry uint64
		if i-nChunk >= 0 {
			carry = s.bits[i-nChunk] << nN
			if i-nChunk-1 >= 0 {
				carry |= s.bits[i-nChunk-1] >> (64 - nN)
			}
		}
		s.bits[i] = (s.bits[i] << n) | carry
	}
	s.bits[len(s.bits)-1] &= s.msbMask
}

func (s *transportFixedBigInt) Bit(i uint) uint {
	if i >= s.n {
		return 0
	}
	chunk := i / 64
	pos := i % 64
	if s.bits[chunk]&(1<<pos) != 0 {
		return 1
	}

	return 0
}

func (s *transportFixedBigInt) SetBit(i uint) {
	if i >= s.n {
		return
	}
	chunk := i / 64
	pos := i % 64
	s.bits[chunk] |= 1 << pos
}

type TransportStdNet struct {
	interfaces []*TransportInterface
}

func TransportNewNet() (*TransportStdNet, error) {
	n := &TransportStdNet{}

	return n, n.UpdateInterfaces()
}

var _ TransportNet = &TransportStdNet{}

func (n *TransportStdNet) UpdateInterfaces() error {
	ifs := []*TransportInterface{}

	oifs, err := anet.Interfaces()
	if err != nil {
		return err
	}

	for i := range oifs {
		ifc := TransportNewInterface(oifs[i])

		addrs, err := anet.InterfaceAddrsByInterface(&oifs[i])
		if err != nil {
			return err
		}

		for _, addr := range addrs {
			ifc.AddAddress(addr)
		}

		ifs = append(ifs, ifc)
	}

	n.interfaces = ifs

	return nil
}

func (n *TransportStdNet) Interfaces() ([]*TransportInterface, error) {
	return n.interfaces, nil
}

func (n *TransportStdNet) InterfaceByIndex(index int) (*TransportInterface, error) {
	for _, ifc := range n.interfaces {
		if ifc.Index == index {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: index=%d", TransportErrInterfaceNotFound, index)
}

func (n *TransportStdNet) InterfaceByName(name string) (*TransportInterface, error) {
	for _, ifc := range n.interfaces {
		if ifc.Name == name {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", TransportErrInterfaceNotFound, name)
}

func (n *TransportStdNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func (n *TransportStdNet) ListenUDP(network string, locAddr *net.UDPAddr) (TransportUDPConn, error) {
	return net.ListenUDP(network, locAddr)
}

func (n *TransportStdNet) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (n *TransportStdNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (TransportUDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

func (n *TransportStdNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return net.ResolveIPAddr(network, address)
}

func (n *TransportStdNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr(network, address)
}

func (n *TransportStdNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr(network, address)
}

func (n *TransportStdNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (TransportTCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}

func (n *TransportStdNet) ListenTCP(network string, laddr *net.TCPAddr) (TransportTCPListener, error) {
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	return transportTcpListener{l}, nil
}

type transportTcpListener struct {
	*net.TCPListener
}

func (l transportTcpListener) AcceptTCP() (TransportTCPConn, error) {
	return l.TCPListener.AcceptTCP()
}

type transportStdDialer struct {
	*net.Dialer
}

func (d transportStdDialer) Dial(network, address string) (net.Conn, error) {
	return d.Dialer.Dial(network, address)
}

func (n *TransportStdNet) CreateDialer(d *net.Dialer) TransportDialer {
	return transportStdDialer{d}
}

type transportStdListenConfig struct {
	*net.ListenConfig
}

func (d transportStdListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.ListenConfig.Listen(ctx, network, address)
}

func (d transportStdListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return d.ListenConfig.ListenPacket(ctx, network, address)
}

func (n *TransportStdNet) CreateListenConfig(d *net.ListenConfig) TransportListenConfig {
	return transportStdListenConfig{d}
}

func TransportXorBytes(dst, a, b []byte) int {
	return subtle.XORBytes(dst, a, b)
}
