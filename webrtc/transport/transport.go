package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wlynxg/anet"
)

// -----------------------------------------------------------------------------
// net.go (base transport package)
// -----------------------------------------------------------------------------

var (
	ErrNoAddressAssigned = errors.New("no address assigned")

	ErrInterfaceNotFound = errors.New("interface not found")
)

type Net interface {
	ListenPacket(network string, address string) (net.PacketConn, error)
	ListenUDP(network string, locAddr *net.UDPAddr) (UDPConn, error)
	ListenTCP(network string, laddr *net.TCPAddr) (TCPListener, error)
	Dial(network, address string) (net.Conn, error)
	DialUDP(network string, laddr, raddr *net.UDPAddr) (UDPConn, error)
	DialTCP(network string, laddr, raddr *net.TCPAddr) (TCPConn, error)
	ResolveIPAddr(network, address string) (*net.IPAddr, error)
	ResolveUDPAddr(network, address string) (*net.UDPAddr, error)
	ResolveTCPAddr(network, address string) (*net.TCPAddr, error)
	Interfaces() ([]*Interface, error)
	InterfaceByIndex(index int) (*Interface, error)
	InterfaceByName(name string) (*Interface, error)
	CreateDialer(dialer *net.Dialer) Dialer
	CreateListenConfig(listenerConfig *net.ListenConfig) ListenConfig
}

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type ListenConfig interface {
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

type UDPConn interface {
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

type TCPConn interface {
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

type TCPListener interface {
	net.Listener
	AcceptTCP() (TCPConn, error)
	SetDeadline(t time.Time) error
}

type Interface struct {
	net.Interface
	addrs []net.Addr
}

func NewInterface(ifc net.Interface) *Interface {
	return &Interface{
		Interface: ifc,
		addrs:     nil,
	}
}

func (ifc *Interface) AddAddress(addr net.Addr) {
	ifc.addrs = append(ifc.addrs, addr)
}

func (ifc *Interface) Addrs() ([]net.Addr, error) {
	if len(ifc.addrs) == 0 {
		return nil, ErrNoAddressAssigned
	}

	return ifc.addrs, nil
}

// -----------------------------------------------------------------------------
// deadline (was package deadline)
// -----------------------------------------------------------------------------

type deadlineState uint8

const (
	deadlineStopped deadlineState = iota
	deadlineStarted
	deadlineExceeded
)

var _ context.Context = (*Deadline)(nil)

type Deadline struct {
	mu       sync.RWMutex
	timer    timer
	done     chan struct{}
	deadline time.Time
	state    deadlineState
	pending  uint8
}

func NewDeadline() *Deadline {
	return &Deadline{
		done: make(chan struct{}),
	}
}

func (d *Deadline) timeout() {
	d.mu.Lock()
	if d.pending--; d.pending != 0 || d.state != deadlineStarted {
		d.mu.Unlock()

		return
	}

	d.state = deadlineExceeded
	done := d.done
	d.mu.Unlock()

	close(done)
}

func (d *Deadline) Set(setTo time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.state == deadlineStarted && d.timer.Stop() {
		d.pending--
	}

	d.deadline = setTo
	d.pending++

	if d.state == deadlineExceeded {
		d.done = make(chan struct{})
	}

	if setTo.IsZero() {
		d.pending--
		d.state = deadlineStopped

		return
	}

	if dur := time.Until(setTo); dur > 0 {
		d.state = deadlineStarted
		if d.timer == nil {
			d.timer = afterFunc(dur, d.timeout)
		} else {
			d.timer.Reset(dur)
		}

		return
	}

	d.pending--
	d.state = deadlineExceeded
	close(d.done)
}

func (d *Deadline) Done() <-chan struct{} {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.done
}

func (d *Deadline) Err() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.state == deadlineExceeded {
		return context.DeadlineExceeded
	}

	return nil
}

func (d *Deadline) Deadline() (time.Time, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.deadline.IsZero() {
		return d.deadline, false
	}

	return d.deadline, true
}

func (d *Deadline) Value(any) any {
	return nil
}

type timer interface {
	Stop() bool
	Reset(time.Duration) bool
}

func afterFunc(d time.Duration, f func()) timer {
	return time.AfterFunc(d, f)
}

// -----------------------------------------------------------------------------
// netctx (was package netctx)
// -----------------------------------------------------------------------------

var ErrClosing = errors.New("use of closed network connection")

var veryOld = time.Unix(0, 1)

type ReaderFrom interface {
	ReadFromContext(context.Context, []byte) (int, net.Addr, error)
}

type WriterTo interface {
	WriteToContext(context.Context, []byte, net.Addr) (int, error)
}

type PacketConn interface {
	ReaderFrom
	WriterTo
	io.Closer
	LocalAddr() net.Addr
	Conn() net.PacketConn
}

type packetConn struct {
	nextConn  net.PacketConn
	closed    chan struct{}
	closeOnce sync.Once
	readMu    sync.Mutex
	writeMu   sync.Mutex
}

func NewPacketConn(pconn net.PacketConn) PacketConn {
	p := &packetConn{
		nextConn: pconn,
		closed:   make(chan struct{}),
	}

	return p
}

func (p *packetConn) ReadFromContext(ctx context.Context, b []byte) (int, net.Addr, error) {
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

			if err := p.nextConn.SetReadDeadline(veryOld); err != nil {
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

func (p *packetConn) WriteToContext(ctx context.Context, b []byte, raddr net.Addr) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	select {
	case <-p.closed:
		return 0, ErrClosing
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

			if err := p.nextConn.SetWriteDeadline(veryOld); err != nil {
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

func (p *packetConn) Close() error {
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

func (p *packetConn) LocalAddr() net.Addr {
	return p.nextConn.LocalAddr()
}

func (p *packetConn) Conn() net.PacketConn {
	return p.nextConn
}

// -----------------------------------------------------------------------------
// packetio (was package packetio)
// -----------------------------------------------------------------------------

var errPacketTooBig = errors.New("packet too big")

var (
	ErrFull = errors.New("packetio.Buffer is full, discarding write")

	ErrTimeout = errors.New("i/o timeout")
)

type netError struct {
	error
	timeout, temporary bool
}

func (e *netError) Timeout() bool {
	return e.timeout
}

func (e *netError) Temporary() bool {
	return e.temporary
}

type BufferPacketType int

const (
	RTPBufferPacket BufferPacketType = 1

	RTCPBufferPacket BufferPacketType = 2
)

type Buffer struct {
	mutex        sync.Mutex
	data         []byte
	head, tail   int
	notify       chan struct{}
	closed       bool
	limitSize    int
	readDeadline *Deadline
}

const (
	minSize    = 2048
	cutoffSize = 128 * 1024
	maxSize    = 4 * 1024 * 1024
)

func NewBuffer() *Buffer {
	return &Buffer{
		notify:       make(chan struct{}, 1),
		readDeadline: NewDeadline(),
	}
}

func (b *Buffer) available(size int) bool {
	available := b.head - b.tail
	if available <= 0 {
		available += len(b.data)
	}

	if size+2+1 > available {
		return false
	}

	return true
}

func (b *Buffer) grow() error {
	var newSize int
	if len(b.data) < cutoffSize {
		newSize = 2 * len(b.data)
	} else {
		newSize = 5 * len(b.data) / 4
	}
	if newSize < minSize {
		newSize = minSize
	}
	if b.limitSize <= 0 && newSize > maxSize {
		newSize = maxSize
	}

	if b.limitSize > 0 && newSize > b.limitSize+1 {
		newSize = b.limitSize + 1
	}

	if newSize <= len(b.data) {
		return ErrFull
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

func (b *Buffer) Write(packet []byte) (int, error) {
	if len(packet) >= 0x10000 {
		return 0, errPacketTooBig
	}

	b.mutex.Lock()

	if b.closed {
		b.mutex.Unlock()

		return 0, io.ErrClosedPipe
	}

	if b.limitSize > 0 && b.size()+2+len(packet) > b.limitSize {
		b.mutex.Unlock()

		return 0, ErrFull
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

func (b *Buffer) Read(packet []byte) (n int, err error) {

	select {
	case <-b.readDeadline.Done():
		return 0, &netError{ErrTimeout, true, true}
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
			return 0, &netError{ErrTimeout, true, true}
		case <-b.notify:
		}
	}
}

func (b *Buffer) Close() (err error) {
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

func (b *Buffer) size() int {
	size := b.tail - b.head
	if size < 0 {
		size += len(b.data)
	}

	return size
}

func (b *Buffer) SetLimitSize(limit int) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.limitSize = limit
}

func (b *Buffer) SetReadDeadline(t time.Time) error {
	b.readDeadline.Set(t)

	return nil
}

// -----------------------------------------------------------------------------
// replaydetector (was package replaydetector)
// -----------------------------------------------------------------------------

type ReplayDetector interface {
	Check(seq uint64) (accept func() bool, ok bool)
}

func nop() bool {
	return false
}

type slidingWindowDetector struct {
	latestSeq  uint64
	maxSeq     uint64
	windowSize uint
	mask       *fixedBigInt
}

func NewReplayDetector(windowSize uint, maxSeq uint64) ReplayDetector {
	return &slidingWindowDetector{
		maxSeq:     maxSeq,
		windowSize: windowSize,
		mask:       newFixedBigInt(windowSize),
	}
}

func (d *slidingWindowDetector) Check(seq uint64) (func() bool, bool) {
	if seq > d.maxSeq {
		return nop, false
	}

	if seq <= d.latestSeq {
		if d.latestSeq >= uint64(d.windowSize)+seq {
			return nop, false
		}
		if d.mask.Bit(uint(d.latestSeq-seq)) != 0 {
			return nop, false
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

type fixedBigInt struct {
	bits    []uint64
	n       uint
	msbMask uint64
}

func newFixedBigInt(n uint) *fixedBigInt {
	chunkSize := (n + 63) / 64
	if chunkSize == 0 {
		chunkSize = 1
	}

	return &fixedBigInt{
		bits:    make([]uint64, chunkSize),
		n:       n,
		msbMask: (1 << (64 - n%64)) - 1,
	}
}

func (s *fixedBigInt) Lsh(n uint) {
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

func (s *fixedBigInt) Bit(i uint) uint {
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

func (s *fixedBigInt) SetBit(i uint) {
	if i >= s.n {
		return
	}
	chunk := i / 64
	pos := i % 64
	s.bits[chunk] |= 1 << pos
}

// -----------------------------------------------------------------------------
// stdnet (was package stdnet). The concrete Net implementation is renamed to
// StdNet to avoid colliding with the Net interface above.
// -----------------------------------------------------------------------------

type StdNet struct {
	interfaces []*Interface
}

func NewNet() (*StdNet, error) {
	n := &StdNet{}

	return n, n.UpdateInterfaces()
}

var _ Net = &StdNet{}

func (n *StdNet) UpdateInterfaces() error {
	ifs := []*Interface{}

	oifs, err := anet.Interfaces()
	if err != nil {
		return err
	}

	for i := range oifs {
		ifc := NewInterface(oifs[i])

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

func (n *StdNet) Interfaces() ([]*Interface, error) {
	return n.interfaces, nil
}

func (n *StdNet) InterfaceByIndex(index int) (*Interface, error) {
	for _, ifc := range n.interfaces {
		if ifc.Index == index {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: index=%d", ErrInterfaceNotFound, index)
}

func (n *StdNet) InterfaceByName(name string) (*Interface, error) {
	for _, ifc := range n.interfaces {
		if ifc.Name == name {
			return ifc, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrInterfaceNotFound, name)
}

func (n *StdNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

func (n *StdNet) ListenUDP(network string, locAddr *net.UDPAddr) (UDPConn, error) {
	return net.ListenUDP(network, locAddr)
}

func (n *StdNet) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

func (n *StdNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

func (n *StdNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	return net.ResolveIPAddr(network, address)
}

func (n *StdNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	return net.ResolveUDPAddr(network, address)
}

func (n *StdNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	return net.ResolveTCPAddr(network, address)
}

func (n *StdNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}

func (n *StdNet) ListenTCP(network string, laddr *net.TCPAddr) (TCPListener, error) {
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	return tcpListener{l}, nil
}

type tcpListener struct {
	*net.TCPListener
}

func (l tcpListener) AcceptTCP() (TCPConn, error) {
	return l.TCPListener.AcceptTCP()
}

type stdDialer struct {
	*net.Dialer
}

func (d stdDialer) Dial(network, address string) (net.Conn, error) {
	return d.Dialer.Dial(network, address)
}

func (n *StdNet) CreateDialer(d *net.Dialer) Dialer {
	return stdDialer{d}
}

type stdListenConfig struct {
	*net.ListenConfig
}

func (d stdListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.ListenConfig.Listen(ctx, network, address)
}

func (d stdListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return d.ListenConfig.ListenPacket(ctx, network, address)
}

func (n *StdNet) CreateListenConfig(d *net.ListenConfig) ListenConfig {
	return stdListenConfig{d}
}
