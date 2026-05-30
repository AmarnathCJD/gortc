package webrtc

import (
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"math/big"
	mrand "math/rand"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// wsaEADDRNOTAVAIL is the Windows socket error (WSAEADDRNOTAVAIL).
const wsaEADDRNOTAVAIL syscall.Errno = 10049

// IsAddrUnavailable reports whether err is an "address not available" error,
// across Unix (EADDRNOTAVAIL) and Windows (WSAEADDRNOTAVAIL).
func IsAddrUnavailable(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	if errno == syscall.EADDRNOTAVAIL {
		return true
	}

	return runtime.GOOS == "windows" && errno == wsaEADDRNOTAVAIL
}

func NTPTimestamp(t time.Time) uint64 {
	s := (float64(t.UnixNano()) / 1000000000) + 2208988800
	integerPart := uint32(s)
	fractionalPart := uint32((s - float64(integerPart)) * 0xFFFFFFFF)

	return uint64(integerPart)<<32 | uint64(fractionalPart)
}

func NTPToTime(t uint64) time.Time {
	seconds := (t & 0xFFFFFFFF00000000) >> 32
	fractional := float64(t&0x00000000FFFFFFFF) / float64(0xFFFFFFFF)
	d := time.Duration(seconds)*time.Second + time.Duration(fractional*1e9)*time.Nanosecond

	return time.Unix(0, 0).Add(-2208988800 * time.Second).Add(d)
}

func CryptoRandString(n int, runes string) (string, error) {
	letters := []rune(runes)
	b := make([]rune, n)
	for i := range b {
		v, err := crand.Int(crand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		b[i] = letters[v.Int64()]
	}

	return string(b), nil
}

func CryptoUint64() (uint64, error) {
	var v uint64
	if err := binary.Read(crand.Reader, binary.LittleEndian, &v); err != nil {
		return 0, err
	}

	return v, nil
}

type RandGenerator interface {
	Intn(n int) int
	Uint32() uint32
	Uint64() uint64
	GenerateString(n int, runes string) string
}

type randGenerator struct {
	r  *mrand.Rand
	mu sync.Mutex
}

func NewRandGenerator() RandGenerator {
	seed, err := CryptoUint64()
	if err != nil {
		seed = uint64(time.Now().UnixNano())
	}

	return &randGenerator{r: mrand.New(mrand.NewSource(int64(seed)))}
}

func (g *randGenerator) Intn(n int) int {
	g.mu.Lock()
	v := g.r.Intn(n)
	g.mu.Unlock()

	return v
}

func (g *randGenerator) Uint32() uint32 {
	g.mu.Lock()
	v := g.r.Uint32()
	g.mu.Unlock()

	return v
}

func (g *randGenerator) Uint64() uint64 {
	g.mu.Lock()
	v := g.r.Uint64()
	g.mu.Unlock()

	return v
}

func (g *randGenerator) GenerateString(n int, runes string) string {
	letters := []rune(runes)
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[g.Intn(len(letters))]
	}

	return string(b)
}

const runesAlpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var globalRandGenerator = NewRandGenerator()

func RandAlphaString(n int) string {
	return globalRandGenerator.GenerateString(n, runesAlpha)
}

func RandUint32() uint32 {
	return globalRandGenerator.Uint32()
}

func JoinErrors(errs []error) error {
	filtered := []error{}
	for _, e := range errs {
		if e != nil {
			filtered = append(filtered, e)
		}
	}
	if len(filtered) == 0 {
		return nil
	}

	return multiError(filtered)
}

type multiError []error

func (me multiError) Error() string {
	var msgs []string
	for _, err := range me {
		if err != nil {
			msgs = append(msgs, err.Error())
		}
	}
	if len(msgs) == 0 {
		return "multiError must contain multiple error but is empty"
	}

	return strings.Join(msgs, "\n")
}

func (me multiError) Is(err error) bool {
	for _, e := range me {
		if errors.Is(e, err) {
			return true
		}
		if me2, ok := e.(multiError); ok {
			if me2.Is(err) {
				return true
			}
		}
	}

	return false
}

type AtomicErr struct {
	v atomic.Value
}

func (a *AtomicErr) Store(err error) {
	a.v.Store(struct{ error }{err})
}

func (a *AtomicErr) Load() error {
	err, _ := a.v.Load().(struct{ error })

	return err.error
}

func BEUint24(raw []byte) uint32 {
	if len(raw) < 3 {
		return 0
	}
	rawCopy := make([]byte, 4)
	copy(rawCopy[1:], raw)

	return binary.BigEndian.Uint32(rawCopy)
}

func PutBEUint24(out []byte, in uint32) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, in)
	copy(out, tmp[1:])
}

func PutBEUint48(out []byte, in uint64) {
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, in)
	copy(out, tmp[2:])
}

func MaxInt(a, b int) int {
	return max(a, b)
}

func AddUint48(b *cryptobyte.Builder, v uint64) {
	b.AddBytes([]byte{byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

const (
	maxSequenceNumberPlusOne = int64(65536)
	seqBreakpoint            = 32768
)

type SeqUnwrapper struct {
	init          bool
	lastUnwrapped int64
}

func seqIsNewer(value, previous uint16) bool {
	if value-previous == seqBreakpoint {
		return value > previous
	}

	return value != previous && (value-previous) < seqBreakpoint
}

func (u *SeqUnwrapper) Unwrap(i uint16) int64 {
	if !u.init {
		u.init = true
		u.lastUnwrapped = int64(i)

		return u.lastUnwrapped
	}
	lastWrapped := uint16(u.lastUnwrapped)
	delta := int64(i - lastWrapped)
	if seqIsNewer(i, lastWrapped) {
		if delta < 0 {
			delta += maxSequenceNumberPlusOne
		}
	} else if delta > 0 && u.lastUnwrapped+delta-maxSequenceNumberPlusOne >= 0 {
		delta -= maxSequenceNumberPlusOne
	}
	u.lastUnwrapped += delta

	return u.lastUnwrapped
}

type marshalable interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

type hmacHash struct {
	opad, ipad   []byte
	outer, inner hash.Hash
	marshaled    bool
}

func (h *hmacHash) Sum(in []byte) []byte {
	origLen := len(in)
	in = h.inner.Sum(in)
	if h.marshaled {
		if err := h.outer.(marshalable).UnmarshalBinary(h.opad); err != nil {
			panic(err)
		}
	} else {
		h.outer.Reset()
		h.outer.Write(h.opad)
	}
	h.outer.Write(in[origLen:])

	return h.outer.Sum(in[:origLen])
}

func (h *hmacHash) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

func (h *hmacHash) Size() int { return h.outer.Size() }

func (h *hmacHash) BlockSize() int { return h.inner.BlockSize() }

func (h *hmacHash) Reset() {
	if h.marshaled {
		if err := h.inner.(marshalable).UnmarshalBinary(h.ipad); err != nil {
			panic(err)
		}

		return
	}
	h.inner.Reset()
	h.inner.Write(h.ipad)
	marshalableInner, innerOK := h.inner.(marshalable)
	if !innerOK {
		return
	}
	marshalableOuter, outerOK := h.outer.(marshalable)
	if !outerOK {
		return
	}
	imarshal, err := marshalableInner.MarshalBinary()
	if err != nil {
		return
	}
	h.outer.Reset()
	h.outer.Write(h.opad)
	omarshal, err := marshalableOuter.MarshalBinary()
	if err != nil {
		return
	}
	h.ipad = imarshal
	h.opad = omarshal
	h.marshaled = true
}

func MakeHMAC(h func() hash.Hash, key []byte) hash.Hash {
	hm := new(hmacHash)
	hm.outer = h()
	hm.inner = h()
	blocksize := hm.inner.BlockSize()
	hm.ipad = make([]byte, blocksize)
	hm.opad = make([]byte, blocksize)
	if len(key) > blocksize {
		hm.outer.Write(key)
		key = hm.outer.Sum(nil)
	}
	copy(hm.ipad, key)
	copy(hm.opad, key)
	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36
	}
	for i := range hm.opad {
		hm.opad[i] ^= 0x5c
	}
	hm.inner.Write(hm.ipad)

	return hm
}

func HMACEqual(mac1, mac2 []byte) bool {
	return subtle.ConstantTimeCompare(mac1, mac2) == 1
}

func (h *hmacHash) resetTo(key []byte) {
	h.outer.Reset()
	h.inner.Reset()
	blocksize := h.inner.BlockSize()
	h.ipad = append(h.ipad[:0], make([]byte, blocksize)...)
	h.opad = append(h.opad[:0], make([]byte, blocksize)...)
	if len(key) > blocksize {
		h.outer.Write(key)
		key = h.outer.Sum(nil)
	}
	copy(h.ipad, key)
	copy(h.opad, key)
	for i := range h.ipad {
		h.ipad[i] ^= 0x36
	}
	for i := range h.opad {
		h.opad[i] ^= 0x5c
	}
	h.inner.Write(h.ipad)
	h.marshaled = false
}

var hmacSHA1Pool = &sync.Pool{
	New: func() any {
		return MakeHMAC(sha1.New, make([]byte, sha1.BlockSize))
	},
}

func AcquireSHA1(key []byte) hash.Hash {
	h := hmacSHA1Pool.Get().(*hmacHash)
	assertHMACSize(h, sha1.Size, sha1.BlockSize)
	h.resetTo(key)

	return h
}

func PutSHA1(h hash.Hash) {
	hm := h.(*hmacHash)
	assertHMACSize(hm, sha1.Size, sha1.BlockSize)
	hmacSHA1Pool.Put(hm)
}

func assertHMACSize(h *hmacHash, size, blocksize int) {
	if h.Size() != size || h.BlockSize() != blocksize {
		panic("BUG: hmac size invalid")
	}
}

type FMTPFormat interface {
	MimeType() string
	Match(f FMTPFormat) bool
	Parameter(key string) (string, bool)
}

func ParseFMTP(mimeType string, clockRate uint32, channels uint16, line string) FMTPFormat {
	parameters := parseFMTPParameters(line)

	switch {
	case strings.EqualFold(mimeType, "video/h264"):
		return &h264FMTP{parameters: parameters}
	case strings.EqualFold(mimeType, "video/vp9"):
		return &vp9FMTP{parameters: parameters}
	case strings.EqualFold(mimeType, "video/av1"):
		return &av1FMTP{parameters: parameters}
	default:
		return &genericFMTP{
			mimeType:   mimeType,
			clockRate:  clockRate,
			channels:   channels,
			parameters: parameters,
		}
	}
}

func ClockRateEqual(mimeType string, valA, valB uint32) bool {
	if valA == 0 {
		valA = defaultClockRate(mimeType)
	}
	if valB == 0 {
		valB = defaultClockRate(mimeType)
	}

	return valA == valB
}

func ChannelsEqual(mimeType string, valA, valB uint16) bool {
	if valA == 0 {
		valA = defaultChannels(mimeType)
	}
	if valB == 0 {
		valB = defaultChannels(mimeType)
	}
	if valA == 0 {
		valA = 1
	}
	if valB == 0 {
		valB = 1
	}

	return valA == valB
}

func defaultClockRate(mimeType string) uint32 {
	defaults := map[string]uint32{
		"audio/opus": 48000,
		"audio/pcmu": 8000,
		"audio/pcma": 8000,
	}
	if def, ok := defaults[strings.ToLower(mimeType)]; ok {
		return def
	}

	return 90000
}

func defaultChannels(mimeType string) uint16 {
	defaults := map[string]uint16{
		"audio/opus": 2,
	}
	if def, ok := defaults[strings.ToLower(mimeType)]; ok {
		return def
	}

	return 0
}

func parseFMTPParameters(line string) map[string]string {
	parameters := make(map[string]string)
	for p := range strings.SplitSeq(line, ";") {
		pp := strings.SplitN(strings.TrimSpace(p), "=", 2)
		key := strings.ToLower(pp[0])
		var value string
		if len(pp) > 1 {
			value = pp[1]
		}
		parameters[key] = value
	}

	return parameters
}

func fmtpParamsEqual(valA, valB map[string]string) bool {
	for k, v := range valA {
		if vb, ok := valB[k]; ok && !strings.EqualFold(vb, v) {
			return false
		}
	}
	for k, v := range valB {
		if va, ok := valA[k]; ok && !strings.EqualFold(va, v) {
			return false
		}
	}

	return true
}

func profileLevelIDMatches(a, b string) bool {
	aa, err := hex.DecodeString(a)
	if err != nil || len(aa) < 2 {
		return false
	}
	bb, err := hex.DecodeString(b)
	if err != nil || len(bb) < 2 {
		return false
	}

	return aa[0] == bb[0] && aa[1] == bb[1]
}

type genericFMTP struct {
	mimeType   string
	clockRate  uint32
	channels   uint16
	parameters map[string]string
}

func (g *genericFMTP) MimeType() string { return g.mimeType }

func (g *genericFMTP) Match(b FMTPFormat) bool {
	fmtp, ok := b.(*genericFMTP)
	if !ok {
		return false
	}

	return strings.EqualFold(g.mimeType, fmtp.MimeType()) &&
		ClockRateEqual(g.mimeType, g.clockRate, fmtp.clockRate) &&
		ChannelsEqual(g.mimeType, g.channels, fmtp.channels) &&
		fmtpParamsEqual(g.parameters, fmtp.parameters)
}

func (g *genericFMTP) Parameter(key string) (string, bool) {
	v, ok := g.parameters[key]

	return v, ok
}

type h264FMTP struct {
	parameters map[string]string
}

func (h *h264FMTP) MimeType() string { return "video/h264" }

func (h *h264FMTP) Match(b FMTPFormat) bool {
	fmtp, ok := b.(*h264FMTP)
	if !ok {
		return false
	}
	hpmode, hok := h.parameters["packetization-mode"]
	if !hok {
		return false
	}
	cpmode, cok := fmtp.parameters["packetization-mode"]
	if !cok {
		return false
	}
	if hpmode != cpmode {
		return false
	}
	hplid, hok := h.parameters["profile-level-id"]
	if !hok {
		return false
	}
	cplid, cok := fmtp.parameters["profile-level-id"]
	if !cok {
		return false
	}

	return profileLevelIDMatches(hplid, cplid)
}

func (h *h264FMTP) Parameter(key string) (string, bool) {
	v, ok := h.parameters[key]

	return v, ok
}

type vp9FMTP struct {
	parameters map[string]string
}

func (h *vp9FMTP) MimeType() string { return "video/vp9" }

func (h *vp9FMTP) Match(b FMTPFormat) bool {
	c, ok := b.(*vp9FMTP)
	if !ok {
		return false
	}
	hProfileID, ok := h.parameters["profile-id"]
	if !ok {
		hProfileID = "0"
	}
	cProfileID, ok := c.parameters["profile-id"]
	if !ok {
		cProfileID = "0"
	}

	return hProfileID == cProfileID
}

func (h *vp9FMTP) Parameter(key string) (string, bool) {
	v, ok := h.parameters[key]

	return v, ok
}

type av1FMTP struct {
	parameters map[string]string
}

func (h *av1FMTP) MimeType() string { return "video/av1" }

func (h *av1FMTP) Match(b FMTPFormat) bool {
	c, ok := b.(*av1FMTP)
	if !ok {
		return false
	}
	hProfile, ok := h.parameters["profile"]
	if !ok {
		hProfile = "0"
	}
	cProfile, ok := c.parameters["profile"]
	if !ok {
		cProfile = "0"
	}

	return hProfile == cProfile
}

func (h *av1FMTP) Parameter(key string) (string, bool) {
	v, ok := h.parameters[key]

	return v, ok
}
