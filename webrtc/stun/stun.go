// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package stun

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/amarnathcjd/gortc/webrtc"
)

var bin = binary.BigEndian

func writeOrPanic(w io.Writer, v []byte) int {
	n, err := w.Write(v)
	if err != nil {
		panic(err)
	}

	return n
}

type transactionIDSetter struct{}

func (transactionIDSetter) AddTo(m *Message) error {
	return m.NewTransactionID()
}

var TransactionID Setter = transactionIDSetter{}

const (
	magicCookie         = 0x2112A442
	attributeHeaderSize = 4
	messageHeaderSize   = 20

	TransactionIDSize = 12
)

func IsMessage(b []byte) bool {
	return len(b) >= messageHeaderSize && bin.Uint32(b[4:8]) == magicCookie
}

type Message struct {
	Type          MessageType
	Length        uint32
	TransactionID [TransactionIDSize]byte
	Attributes    Attributes
	Raw           []byte
}

func (m *Message) AddTo(b *Message) error {
	b.TransactionID = m.TransactionID
	b.WriteTransactionID()

	return nil
}

func (m *Message) NewTransactionID() error {
	_, err := io.ReadFull(rand.Reader, m.TransactionID[:])
	if err == nil {
		m.WriteTransactionID()
	}

	return err
}

func (m *Message) String() string {
	tID := base64.StdEncoding.EncodeToString(m.TransactionID[:])
	var aInfo strings.Builder
	for k, a := range m.Attributes {
		fmt.Fprintf(&aInfo, "attr%d=%s ", k, a.Type)
	}

	return fmt.Sprintf("%s l=%d attrs=%d id=%s, %s", m.Type, m.Length, len(m.Attributes), tID, aInfo.String())
}

func (m *Message) Reset() {
	m.Raw = m.Raw[:0]
	m.Length = 0
	m.Attributes = m.Attributes[:0]
}

func (m *Message) grow(n int) {
	if len(m.Raw) >= n {
		return
	}
	if cap(m.Raw) >= n {
		m.Raw = m.Raw[:n]

		return
	}
	m.Raw = append(m.Raw, make([]byte, n-len(m.Raw))...)
}

func (m *Message) Add(attrType AttrType, val []byte) {
	allocSize := attributeHeaderSize + len(val)
	first := messageHeaderSize + int(m.Length)
	last := first + allocSize
	m.grow(last)
	m.Raw = m.Raw[:last]

	m.Length += uint32(allocSize)

	buf := m.Raw[first:last]
	value := buf[attributeHeaderSize:]
	attr := RawAttribute{
		Type: attrType,

		Length: uint16(len(val)),
		Value:  value,
	}

	bin.PutUint16(buf[0:2], attr.Type.Value())
	bin.PutUint16(buf[2:4], attr.Length)
	copy(value, val)

	if attr.Length%padding != 0 {
		bytesToAdd := nearestPaddedValueLength(len(val)) - len(val)
		last += bytesToAdd
		m.grow(last)
		buf = m.Raw[last-bytesToAdd : last]
		for i := range buf {
			buf[i] = 0
		}
		m.Raw = m.Raw[:last]

		m.Length += uint32(bytesToAdd)
	}
	m.Attributes = append(m.Attributes, attr)
	m.WriteLength()
}

func (m *Message) WriteLength() {
	m.grow(4)
	bin.PutUint16(m.Raw[2:4], uint16(m.Length))
}

func (m *Message) WriteHeader() {
	m.grow(messageHeaderSize)
	_ = m.Raw[:messageHeaderSize]

	m.WriteType()
	m.WriteLength()
	bin.PutUint32(m.Raw[4:8], magicCookie)
	copy(m.Raw[8:messageHeaderSize], m.TransactionID[:])
}

func (m *Message) WriteTransactionID() {
	copy(m.Raw[8:messageHeaderSize], m.TransactionID[:])
}

func (m *Message) WriteType() {
	m.grow(2)
	bin.PutUint16(m.Raw[0:2], m.Type.Value())
}

func (m *Message) SetType(t MessageType) {
	m.Type = t
	m.WriteType()
}

func (m *Message) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(m.Raw)

	return int64(n), err
}

func (m *Message) ReadFrom(r io.Reader) (int64, error) {
	tBuf := m.Raw[:cap(m.Raw)]
	var (
		n   int
		err error
	)
	if n, err = r.Read(tBuf); err != nil {
		return int64(n), err
	}
	m.Raw = tBuf[:n]

	return int64(n), m.Decode()
}

var ErrUnexpectedHeaderEOF = errors.New("unexpected EOF: not enough bytes to read header")

func (m *Message) Decode() error {
	buf := m.Raw
	if len(buf) < messageHeaderSize {
		return ErrUnexpectedHeaderEOF
	}
	var (
		msgType  = bin.Uint16(buf[0:2])
		size     = int(bin.Uint16(buf[2:4]))
		cookie   = bin.Uint32(buf[4:8])
		fullSize = messageHeaderSize + size
	)
	if cookie != magicCookie {
		msg := fmt.Sprintf("%x is invalid magic cookie (should be %x)", cookie, magicCookie)

		return newDecodeErr("message", "cookie", msg)
	}
	if len(buf) < fullSize {
		msg := fmt.Sprintf("buffer length %d is less than %d (expected message size)", len(buf), fullSize)

		return newAttrDecodeErr("message", msg)
	}
	m.Type.ReadValue(msgType)
	m.Length = uint32(size)
	copy(m.TransactionID[:], buf[8:messageHeaderSize])

	m.Attributes = m.Attributes[:0]
	var (
		offset = 0
		b      = buf[messageHeaderSize:fullSize]
	)
	for offset < size {
		if len(b) < attributeHeaderSize {
			msg := fmt.Sprintf("buffer length %d is less than %d (expected header size)", len(b), attributeHeaderSize)

			return newAttrDecodeErr("header", msg)
		}
		var (
			attr = RawAttribute{
				Type:   compatAttrType(bin.Uint16(b[0:2])),
				Length: bin.Uint16(b[2:4]),
			}
			aL     = int(attr.Length)
			aBuffL = nearestPaddedValueLength(aL)
		)
		b = b[attributeHeaderSize:]
		offset += attributeHeaderSize
		if len(b) < aBuffL {
			msg := fmt.Sprintf("buffer length %d is less than %d (expected value size for %s)", len(b), aBuffL, attr.Type)

			return newAttrDecodeErr("value", msg)
		}
		attr.Value = b[:aL]
		offset += aBuffL
		b = b[aBuffL:]

		m.Attributes = append(m.Attributes, attr)
	}

	return nil
}

func (m *Message) Write(tBuf []byte) (int, error) {
	m.Raw = append(m.Raw[:0], tBuf...)

	return len(tBuf), m.Decode()
}

type MessageClass byte

const (
	ClassRequest         MessageClass = 0x00
	ClassIndication      MessageClass = 0x01
	ClassSuccessResponse MessageClass = 0x02
	ClassErrorResponse   MessageClass = 0x03
)

var (
	BindingRequest = NewType(MethodBinding, ClassRequest)

	BindingSuccess = NewType(MethodBinding, ClassSuccessResponse)

	BindingError = NewType(MethodBinding, ClassErrorResponse)
)

func (c MessageClass) String() string {
	switch c {
	case ClassRequest:
		return "request"
	case ClassIndication:
		return "indication"
	case ClassSuccessResponse:
		return "success response"
	case ClassErrorResponse:
		return "error response"
	default:
		panic("unknown message class")
	}
}

type Method uint16

const (
	MethodBinding          Method = 0x001
	MethodAllocate         Method = 0x003
	MethodRefresh          Method = 0x004
	MethodSend             Method = 0x006
	MethodData             Method = 0x007
	MethodCreatePermission Method = 0x008
	MethodChannelBind      Method = 0x009
)

const (
	MethodConnect           Method = 0x000a
	MethodConnectionBind    Method = 0x000b
	MethodConnectionAttempt Method = 0x000c
)

func methodName() map[Method]string {
	return map[Method]string{
		MethodBinding:          "Binding",
		MethodAllocate:         "Allocate",
		MethodRefresh:          "Refresh",
		MethodSend:             "Send",
		MethodData:             "Data",
		MethodCreatePermission: "CreatePermission",
		MethodChannelBind:      "ChannelBind",

		MethodConnect:           "Connect",
		MethodConnectionBind:    "ConnectionBind",
		MethodConnectionAttempt: "ConnectionAttempt",
	}
}

func (m Method) String() string {
	s, ok := methodName()[m]
	if !ok {

		s = fmt.Sprintf("0x%x", uint16(m))
	}

	return s
}

type MessageType struct {
	Method Method
	Class  MessageClass
}

func (t MessageType) AddTo(m *Message) error {
	m.SetType(t)

	return nil
}

func NewType(method Method, class MessageClass) MessageType {
	return MessageType{
		Method: method,
		Class:  class,
	}
}

const (
	methodABits = 0xf
	methodBBits = 0x70
	methodDBits = 0xf80

	methodBShift = 1
	methodDShift = 2

	firstBit  = 0x1
	secondBit = 0x2

	c0Bit = firstBit
	c1Bit = secondBit

	classC0Shift = 4
	classC1Shift = 7
)

func (t MessageType) Value() uint16 {
	msg := uint16(t.Method)
	a := msg & methodABits
	b := msg & methodBBits
	d := msg & methodDBits

	msg = a + (b << methodBShift) + (d << methodDShift)

	c := uint16(t.Class)
	c0 := (c & c0Bit) << classC0Shift
	c1 := (c & c1Bit) << classC1Shift
	class := c0 + c1

	return msg + class
}

func (t *MessageType) ReadValue(v uint16) {
	c0 := (v >> classC0Shift) & c0Bit
	c1 := (v >> classC1Shift) & c1Bit
	class := c0 + c1
	t.Class = MessageClass(class)

	a := v & methodABits
	b := (v >> methodBShift) & methodBBits
	d := (v >> methodDShift) & methodDBits
	m := a + b + d
	t.Method = Method(m)
}

func (t MessageType) String() string {
	return fmt.Sprintf("%s %s", t.Method, t.Class)
}

func (m *Message) Contains(t AttrType) bool {
	for _, a := range m.Attributes {
		if a.Type == t {
			return true
		}
	}

	return false
}

type Attributes []RawAttribute

func (a Attributes) Get(t AttrType) (RawAttribute, bool) {
	for _, candidate := range a {
		if candidate.Type == t {
			return candidate, true
		}
	}

	return RawAttribute{}, false
}

type AttrType uint16

const (
	AttrMappedAddress     AttrType = 0x0001
	AttrUsername          AttrType = 0x0006
	AttrMessageIntegrity  AttrType = 0x0008
	AttrErrorCode         AttrType = 0x0009
	AttrUnknownAttributes AttrType = 0x000A
	AttrRealm             AttrType = 0x0014
	AttrNonce             AttrType = 0x0015
	AttrXORMappedAddress  AttrType = 0x0020
)

const (
	AttrSoftware        AttrType = 0x8022
	AttrAlternateServer AttrType = 0x8023
	AttrFingerprint     AttrType = 0x8028
)

const (
	AttrPriority       AttrType = 0x0024
	AttrUseCandidate   AttrType = 0x0025
	AttrICEControlled  AttrType = 0x8029
	AttrICEControlling AttrType = 0x802A
)

const (
	AttrChannelNumber      AttrType = 0x000C
	AttrLifetime           AttrType = 0x000D
	AttrXORPeerAddress     AttrType = 0x0012
	AttrData               AttrType = 0x0013
	AttrXORRelayedAddress  AttrType = 0x0016
	AttrEvenPort           AttrType = 0x0018
	AttrRequestedTransport AttrType = 0x0019
	AttrDontFragment       AttrType = 0x001A
	AttrReservationToken   AttrType = 0x0022
)

const (
	AttrChangeRequest  AttrType = 0x0003
	AttrPadding        AttrType = 0x0026
	AttrResponsePort   AttrType = 0x0027
	AttrCacheTimeout   AttrType = 0x8027
	AttrResponseOrigin AttrType = 0x802b
	AttrOtherAddress   AttrType = 0x802C
)

const (
	AttrSourceAddress  AttrType = 0x0004
	AttrChangedAddress AttrType = 0x0005
)

const (
	AttrConnectionID AttrType = 0x002a
)

const (
	AttrRequestedAddressFamily AttrType = 0x0017
)

const (
	AttrOrigin AttrType = 0x802F
)

const (
	AttrMessageIntegritySHA256 AttrType = 0x001C
	AttrPasswordAlgorithm      AttrType = 0x001D
	AttrUserhash               AttrType = 0x001E
	AttrPasswordAlgorithms     AttrType = 0x8002
	AttrAlternateDomain        AttrType = 0x8003
)

const (
	AttrDtlsInStun    AttrType = 0xC070
	AttrDtlsInStunAck AttrType = 0xC071
)

func (t AttrType) Value() uint16 {
	return uint16(t)
}

func attrNames() map[AttrType]string {
	return map[AttrType]string{
		AttrMappedAddress:          "MAPPED-ADDRESS",
		AttrUsername:               "USERNAME",
		AttrErrorCode:              "ERROR-CODE",
		AttrMessageIntegrity:       "MESSAGE-INTEGRITY",
		AttrUnknownAttributes:      "UNKNOWN-ATTRIBUTES",
		AttrRealm:                  "REALM",
		AttrNonce:                  "NONCE",
		AttrXORMappedAddress:       "XOR-MAPPED-ADDRESS",
		AttrSoftware:               "SOFTWARE",
		AttrAlternateServer:        "ALTERNATE-SERVER",
		AttrFingerprint:            "FINGERPRINT",
		AttrPriority:               "PRIORITY",
		AttrUseCandidate:           "USE-CANDIDATE",
		AttrICEControlled:          "ICE-CONTROLLED",
		AttrICEControlling:         "ICE-CONTROLLING",
		AttrChannelNumber:          "CHANNEL-NUMBER",
		AttrLifetime:               "LIFETIME",
		AttrXORPeerAddress:         "XOR-PEER-ADDRESS",
		AttrData:                   "DATA",
		AttrXORRelayedAddress:      "XOR-RELAYED-ADDRESS",
		AttrEvenPort:               "EVEN-PORT",
		AttrRequestedTransport:     "REQUESTED-TRANSPORT",
		AttrDontFragment:           "DONT-FRAGMENT",
		AttrReservationToken:       "RESERVATION-TOKEN",
		AttrConnectionID:           "CONNECTION-ID",
		AttrRequestedAddressFamily: "REQUESTED-ADDRESS-FAMILY",
		AttrMessageIntegritySHA256: "MESSAGE-INTEGRITY-SHA256",
		AttrPasswordAlgorithm:      "PASSWORD-ALGORITHM",
		AttrUserhash:               "USERHASH",
		AttrPasswordAlgorithms:     "PASSWORD-ALGORITHMS",
		AttrAlternateDomain:        "ALTERNATE-DOMAIN",
		AttrDtlsInStun:             "DTLS-IN-STUN",
		AttrDtlsInStunAck:          "DTLS-IN-STUN-ACKNOWLEDGEMENT",
	}
}

func (t AttrType) String() string {
	s, ok := attrNames()[t]
	if !ok {

		return fmt.Sprintf("0x%x", uint16(t))
	}

	return s
}

type RawAttribute struct {
	Type   AttrType
	Length uint16
	Value  []byte
}

func (a RawAttribute) AddTo(m *Message) error {
	m.Add(a.Type, a.Value)

	return nil
}

func (a RawAttribute) String() string {
	return fmt.Sprintf("%s: 0x%x", a.Type, a.Value)
}

var ErrAttributeNotFound = errors.New("attribute not found")

func (m *Message) Get(t AttrType) ([]byte, error) {
	v, ok := m.Attributes.Get(t)
	if !ok {
		return nil, ErrAttributeNotFound
	}

	return v.Value, nil
}

const padding = 4

func nearestPaddedValueLength(l int) int {
	n := padding * (l / padding)
	if n < l {
		n += padding
	}

	return n
}

func compatAttrType(val uint16) AttrType {
	if val == 0x8020 {
		return AttrXORMappedAddress
	}

	return AttrType(val)
}

type (
	Setter interface {
		AddTo(m *Message) error
	}

	Getter interface {
		GetFrom(m *Message) error
	}

	Checker interface {
		Check(m *Message) error
	}
)

func (m *Message) Build(setters ...Setter) error {
	m.Reset()
	m.WriteHeader()
	for _, s := range setters {
		if err := s.AddTo(m); err != nil {
			return err
		}
	}

	return nil
}

func (m *Message) Check(checkers ...Checker) error {
	for _, c := range checkers {
		if err := c.Check(m); err != nil {
			return err
		}
	}

	return nil
}

func (m *Message) Parse(getters ...Getter) error {
	for _, c := range getters {
		if err := c.GetFrom(m); err != nil {
			return err
		}
	}

	return nil
}

func Build(setters ...Setter) (*Message, error) {
	m := new(Message)
	if err := m.Build(setters...); err != nil {
		return nil, err
	}

	return m, nil
}

func CheckSize(_ AttrType, got, expected int) error {
	if got == expected {
		return nil
	}

	return ErrAttributeSizeInvalid
}

func checkHMAC(got, expected []byte) error {
	if webrtc.HMACEqual(got, expected) {
		return nil
	}

	return ErrIntegrityMismatch
}

func checkFingerprint(got, expected uint32) error {
	if got == expected {
		return nil
	}

	return ErrFingerprintMismatch
}

func CheckOverflow(_ AttrType, got, maxVal int) error {
	if got <= maxVal {
		return nil
	}

	return ErrAttributeSizeOverflow
}

type DecodeErr struct {
	Place   DecodeErrPlace
	Message string
}

func (e DecodeErr) IsInvalidCookie() bool {
	return e.Place == DecodeErrPlace{"message", "cookie"}
}

func (e DecodeErr) IsPlaceParent(p string) bool {
	return e.Place.Parent == p
}

func (e DecodeErr) IsPlaceChildren(c string) bool {
	return e.Place.Children == c
}

func (e DecodeErr) IsPlace(p DecodeErrPlace) bool {
	return e.Place == p
}

type DecodeErrPlace struct {
	Parent   string
	Children string
}

func (p DecodeErrPlace) String() string {
	return p.Parent + "/" + p.Children
}

func (e DecodeErr) Error() string {
	return "BadFormat for " + e.Place.String() + ": " + e.Message
}

func newDecodeErr(parent, children, message string) *DecodeErr {
	return &DecodeErr{
		Place:   DecodeErrPlace{Parent: parent, Children: children},
		Message: message,
	}
}

func newAttrDecodeErr(children, message string) *DecodeErr {
	return newDecodeErr("attribute", children, message)
}

var ErrAttributeSizeInvalid = errors.New("attribute size is invalid")

var ErrAttributeSizeOverflow = errors.New("attribute size overflow")

var errInvalidErrorCode = errors.New("invalid ErrorCode")

type ErrorCodeAttribute struct {
	Code   ErrorCode
	Reason []byte
}

func (c ErrorCodeAttribute) String() string {
	return fmt.Sprintf("%d: %s", c.Code, c.Reason)
}

const (
	errorCodeReasonStart = 4
	errorCodeClassByte   = 2
	errorCodeNumberByte  = 3
	errorCodeClassMax    = 255
	errorCodeReasonMaxB  = 763
	errorCodeModulo      = 100
)

func (c ErrorCodeAttribute) AddTo(msg *Message) error {
	value := make([]byte, 0, errorCodeReasonStart+errorCodeReasonMaxB)
	if err := CheckOverflow(AttrErrorCode,
		len(c.Reason)+errorCodeReasonStart,
		errorCodeReasonMaxB+errorCodeReasonStart,
	); err != nil {
		return err
	}
	class := int(c.Code) / errorCodeModulo
	number := int(c.Code) % errorCodeModulo
	if class < 0 || class > errorCodeClassMax || number < 0 {
		return errInvalidErrorCode
	}
	value = value[:errorCodeReasonStart+len(c.Reason)]
	value[errorCodeClassByte] = byte(class)
	value[errorCodeNumberByte] = byte(number)
	copy(value[errorCodeReasonStart:], c.Reason)
	msg.Add(AttrErrorCode, value)

	return nil
}

func (c *ErrorCodeAttribute) GetFrom(m *Message) error {
	value, err := m.Get(AttrErrorCode)
	if err != nil {
		return err
	}
	if len(value) < errorCodeReasonStart {
		return io.ErrUnexpectedEOF
	}
	var (
		class  = uint16(value[errorCodeClassByte])
		number = uint16(value[errorCodeNumberByte])
		code   = int(class*errorCodeModulo + number)
	)
	c.Code = ErrorCode(code)
	c.Reason = value[errorCodeReasonStart:]

	return nil
}

type ErrorCode int

var ErrNoDefaultReason = errors.New("no default reason for ErrorCode")

func (c ErrorCode) AddTo(m *Message) error {
	reason := errorReasons[c]
	if reason == nil {
		return ErrNoDefaultReason
	}
	a := &ErrorCodeAttribute{
		Code:   c,
		Reason: reason,
	}

	return a.AddTo(m)
}

const (
	CodeTryAlternate     ErrorCode = 300
	CodeBadRequest       ErrorCode = 400
	CodeUnauthorized     ErrorCode = 401
	CodeUnknownAttribute ErrorCode = 420
	CodeStaleNonce       ErrorCode = 438
	CodeRoleConflict     ErrorCode = 487
	CodeServerError      ErrorCode = 500
)

const (
	CodeForbidden             ErrorCode = 403
	CodeAllocMismatch         ErrorCode = 437
	CodeWrongCredentials      ErrorCode = 441
	CodeUnsupportedTransProto ErrorCode = 442
	CodeAllocQuotaReached     ErrorCode = 486
	CodeInsufficientCapacity  ErrorCode = 508
)

const (
	CodeConnAlreadyExists    ErrorCode = 446
	CodeConnTimeoutOrFailure ErrorCode = 447
)

const (
	CodeAddrFamilyNotSupported ErrorCode = 440
	CodePeerAddrFamilyMismatch ErrorCode = 443
)

var errorReasons = map[ErrorCode][]byte{
	CodeTryAlternate:     []byte("Try Alternate"),
	CodeBadRequest:       []byte("Bad Request"),
	CodeUnauthorized:     []byte("Unauthorized"),
	CodeUnknownAttribute: []byte("Unknown Attribute"),
	CodeStaleNonce:       []byte("Stale Nonce"),
	CodeServerError:      []byte("Server Error"),
	CodeRoleConflict:     []byte("Role Conflict"),

	CodeForbidden:             []byte("Forbidden"),
	CodeAllocMismatch:         []byte("Allocation Mismatch"),
	CodeWrongCredentials:      []byte("Wrong Credentials"),
	CodeUnsupportedTransProto: []byte("Unsupported Transport Protocol"),
	CodeAllocQuotaReached:     []byte("Allocation Quota Reached"),
	CodeInsufficientCapacity:  []byte("Insufficient Capacity"),

	CodeConnAlreadyExists:    []byte("Connection Already Exists"),
	CodeConnTimeoutOrFailure: []byte("Connection Timeout or Failure"),

	CodeAddrFamilyNotSupported: []byte("Address Family not Supported"),
	CodePeerAddrFamilyMismatch: []byte("Peer Address Family Mismatch"),
}

type FingerprintAttr struct{}

var ErrFingerprintMismatch = errors.New("fingerprint check failed")

var Fingerprint FingerprintAttr

const fingerprintXORValue uint32 = 0x5354554e

const fingerprintSize = 4

func FingerprintValue(b []byte) uint32 {
	return crc32.ChecksumIEEE(b) ^ fingerprintXORValue
}

func (FingerprintAttr) AddTo(m *Message) error {
	l := m.Length

	m.Length += fingerprintSize + attributeHeaderSize
	m.WriteLength()
	b := make([]byte, fingerprintSize)
	val := FingerprintValue(m.Raw)
	bin.PutUint32(b, val)
	m.Length = l
	m.Add(AttrFingerprint, b)

	return nil
}

func (FingerprintAttr) Check(m *Message) error {
	b, err := m.Get(AttrFingerprint)
	if err != nil {
		return err
	}
	if err = CheckSize(AttrFingerprint, len(b), fingerprintSize); err != nil {
		return err
	}
	val := bin.Uint32(b)
	attrStart := len(m.Raw) - (fingerprintSize + attributeHeaderSize)
	expected := FingerprintValue(m.Raw[:attrStart])

	return checkFingerprint(val, expected)
}

func NewShortTermIntegrity(password string) MessageIntegrity {
	return MessageIntegrity(password)
}

type MessageIntegrity []byte

func newHMAC(key, message, buf []byte) []byte {
	mac := webrtc.AcquireSHA1(key)
	writeOrPanic(mac, message)
	defer webrtc.PutSHA1(mac)

	return mac.Sum(buf)
}

func (i MessageIntegrity) String() string {
	return fmt.Sprintf("KEY: 0x%x", []byte(i))
}

const messageIntegritySize = 20

var ErrFingerprintBeforeIntegrity = errors.New("FINGERPRINT before MESSAGE-INTEGRITY attribute")

func (i MessageIntegrity) AddTo(msg *Message) error {
	for _, a := range msg.Attributes {

		if a.Type == AttrFingerprint {
			return ErrFingerprintBeforeIntegrity
		}
	}

	length := msg.Length

	msg.Length += messageIntegritySize + attributeHeaderSize
	msg.WriteLength()
	v := newHMAC(i, msg.Raw, msg.Raw[len(msg.Raw):])
	msg.Length = length

	vBuf := make([]byte, sha1.Size)
	copy(vBuf, v)

	msg.Add(AttrMessageIntegrity, vBuf)

	return nil
}

var ErrIntegrityMismatch = errors.New("integrity check failed")

func (i MessageIntegrity) Check(msg *Message) error {
	val, err := msg.Get(AttrMessageIntegrity)
	if err != nil {
		return err
	}

	var (
		length         = msg.Length
		afterIntegrity = false
		sizeReduced    int
	)
	for _, a := range msg.Attributes {
		if afterIntegrity {
			sizeReduced += nearestPaddedValueLength(int(a.Length))
			sizeReduced += attributeHeaderSize
		}
		if a.Type == AttrMessageIntegrity {
			afterIntegrity = true
		}
	}
	msg.Length -= uint32(sizeReduced)
	msg.WriteLength()

	startOfHMAC := messageHeaderSize + msg.Length - (attributeHeaderSize + messageIntegritySize)
	b := msg.Raw[:startOfHMAC]
	expected := newHMAC(i, b, msg.Raw[len(msg.Raw):])
	msg.Length = length
	msg.WriteLength()

	return checkHMAC(val, expected)
}

func NewUsername(username string) Username {
	return Username(username)
}

type Username []byte

func (u Username) String() string {
	return string(u)
}

const maxUsernameB = 513

func (u Username) AddTo(m *Message) error {
	return TextAttribute(u).AddToAs(m, AttrUsername, maxUsernameB)
}

func (u *Username) GetFrom(m *Message) error {
	return (*TextAttribute)(u).GetFromAs(m, AttrUsername)
}

type TextAttribute []byte

func (v TextAttribute) AddToAs(m *Message, t AttrType, maxLen int) error {
	if err := CheckOverflow(t, len(v), maxLen); err != nil {
		return err
	}
	m.Add(t, v)

	return nil
}

func (v *TextAttribute) GetFromAs(m *Message, t AttrType) error {
	a, err := m.Get(t)
	if err != nil {
		return err
	}
	*v = a

	return nil
}

var (
	ErrUnknownType = errors.New("Unknown")

	ErrSchemeType = errors.New("unknown scheme type")

	ErrSTUNQuery = errors.New("queries not supported in stun address")

	ErrInvalidQuery = errors.New("invalid query")

	ErrHost = errors.New("invalid hostname")

	ErrPort = errors.New("invalid port")

	ErrProtoType = errors.New("invalid transport protocol type")
)

type SchemeType int

const (
	SchemeTypeUnknown SchemeType = iota

	SchemeTypeSTUN

	SchemeTypeSTUNS

	SchemeTypeTURN

	SchemeTypeTURNS
)

func NewSchemeType(raw string) SchemeType {
	switch raw {
	case "stun":
		return SchemeTypeSTUN
	case "stuns":
		return SchemeTypeSTUNS
	case "turn":
		return SchemeTypeTURN
	case "turns":
		return SchemeTypeTURNS
	default:
		return SchemeTypeUnknown
	}
}

func (t SchemeType) String() string {
	switch t {
	case SchemeTypeSTUN:
		return "stun"
	case SchemeTypeSTUNS:
		return "stuns"
	case SchemeTypeTURN:
		return "turn"
	case SchemeTypeTURNS:
		return "turns"
	default:
		return ErrUnknownType.Error()
	}
}

type ProtoType int

const (
	ProtoTypeUnknown ProtoType = iota

	ProtoTypeUDP

	ProtoTypeTCP
)

func NewProtoType(raw string) ProtoType {
	switch raw {
	case "udp":
		return ProtoTypeUDP
	case "tcp":
		return ProtoTypeTCP
	default:
		return ProtoTypeUnknown
	}
}

func (t ProtoType) String() string {
	switch t {
	case ProtoTypeUDP:
		return "udp"
	case ProtoTypeTCP:
		return "tcp"
	default:
		return ErrUnknownType.Error()
	}
}

type URI struct {
	Scheme   SchemeType
	Host     string
	Port     int
	Username string
	Password string
	Proto    ProtoType
}

func ParseURI(raw string) (*URI, error) {
	rawParts, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	var uri URI
	uri.Scheme = NewSchemeType(rawParts.Scheme)
	if uri.Scheme == SchemeTypeUnknown {
		return nil, ErrSchemeType
	}

	var rawPort string
	if uri.Host, rawPort, err = net.SplitHostPort(rawParts.Opaque); err != nil {
		var e *net.AddrError
		if errors.As(err, &e) {
			if e.Err == "missing port in address" {
				nextRawURL := uri.Scheme.String() + ":" + rawParts.Opaque
				switch uri.Scheme {
				case SchemeTypeSTUN, SchemeTypeTURN:
					nextRawURL += ":3478"
					if rawParts.RawQuery != "" {
						nextRawURL += "?" + rawParts.RawQuery
					}

					return ParseURI(nextRawURL)
				case SchemeTypeSTUNS, SchemeTypeTURNS:
					nextRawURL += ":5349"
					if rawParts.RawQuery != "" {
						nextRawURL += "?" + rawParts.RawQuery
					}

					return ParseURI(nextRawURL)
				default:
					return nil, ErrSchemeType
				}
			}
		}

		return nil, err
	}

	if uri.Host == "" {
		return nil, ErrHost
	}

	if uri.Port, err = strconv.Atoi(rawPort); err != nil {
		return nil, ErrPort
	}

	switch uri.Scheme {
	case SchemeTypeSTUN:
		qArgs, err := url.ParseQuery(rawParts.RawQuery)
		if err != nil || len(qArgs) > 0 {
			return nil, ErrSTUNQuery
		}
		uri.Proto = ProtoTypeUDP
	case SchemeTypeSTUNS:
		qArgs, err := url.ParseQuery(rawParts.RawQuery)
		if err != nil || len(qArgs) > 0 {
			return nil, ErrSTUNQuery
		}
		uri.Proto = ProtoTypeTCP
	case SchemeTypeTURN:
		proto, err := parseProto(rawParts.RawQuery)
		if err != nil {
			return nil, err
		}

		uri.Proto = proto
		if uri.Proto == ProtoTypeUnknown {
			uri.Proto = ProtoTypeUDP
		}
	case SchemeTypeTURNS:
		proto, err := parseProto(rawParts.RawQuery)
		if err != nil {
			return nil, err
		}

		uri.Proto = proto
		if uri.Proto == ProtoTypeUnknown {
			uri.Proto = ProtoTypeTCP
		}

	case SchemeTypeUnknown:
	}

	return &uri, nil
}

func parseProto(raw string) (ProtoType, error) {
	qArgs, err := url.ParseQuery(raw)
	if err != nil || len(qArgs) > 1 {
		return ProtoTypeUnknown, ErrInvalidQuery
	}

	var proto ProtoType
	if rawProto := qArgs.Get("transport"); rawProto != "" {
		if proto = NewProtoType(rawProto); proto == ProtoTypeUnknown {
			return ProtoTypeUnknown, ErrProtoType
		}

		return proto, nil
	}

	if len(qArgs) > 0 {
		return ProtoTypeUnknown, ErrInvalidQuery
	}

	return proto, nil
}

func (u URI) String() string {
	rawURL := u.Scheme.String() + ":" + net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
	if u.Scheme == SchemeTypeTURN || u.Scheme == SchemeTypeTURNS {
		rawURL += "?transport=" + u.Proto.String()
	}

	return rawURL
}

const (
	familyIPv4 uint16 = 0x01
	familyIPv6 uint16 = 0x02
)

type XORMappedAddress struct {
	IP   net.IP
	Port int
}

func (a XORMappedAddress) String() string {
	return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
}

func isIPv4(ip net.IP) bool {

	return isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff
}

func isZeros(p net.IP) bool {
	for i := range p {
		if p[i] != 0 {
			return false
		}
	}

	return true
}

var ErrBadIPLength = errors.New("invalid length of IP value")

func (a XORMappedAddress) AddToAs(msg *Message, attr AttrType) error {
	var (
		family = familyIPv4
		ip     = a.IP
	)
	if len(a.IP) == net.IPv6len {
		if isIPv4(ip) {
			ip = ip[12:16]
		} else {
			family = familyIPv6
		}
	} else if len(ip) != net.IPv4len {
		return ErrBadIPLength
	}
	value := make([]byte, 32+128)
	value[0] = 0
	xorValue := make([]byte, net.IPv6len)
	copy(xorValue[4:], msg.TransactionID[:])
	bin.PutUint32(xorValue[0:4], magicCookie)
	bin.PutUint16(value[0:2], family)
	bin.PutUint16(value[2:4], uint16(a.Port^magicCookie>>16))
	webrtc.TransportXorBytes(value[4:4+len(ip)], ip, xorValue)
	msg.Add(attr, value[:4+len(ip)])

	return nil
}

func (a XORMappedAddress) AddTo(m *Message) error {
	return a.AddToAs(m, AttrXORMappedAddress)
}

func (a *XORMappedAddress) GetFromAs(msg *Message, attr AttrType) error {
	value, err := msg.Get(attr)
	if err != nil {
		return err
	}
	family := bin.Uint16(value[0:2])
	if family != familyIPv6 && family != familyIPv4 {
		return newDecodeErr("xor-mapped address", "family",
			fmt.Sprintf("bad value %d", family),
		)
	}
	ipLen := net.IPv4len
	if family == familyIPv6 {
		ipLen = net.IPv6len
	}

	if len(a.IP) < ipLen {
		a.IP = make(net.IP, ipLen)
	} else {
		a.IP = a.IP[:ipLen]
		for i := range a.IP {
			a.IP[i] = 0
		}
	}

	if len(value) <= 4 {
		return io.ErrUnexpectedEOF
	}
	if err := CheckOverflow(attr, len(value[4:]), len(a.IP)); err != nil {
		return err
	}
	a.Port = int(bin.Uint16(value[2:4])) ^ (magicCookie >> 16)
	xorValue := make([]byte, 4+TransactionIDSize)
	bin.PutUint32(xorValue[0:4], magicCookie)
	copy(xorValue[4:], msg.TransactionID[:])
	webrtc.TransportXorBytes(a.IP, value[4:], xorValue)

	return nil
}

func (a *XORMappedAddress) GetFrom(m *Message) error {
	return a.GetFromAs(m, AttrXORMappedAddress)
}
