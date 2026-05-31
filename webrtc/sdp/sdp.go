// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package sdp

import (
	"errors"
	"fmt"
	"io"
	"github.com/amarnathcjd/gortc/webrtc"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var errDocumentStart = errors.New("already on document start")

type syntaxError struct {
	s string
	i int
}

func (e syntaxError) Error() string {
	if e.i < 0 {
		e.i = 0
	}

	return fmt.Sprintf("sdp: syntax error at pos %d: %s", e.i, strconv.QuoteToASCII(e.s[e.i:e.i+1]))
}

type baseLexer struct {
	value string
	pos   int
}

func (l baseLexer) syntaxError() error {
	return syntaxError{s: l.value, i: l.pos - 1}
}

func (l *baseLexer) unreadByte() error {
	if l.pos <= 0 {
		return errDocumentStart
	}
	l.pos--

	return nil
}

func (l *baseLexer) readByte() (byte, error) {
	if l.pos >= len(l.value) {
		return byte(0), io.EOF
	}
	ch := l.value[l.pos]
	l.pos++

	return ch, nil
}

func (l *baseLexer) nextLine() error {
	for {
		ch, err := l.readByte()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		if !isNewline(ch) {
			return l.unreadByte()
		}
	}
}

func (l *baseLexer) readWhitespace() error {
	for {
		ch, err := l.readByte()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		if !isWhitespace(ch) {
			return l.unreadByte()
		}
	}
}

func (l *baseLexer) readUint64Field() (i uint64, err error) {
	for {
		ch, err := l.readByte()
		if errors.Is(err, io.EOF) && i > 0 {
			break
		} else if err != nil {
			return i, err
		}

		if isNewline(ch) {
			if err := l.unreadByte(); err != nil {
				return i, err
			}

			break
		}

		if isWhitespace(ch) {
			if err := l.readWhitespace(); err != nil {
				return i, err
			}

			break
		}

		switch ch {
		case '0':
			i *= 10
		case '1':
			i = i*10 + 1
		case '2':
			i = i*10 + 2
		case '3':
			i = i*10 + 3
		case '4':
			i = i*10 + 4
		case '5':
			i = i*10 + 5
		case '6':
			i = i*10 + 6
		case '7':
			i = i*10 + 7
		case '8':
			i = i*10 + 8
		case '9':
			i = i*10 + 9
		default:
			return i, l.syntaxError()
		}
	}

	return i, nil
}

func (l *baseLexer) readField() (string, error) {
	start := l.pos
	var stop int
	for {
		stop = l.pos
		ch, err := l.readByte()
		if errors.Is(err, io.EOF) && stop > start {
			break
		} else if err != nil {
			return "", err
		}

		if isNewline(ch) {
			if err := l.unreadByte(); err != nil {
				return "", err
			}

			break
		}

		if isWhitespace(ch) {
			if err := l.readWhitespace(); err != nil {
				return "", err
			}

			break
		}
	}

	return l.value[start:stop], nil
}

func (l *lexer) readRequiredField() (string, error) {
	field, err := l.readField()
	if err != nil {
		return "", err
	}

	if field == "" {
		return "", errFieldMissing
	}

	return field, nil
}

func (l *baseLexer) readLine() (string, error) {
	start := l.pos
	trim := 1
	for {
		ch, err := l.readByte()
		if err != nil {
			return "", err
		}
		if ch == '\r' {
			trim++
		}
		if ch == '\n' {
			return l.value[start : l.pos-trim], nil
		}
	}
}

func (l *baseLexer) readType() (byte, error) {
	for {
		firstByte, err := l.readByte()
		if err != nil {
			return 0, err
		}

		if isNewline(firstByte) {
			continue
		}

		secondByte, err := l.readByte()
		if err != nil {
			return 0, err
		}

		if secondByte != '=' {
			return firstByte, l.syntaxError()
		}

		return firstByte, nil
	}
}

func isNewline(ch byte) bool { return ch == '\n' || ch == '\r' }

func isWhitespace(ch byte) bool { return ch == ' ' || ch == '\t' }

func anyOf(element string, data ...string) bool {
	return slices.Contains(data, element)
}

type Information string

func (i Information) String() string {
	return stringFromMarshal(i.marshalInto, i.marshalSize)
}

func (i Information) marshalInto(b []byte) []byte {
	return append(b, i...)
}

func (i Information) marshalSize() (size int) {
	return len(i)
}

type ConnectionInformation struct {
	NetworkType string
	AddressType string
	Address     *Address
}

func (c ConnectionInformation) String() string {
	return stringFromMarshal(c.marshalInto, c.marshalSize)
}

func (c ConnectionInformation) marshalInto(b []byte) []byte {
	b = append(append(b, c.NetworkType...), ' ')
	b = append(b, c.AddressType...)

	if c.Address != nil {
		b = append(b, ' ')
		b = c.Address.marshalInto(b)
	}

	return b
}

func (c ConnectionInformation) marshalSize() (size int) {
	size = len(c.NetworkType)
	size += 1 + len(c.AddressType)
	if c.Address != nil {
		size += 1 + c.Address.marshalSize()
	}

	return
}

type Address struct {
	Address string
	TTL     *int
	Range   *int
}

func (c *Address) String() string {
	return stringFromMarshal(c.marshalInto, c.marshalSize)
}

func (c *Address) marshalInto(b []byte) []byte {
	b = append(b, c.Address...)
	if c.TTL != nil {
		b = append(b, '/')
		b = strconv.AppendInt(b, int64(*c.TTL), 10)
	}
	if c.Range != nil {
		b = append(b, '/')
		b = strconv.AppendInt(b, int64(*c.Range), 10)
	}

	return b
}

func (c Address) marshalSize() (size int) {
	size = len(c.Address)
	if c.TTL != nil {
		size += 1 + lenUint(uint64(*c.TTL))
	}
	if c.Range != nil {
		size += 1 + lenUint(uint64(*c.Range))
	}

	return
}

type Bandwidth struct {
	Experimental bool
	Type         string
	Bandwidth    uint64
}

func (b Bandwidth) String() string {
	return stringFromMarshal(b.marshalInto, b.marshalSize)
}

func (b Bandwidth) marshalInto(d []byte) []byte {
	if b.Experimental {
		d = append(d, "X-"...)
	}
	d = append(append(d, b.Type...), ':')

	return strconv.AppendUint(d, b.Bandwidth, 10)
}

func (b Bandwidth) marshalSize() (size int) {
	if b.Experimental {
		size += 2
	}

	size += len(b.Type) + 1 + lenUint(b.Bandwidth)

	return
}

type EncryptionKey string

func (e EncryptionKey) String() string {
	return stringFromMarshal(e.marshalInto, e.marshalSize)
}

func (e EncryptionKey) marshalInto(b []byte) []byte {
	return append(b, e...)
}

func (e EncryptionKey) marshalSize() (size int) {
	return len(e)
}

type Attribute struct {
	Key   string
	Value string
}

func NewPropertyAttribute(key string) Attribute {
	return Attribute{
		Key: key,
	}
}

func NewAttribute(key, value string) Attribute {
	return Attribute{
		Key:   key,
		Value: value,
	}
}

func (a Attribute) String() string {
	return stringFromMarshal(a.marshalInto, a.marshalSize)
}

func (a Attribute) marshalInto(b []byte) []byte {
	b = append(b, a.Key...)
	if len(a.Value) > 0 {
		b = append(append(b, ':'), a.Value...)
	}

	return b
}

func (a Attribute) marshalSize() (size int) {
	size = len(a.Key)
	if len(a.Value) > 0 {
		size += 1 + len(a.Value)
	}

	return size
}

func (a Attribute) IsICECandidate() bool {
	return a.Key == "candidate"
}

type Direction int

const (
	DirectionSendRecv Direction = iota + 1

	DirectionSendOnly

	DirectionRecvOnly

	DirectionInactive
)

const (
	directionSendRecvStr = "sendrecv"
	directionSendOnlyStr = "sendonly"
	directionRecvOnlyStr = "recvonly"
	directionInactiveStr = "inactive"
	directionUnknownStr  = ""
)

var errDirectionString = errors.New("invalid direction string")

func NewDirection(raw string) (Direction, error) {
	switch raw {
	case directionSendRecvStr:
		return DirectionSendRecv, nil
	case directionSendOnlyStr:
		return DirectionSendOnly, nil
	case directionRecvOnlyStr:
		return DirectionRecvOnly, nil
	case directionInactiveStr:
		return DirectionInactive, nil
	default:
		return Direction(unknown), errDirectionString
	}
}

func (t Direction) String() string {
	switch t {
	case DirectionSendRecv:
		return directionSendRecvStr
	case DirectionSendOnly:
		return directionSendOnlyStr
	case DirectionRecvOnly:
		return directionRecvOnlyStr
	case DirectionInactive:
		return directionInactiveStr
	default:
		return directionUnknownStr
	}
}

const (
	DefExtMapValueABSSendTime     = 1
	DefExtMapValueTransportCC     = 2
	DefExtMapValueSDESMid         = 3
	DefExtMapValueSDESRTPStreamID = 4

	ABSSendTimeURI           = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
	TransportCCURI           = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
	SDESMidURI               = "urn:ietf:params:rtp-hdrext:sdes:mid"
	SDESRTPStreamIDURI       = "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
	SDESRepairRTPStreamIDURI = "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id"
	AudioLevelURI            = "urn:ietf:params:rtp-hdrext:ssrc-audio-level"
)

type ExtMap struct {
	Value     int
	Direction Direction
	URI       *url.URL
	ExtAttr   *string
}

func (e *ExtMap) Clone() Attribute {
	return Attribute{Key: "extmap", Value: e.string()}
}

func (e *ExtMap) Unmarshal(raw string) error {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: %v", errSyntaxError, raw)
	}

	fields := strings.Fields(parts[1])
	if len(fields) < 2 {
		return fmt.Errorf("%w: %v", errSyntaxError, raw)
	}

	valdir := strings.Split(fields[0], "/")
	value, err := strconv.ParseInt(valdir[0], 10, 64)
	if (value < 1) || (value > 246) {
		return fmt.Errorf("%w: %v -- extmap key must be in the range 1-256", errSyntaxError, valdir[0])
	}
	if err != nil {
		return fmt.Errorf("%w: %v", errSyntaxError, valdir[0])
	}

	var direction Direction
	if len(valdir) == 2 {
		direction, err = NewDirection(valdir[1])
		if err != nil {
			return err
		}
	}

	uri, err := url.Parse(fields[1])
	if err != nil {
		return err
	}

	if len(fields) == 3 {
		tmp := fields[2]
		e.ExtAttr = &tmp
	}

	e.Value = int(value)
	e.Direction = direction
	e.URI = uri

	return nil
}

func (e *ExtMap) Marshal() string {
	return e.Name() + ":" + e.string()
}

func (e *ExtMap) string() string {
	output := fmt.Sprintf("%d", e.Value)
	dirstring := e.Direction.String()
	if dirstring != directionUnknownStr {
		output += "/" + dirstring
	}

	if e.URI != nil {
		output += " " + e.URI.String()
	}

	if e.ExtAttr != nil {
		output += " " + *e.ExtAttr
	}

	return output
}

func (e *ExtMap) Name() string {
	return "extmap"
}

const (
	AttrKeyCandidate        = "candidate"
	AttrKeyEndOfCandidates  = "end-of-candidates"
	AttrKeyIdentity         = "identity"
	AttrKeyGroup            = "group"
	AttrKeySSRC             = "ssrc"
	AttrKeySSRCGroup        = "ssrc-group"
	AttrKeyMsid             = "msid"
	AttrKeyMsidSemantic     = "msid-semantic"
	AttrKeyConnectionSetup  = "setup"
	AttrKeyMID              = "mid"
	AttrKeyICELite          = "ice-lite"
	AttrKeyICEOptions       = "ice-options"
	AttrKeyRTCPMux          = "rtcp-mux"
	AttrKeyRTCPRsize        = "rtcp-rsize"
	AttrKeyInactive         = "inactive"
	AttrKeyRecvOnly         = "recvonly"
	AttrKeySendOnly         = "sendonly"
	AttrKeySendRecv         = "sendrecv"
	AttrKeyExtMap           = "extmap"
	AttrKeyExtMapAllowMixed = "extmap-allow-mixed"
	AttrKeyCryptex          = "cryptex"
)

const (
	SemanticTokenLipSynchronization     = "LS"
	SemanticTokenFlowIdentification     = "FID"
	SemanticTokenForwardErrorCorrection = "FEC"

	SemanticTokenForwardErrorCorrectionFramework = "FEC-FR"
	SemanticTokenWebRTCMediaStreams              = "WMS"
)

const (
	ExtMapValueTransportCC = 3
)

func extMapURI() map[int]string {
	return map[int]string{
		ExtMapValueTransportCC: "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
	}
}

func NewJSEPSessionDescription(identity bool) (*SessionDescription, error) {
	sid, err := newSessionID()
	if err != nil {
		return nil, err
	}
	descr := &SessionDescription{
		Version: 0,
		Origin: Origin{
			Username:       "-",
			SessionID:      sid,
			SessionVersion: uint64(time.Now().Unix()),
			NetworkType:    "IN",
			AddressType:    "IP4",
			UnicastAddress: "0.0.0.0",
		},
		SessionName: "-",
		TimeDescriptions: []TimeDescription{
			{
				Timing: Timing{
					StartTime: 0,
					StopTime:  0,
				},
				RepeatTimes: nil,
			},
		},
		Attributes: []Attribute{},
	}

	if identity {
		descr.WithPropertyAttribute(AttrKeyIdentity)
	}

	return descr, nil
}

func (s *SessionDescription) WithPropertyAttribute(key string) *SessionDescription {
	s.Attributes = append(s.Attributes, NewPropertyAttribute(key))

	return s
}

func (s *SessionDescription) WithValueAttribute(key, value string) *SessionDescription {
	s.Attributes = append(s.Attributes, NewAttribute(key, value))

	return s
}

func (s *SessionDescription) addOrUpdateICEOption(value string) *SessionDescription {
	for i := range s.Attributes {
		if s.Attributes[i].Key == AttrKeyICEOptions {
			prefix := " "
			if s.Attributes[i].Value == "" {
				prefix = ""
			}

			s.Attributes[i].Value += prefix + value

			return s
		}
	}

	return s.WithValueAttribute(AttrKeyICEOptions, value)
}

func (s *SessionDescription) WithICETrickleAdvertised() *SessionDescription {
	return s.addOrUpdateICEOption("trickle")
}

func (s *SessionDescription) WithICERenomination() *SessionDescription {
	return s.addOrUpdateICEOption("renomination")
}

func (s *SessionDescription) WithFingerprint(algorithm, value string) *SessionDescription {
	return s.WithValueAttribute("fingerprint", algorithm+" "+value)
}

func (s *SessionDescription) WithMedia(md *MediaDescription) *SessionDescription {
	s.MediaDescriptions = append(s.MediaDescriptions, md)

	return s
}

func NewJSEPMediaDescription(codecType string, _ []string) *MediaDescription {
	return &MediaDescription{
		MediaName: MediaName{
			Media:  codecType,
			Port:   RangedPort{Value: 9},
			Protos: []string{"UDP", "TLS", "RTP", "SAVPF"},
		},
		ConnectionInformation: &ConnectionInformation{
			NetworkType: "IN",
			AddressType: "IP4",
			Address: &Address{
				Address: "0.0.0.0",
			},
		},
	}
}

func (d *MediaDescription) WithPropertyAttribute(key string) *MediaDescription {
	d.Attributes = append(d.Attributes, NewPropertyAttribute(key))

	return d
}

func (d *MediaDescription) WithValueAttribute(key, value string) *MediaDescription {
	d.Attributes = append(d.Attributes, NewAttribute(key, value))

	return d
}

func (d *MediaDescription) WithFingerprint(algorithm, value string) *MediaDescription {
	return d.WithValueAttribute("fingerprint", algorithm+" "+value)
}

func (d *MediaDescription) WithICECredentials(username, password string) *MediaDescription {
	return d.
		WithValueAttribute("ice-ufrag", username).
		WithValueAttribute("ice-pwd", password)
}

func (d *MediaDescription) WithCodec(
	payloadType uint8,
	name string,
	clockrate uint32,
	channels uint16,
	fmtp string,
) *MediaDescription {
	d.MediaName.Formats = append(d.MediaName.Formats, strconv.Itoa(int(payloadType)))
	rtpmap := fmt.Sprintf("%d %s/%d", payloadType, name, clockrate)
	if channels > 0 {
		rtpmap += fmt.Sprintf("/%d", channels)
	}
	d.WithValueAttribute("rtpmap", rtpmap)
	if fmtp != "" {
		d.WithValueAttribute("fmtp", fmt.Sprintf("%d %s", payloadType, fmtp))
	}

	return d
}

func (d *MediaDescription) WithMediaSource(ssrc uint32, cname, streamLabel, label string) *MediaDescription {
	return d.
		WithValueAttribute("ssrc", fmt.Sprintf("%d cname:%s", ssrc, cname)).
		WithValueAttribute("ssrc", fmt.Sprintf("%d msid:%s %s", ssrc, streamLabel, label)).
		WithValueAttribute("ssrc", fmt.Sprintf("%d mslabel:%s", ssrc, streamLabel)).
		WithValueAttribute("ssrc", fmt.Sprintf("%d label:%s", ssrc, label))
}

func (d *MediaDescription) WithCandidate(value string) *MediaDescription {
	return d.WithValueAttribute("candidate", value)
}

func (d *MediaDescription) WithExtMap(e ExtMap) *MediaDescription {
	return d.WithPropertyAttribute(e.Marshal())
}

func (d *MediaDescription) WithTransportCCExtMap() *MediaDescription {
	uri, _ := url.Parse(extMapURI()[ExtMapValueTransportCC])
	e := ExtMap{
		Value: ExtMapValueTransportCC,
		URI:   uri,
	}

	return d.WithExtMap(e)
}

func (s *SessionDescription) Marshal() ([]byte, error) {
	marsh := make(marshaller, 0, s.MarshalSize())

	marsh.addKeyValue("v=", s.Version.marshalInto)
	marsh.addKeyValue("o=", s.Origin.marshalInto)
	marsh.addKeyValue("s=", s.SessionName.marshalInto)

	if s.SessionInformation != nil {
		marsh.addKeyValue("i=", s.SessionInformation.marshalInto)
	}

	if s.URI != nil {
		marsh = append(marsh, "u="...)
		marsh = append(marsh, s.URI.String()...)
		marsh = append(marsh, "\r\n"...)
	}

	if s.EmailAddress != nil {
		marsh.addKeyValue("e=", s.EmailAddress.marshalInto)
	}

	if s.PhoneNumber != nil {
		marsh.addKeyValue("p=", s.PhoneNumber.marshalInto)
	}

	if s.ConnectionInformation != nil {
		marsh.addKeyValue("c=", s.ConnectionInformation.marshalInto)
	}

	for _, b := range s.Bandwidth {
		marsh.addKeyValue("b=", b.marshalInto)
	}

	for _, td := range s.TimeDescriptions {
		marsh.addKeyValue("t=", td.Timing.marshalInto)
		for _, r := range td.RepeatTimes {
			marsh.addKeyValue("r=", r.marshalInto)
		}
	}

	if len(s.TimeZones) > 0 {
		marsh = append(marsh, "z="...)
		for i, z := range s.TimeZones {
			if i > 0 {
				marsh = append(marsh, ' ')
			}
			marsh = z.marshalInto(marsh)
		}
		marsh = append(marsh, "\r\n"...)
	}

	if s.EncryptionKey != nil {
		marsh.addKeyValue("k=", s.EncryptionKey.marshalInto)
	}

	for _, a := range s.Attributes {
		marsh.addKeyValue("a=", a.marshalInto)
	}

	for _, md := range s.MediaDescriptions {
		marsh.addKeyValue("m=", md.MediaName.marshalInto)

		if md.MediaTitle != nil {
			marsh.addKeyValue("i=", md.MediaTitle.marshalInto)
		}

		if md.ConnectionInformation != nil {
			marsh.addKeyValue("c=", md.ConnectionInformation.marshalInto)
		}

		for _, b := range md.Bandwidth {
			marsh.addKeyValue("b=", b.marshalInto)
		}

		if md.EncryptionKey != nil {
			marsh.addKeyValue("k=", md.EncryptionKey.marshalInto)
		}

		for _, a := range md.Attributes {
			marsh.addKeyValue("a=", a.marshalInto)
		}
	}

	return marsh, nil
}

const lineBaseSize = 4

func (s *SessionDescription) MarshalSize() (marshalSize int) {
	marshalSize += lineBaseSize + s.Version.marshalSize()
	marshalSize += lineBaseSize + s.Origin.marshalSize()
	marshalSize += lineBaseSize + s.SessionName.marshalSize()

	if s.SessionInformation != nil {
		marshalSize += lineBaseSize + s.SessionInformation.marshalSize()
	}

	if s.URI != nil {
		marshalSize += lineBaseSize + len(s.URI.String())
	}

	if s.EmailAddress != nil {
		marshalSize += lineBaseSize + s.EmailAddress.marshalSize()
	}

	if s.PhoneNumber != nil {
		marshalSize += lineBaseSize + s.PhoneNumber.marshalSize()
	}

	if s.ConnectionInformation != nil {
		marshalSize += lineBaseSize + s.ConnectionInformation.marshalSize()
	}

	for _, b := range s.Bandwidth {
		marshalSize += lineBaseSize + b.marshalSize()
	}

	for _, td := range s.TimeDescriptions {
		marshalSize += lineBaseSize + td.Timing.marshalSize()
		for _, r := range td.RepeatTimes {
			marshalSize += lineBaseSize + r.marshalSize()
		}
	}

	if len(s.TimeZones) > 0 {
		marshalSize += lineBaseSize

		for i, z := range s.TimeZones {
			if i > 0 {
				marshalSize++
			}
			marshalSize += z.marshalSize()
		}
	}

	if s.EncryptionKey != nil {
		marshalSize += lineBaseSize + s.EncryptionKey.marshalSize()
	}

	for _, a := range s.Attributes {
		marshalSize += lineBaseSize + a.marshalSize()
	}

	for _, md := range s.MediaDescriptions {
		marshalSize += lineBaseSize + md.MediaName.marshalSize()
		if md.MediaTitle != nil {
			marshalSize += lineBaseSize + md.MediaTitle.marshalSize()
		}
		if md.ConnectionInformation != nil {
			marshalSize += lineBaseSize + md.ConnectionInformation.marshalSize()
		}

		for _, b := range md.Bandwidth {
			marshalSize += lineBaseSize + b.marshalSize()
		}

		if md.EncryptionKey != nil {
			marshalSize += lineBaseSize + md.EncryptionKey.marshalSize()
		}

		for _, a := range md.Attributes {
			marshalSize += lineBaseSize + a.marshalSize()
		}
	}

	return marshalSize
}

type marshaller []byte

func (m *marshaller) addKeyValue(key string, value func([]byte) []byte) {
	*m = append(*m, key...)
	*m = value(*m)
	*m = append(*m, "\r\n"...)
}

func lenUint(i uint64) (count int) {
	if i == 0 {
		return 1
	}

	for i != 0 {
		i /= 10
		count++
	}

	return
}

func lenInt(i int64) (count int) {
	if i < 0 {
		return lenUint(uint64(-i)) + 1
	}

	return lenUint(uint64(i))
}

func stringFromMarshal(marshalFunc func([]byte) []byte, sizeFunc func() int) string {
	return string(marshalFunc(make([]byte, 0, sizeFunc())))
}

type MediaDescription struct {
	MediaName             MediaName
	MediaTitle            *Information
	ConnectionInformation *ConnectionInformation
	Bandwidth             []Bandwidth
	EncryptionKey         *EncryptionKey
	Attributes            []Attribute
}

func (d *MediaDescription) Attribute(key string) (string, bool) {
	for _, a := range d.Attributes {
		if a.Key == key {
			return a.Value, true
		}
	}

	return "", false
}

type RangedPort struct {
	Value int
	Range *int
}

func (p *RangedPort) String() string {
	output := strconv.Itoa(p.Value)
	if p.Range != nil {
		output += "/" + strconv.Itoa(*p.Range)
	}

	return output
}

func (p RangedPort) marshalInto(b []byte) []byte {
	b = strconv.AppendInt(b, int64(p.Value), 10)
	if p.Range != nil {
		b = append(b, '/')
		b = strconv.AppendInt(b, int64(*p.Range), 10)
	}

	return b
}

func (p RangedPort) marshalSize() (size int) {
	size = lenInt(int64(p.Value))
	if p.Range != nil {
		size += 1 + lenInt(int64(*p.Range))
	}

	return
}

type MediaName struct {
	Media   string
	Port    RangedPort
	Protos  []string
	Formats []string
}

func (m MediaName) String() string {
	return stringFromMarshal(m.marshalInto, m.marshalSize)
}

func (m MediaName) marshalInto(b []byte) []byte {
	appendList := func(list []string, sep byte) {
		for i, p := range list {
			if i != 0 && i != len(list) {
				b = append(b, sep)
			}
			b = append(b, p...)
		}
	}

	b = append(append(b, m.Media...), ' ')
	b = append(m.Port.marshalInto(b), ' ')
	appendList(m.Protos, '/')
	b = append(b, ' ')
	appendList(m.Formats, ' ')

	return b
}

func (m MediaName) marshalSize() (size int) {
	listSize := func(list []string) {
		for _, p := range list {
			size += 1 + len(p)
		}
	}

	size = len(m.Media)
	size += 1 + m.Port.marshalSize()
	listSize(m.Protos)
	listSize(m.Formats)

	return size
}

type SessionDescription struct {
	Version               Version
	Origin                Origin
	SessionName           SessionName
	SessionInformation    *Information
	URI                   *url.URL
	EmailAddress          *EmailAddress
	PhoneNumber           *PhoneNumber
	ConnectionInformation *ConnectionInformation
	Bandwidth             []Bandwidth
	TimeDescriptions      []TimeDescription
	TimeZones             []TimeZone
	EncryptionKey         *EncryptionKey
	Attributes            []Attribute
	MediaDescriptions     []*MediaDescription
}

func (s *SessionDescription) Attribute(key string) (string, bool) {
	for _, a := range s.Attributes {
		if a.Key == key {
			return a.Value, true
		}
	}

	return "", false
}

type Version int

func (v Version) String() string {
	return stringFromMarshal(v.marshalInto, v.marshalSize)
}

func (v Version) marshalInto(b []byte) []byte {
	return strconv.AppendInt(b, int64(v), 10)
}

func (v Version) marshalSize() (size int) {
	return lenInt(int64(v))
}

type Origin struct {
	Username       string
	SessionID      uint64
	SessionVersion uint64
	NetworkType    string
	AddressType    string
	UnicastAddress string
}

func (o Origin) String() string {
	return stringFromMarshal(o.marshalInto, o.marshalSize)
}

func (o Origin) marshalInto(b []byte) []byte {
	b = append(append(b, o.Username...), ' ')
	b = append(strconv.AppendUint(b, o.SessionID, 10), ' ')
	b = append(strconv.AppendUint(b, o.SessionVersion, 10), ' ')
	b = append(append(b, o.NetworkType...), ' ')
	b = append(append(b, o.AddressType...), ' ')

	return append(b, o.UnicastAddress...)
}

func (o Origin) marshalSize() (size int) {
	return len(o.Username) +
		lenUint(o.SessionID) +
		lenUint(o.SessionVersion) +
		len(o.NetworkType) +
		len(o.AddressType) +
		len(o.UnicastAddress) +
		5
}

type SessionName string

func (s SessionName) String() string {
	return stringFromMarshal(s.marshalInto, s.marshalSize)
}

func (s SessionName) marshalInto(b []byte) []byte {
	return append(b, s...)
}

func (s SessionName) marshalSize() (size int) {
	return len(s)
}

type EmailAddress string

func (e EmailAddress) String() string {
	return stringFromMarshal(e.marshalInto, e.marshalSize)
}

func (e EmailAddress) marshalInto(b []byte) []byte {
	return append(b, e...)
}

func (e EmailAddress) marshalSize() (size int) {
	return len(e)
}

type PhoneNumber string

func (p PhoneNumber) String() string {
	return stringFromMarshal(p.marshalInto, p.marshalSize)
}

func (p PhoneNumber) marshalInto(b []byte) []byte {
	return append(b, p...)
}

func (p PhoneNumber) marshalSize() (size int) {
	return len(p)
}

type TimeZone struct {
	AdjustmentTime uint64
	Offset         int64
}

func (z TimeZone) String() string {
	return stringFromMarshal(z.marshalInto, z.marshalSize)
}

func (z TimeZone) marshalInto(b []byte) []byte {
	b = strconv.AppendUint(b, z.AdjustmentTime, 10)
	b = append(b, ' ')

	return strconv.AppendInt(b, z.Offset, 10)
}

func (z TimeZone) marshalSize() (size int) {
	return lenUint(z.AdjustmentTime) + 1 + lenInt(z.Offset)
}

type TimeDescription struct {
	Timing      Timing
	RepeatTimes []RepeatTime
}

type Timing struct {
	StartTime uint64
	StopTime  uint64
}

func (t Timing) String() string {
	return stringFromMarshal(t.marshalInto, t.marshalSize)
}

func (t Timing) marshalInto(b []byte) []byte {
	b = append(strconv.AppendUint(b, t.StartTime, 10), ' ')

	return strconv.AppendUint(b, t.StopTime, 10)
}

func (t Timing) marshalSize() (size int) {
	return lenUint(t.StartTime) + 1 + lenUint(t.StopTime)
}

type RepeatTime struct {
	Interval int64
	Duration int64
	Offsets  []int64
}

func (r RepeatTime) String() string {
	return stringFromMarshal(r.marshalInto, r.marshalSize)
}

func (r RepeatTime) marshalInto(b []byte) []byte {
	b = strconv.AppendInt(b, r.Interval, 10)
	b = append(b, ' ')
	b = strconv.AppendInt(b, r.Duration, 10)
	for _, value := range r.Offsets {
		b = append(b, ' ')
		b = strconv.AppendInt(b, value, 10)
	}

	return b
}

func (r RepeatTime) marshalSize() (size int) {
	size = lenInt(r.Interval)
	size += 1 + lenInt(r.Duration)
	for _, o := range r.Offsets {
		size += 1 + lenInt(o)
	}

	return
}

var (
	errSDPInvalidSyntax       = errors.New("sdp: invalid syntax")
	errSDPInvalidNumericValue = errors.New("sdp: invalid numeric value")
	errSDPInvalidValue        = errors.New("sdp: invalid value")
	errSDPInvalidPortValue    = errors.New("sdp: invalid port value")
	errSDPCacheInvalid        = errors.New("sdp: invalid cache")

	unmarshalCachePool = sync.Pool{
		New: func() any {
			return &unmarshalCache{}
		},
	}
)

func (s *SessionDescription) UnmarshalString(value string) error {
	var ok bool
	lex := new(lexer)
	if lex.cache, ok = unmarshalCachePool.Get().(*unmarshalCache); !ok {
		return errSDPCacheInvalid
	}
	defer unmarshalCachePool.Put(lex.cache)

	lex.cache.reset()
	lex.desc = s
	lex.value = value

	for state := s1; state != nil; {
		var err error
		state, err = state(lex)
		if err != nil {
			return err
		}
	}

	s.Attributes = lex.cache.cloneSessionAttributes()
	populateMediaAttributes(lex.cache, lex.desc)

	return nil
}

func (s *SessionDescription) Unmarshal(value []byte) error {
	return s.UnmarshalString(string(value))
}

func s1(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		if key == 'v' {
			return unmarshalProtocolVersion
		}

		return nil
	})
}

func s2(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		if key == 'o' {
			return unmarshalOrigin
		}

		return nil
	})
}

func s3(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		if key == 's' {
			return unmarshalSessionName
		}

		return nil
	})
}

func s4(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'i':
			return unmarshalSessionInformation
		case 'u':
			return unmarshalURI
		case 'e':
			return unmarshalEmail
		case 'p':
			return unmarshalPhone
		case 'c':
			return unmarshalSessionConnectionInformation
		case 'b':
			return unmarshalSessionBandwidth
		case 't':
			return unmarshalTiming
		}

		return nil
	})
}

func s5(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'b':
			return unmarshalSessionBandwidth
		case 't':
			return unmarshalTiming
		}

		return nil
	})
}

func s6(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'p':
			return unmarshalPhone
		case 'c':
			return unmarshalSessionConnectionInformation
		case 'b':
			return unmarshalSessionBandwidth
		case 't':
			return unmarshalTiming
		}

		return nil
	})
}

func s7(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'u':
			return unmarshalURI
		case 'e':
			return unmarshalEmail
		case 'p':
			return unmarshalPhone
		case 'c':
			return unmarshalSessionConnectionInformation
		case 'b':
			return unmarshalSessionBandwidth
		case 't':
			return unmarshalTiming
		}

		return nil
	})
}

func s8(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'c':
			return unmarshalSessionConnectionInformation
		case 'b':
			return unmarshalSessionBandwidth
		case 't':
			return unmarshalTiming
		}

		return nil
	})
}

func s9(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'z':
			return unmarshalTimeZones
		case 'k':
			return unmarshalSessionEncryptionKey
		case 'a':
			return unmarshalSessionAttribute
		case 'r':
			return unmarshalRepeatTimes
		case 't':
			return unmarshalTiming
		case 'm':
			return unmarshalMediaDescription
		}

		return nil
	})
}

func s10(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'e':
			return unmarshalEmail
		case 'p':
			return unmarshalPhone
		case 'c':
			return unmarshalSessionConnectionInformation
		case 'b':
			return unmarshalSessionBandwidth
		case 't':
			return unmarshalTiming
		}

		return nil
	})
}

func s11(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'a':
			return unmarshalSessionAttribute
		case 'm':
			return unmarshalMediaDescription
		}

		return nil
	})
}

func s12(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'a':
			return unmarshalMediaAttribute
		case 'k':
			return unmarshalMediaEncryptionKey
		case 'b':
			return unmarshalMediaBandwidth
		case 'c':
			return unmarshalMediaConnectionInformation
		case 'i':
			return unmarshalMediaTitle
		case 'm':
			return unmarshalMediaDescription
		}

		return nil
	})
}

func s13(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'a':
			return unmarshalSessionAttribute
		case 'k':
			return unmarshalSessionEncryptionKey
		case 'm':
			return unmarshalMediaDescription
		}

		return nil
	})
}

func s14(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'a':
			return unmarshalMediaAttribute
		case 'k':

			return unmarshalMediaEncryptionKey
		case 'b':

			return unmarshalMediaBandwidth
		case 'c':

			return unmarshalMediaConnectionInformation
		case 'i':

			return unmarshalMediaTitle
		case 'm':
			return unmarshalMediaDescription
		}

		return nil
	})
}

func s15(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'a':
			return unmarshalMediaAttribute
		case 'k':
			return unmarshalMediaEncryptionKey
		case 'b':
			return unmarshalMediaBandwidth
		case 'c':
			return unmarshalMediaConnectionInformation
		case 'i':

			return unmarshalMediaTitle
		case 'm':
			return unmarshalMediaDescription
		}

		return nil
	})
}

func s16(l *lexer) (stateFn, error) {
	return l.handleType(func(key byte) stateFn {
		switch key {
		case 'a':
			return unmarshalMediaAttribute
		case 'k':
			return unmarshalMediaEncryptionKey
		case 'c':
			return unmarshalMediaConnectionInformation
		case 'b':
			return unmarshalMediaBandwidth
		case 'i':

			return unmarshalMediaTitle
		case 'm':
			return unmarshalMediaDescription
		}

		return nil
	})
}

func unmarshalProtocolVersion(l *lexer) (stateFn, error) {
	version, err := l.readUint64Field()
	if err != nil {
		return nil, err
	}

	if version != 0 {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, version)
	}

	if err := l.nextLine(); err != nil {
		return nil, err
	}

	return s2, nil
}

func unmarshalOrigin(lex *lexer) (stateFn, error) {
	var err error

	lex.desc.Origin.Username, err = lex.readField()
	if err != nil {
		return nil, err
	}

	lex.desc.Origin.SessionID, err = lex.readUint64Field()
	if err != nil {
		return nil, err
	}

	lex.desc.Origin.SessionVersion, err = lex.readUint64Field()
	if err != nil {
		return nil, err
	}

	lex.desc.Origin.NetworkType, err = lex.readField()
	if err != nil {
		return nil, err
	}

	if !anyOf(lex.desc.Origin.NetworkType, "IN") {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, lex.desc.Origin.NetworkType)
	}

	err = handleAddressType(lex)
	if err != nil {
		return nil, err
	}

	if !anyOf(lex.desc.Origin.AddressType, "IP4", "IP6") {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, lex.desc.Origin.AddressType)
	}

	err = handleUnicastAddress(lex)
	if err != nil {
		return nil, err
	}

	if err := lex.nextLine(); err != nil {
		return nil, err
	}

	return s3, nil
}

func handleAddressType(lex *lexer) error {
	addressType, err := lex.readRequiredField()
	if err != nil {
		if errors.Is(err, errFieldMissing) {

			lex.desc.Origin.AddressType = "IP4"
			lex.desc.Origin.UnicastAddress = "0.0.0.0"

			return nil
		}

		return err
	}

	lex.desc.Origin.AddressType = addressType

	return nil
}

func handleUnicastAddress(lex *lexer) error {
	unicastAddress, err := lex.readRequiredField()
	if err != nil {
		if errors.Is(err, errFieldMissing) {

			if lex.desc.Origin.AddressType == "IP6" {
				lex.desc.Origin.UnicastAddress = "::"
			} else {
				lex.desc.Origin.UnicastAddress = "0.0.0.0"
			}

			return nil
		}

		return err
	}

	lex.desc.Origin.UnicastAddress = unicastAddress

	return nil
}

func unmarshalSessionName(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	l.desc.SessionName = SessionName(value)

	return s4, nil
}

func unmarshalSessionInformation(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	sessionInformation := Information(value)
	l.desc.SessionInformation = &sessionInformation

	return s7, nil
}

func unmarshalURI(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	l.desc.URI, err = url.Parse(value)
	if err != nil {
		return nil, err
	}

	return s10, nil
}

func unmarshalEmail(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	emailAddress := EmailAddress(value)
	l.desc.EmailAddress = &emailAddress

	return s6, nil
}

func unmarshalPhone(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	phoneNumber := PhoneNumber(value)
	l.desc.PhoneNumber = &phoneNumber

	return s8, nil
}

func unmarshalSessionConnectionInformation(l *lexer) (stateFn, error) {
	var err error
	l.desc.ConnectionInformation, err = l.unmarshalConnectionInformation()
	if err != nil {
		return nil, err
	}

	return s5, nil
}

func (l *lexer) unmarshalConnectionInformation() (*ConnectionInformation, error) {
	var err error
	var connInfo ConnectionInformation

	connInfo.NetworkType, err = l.readField()
	if err != nil {
		return nil, err
	}

	if !anyOf(connInfo.NetworkType, "IN") {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, connInfo.NetworkType)
	}

	connInfo.AddressType, err = l.readField()
	if err != nil {
		return nil, err
	}

	if !anyOf(connInfo.AddressType, "IP4", "IP6") {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, connInfo.AddressType)
	}

	address, err := l.readField()
	if err != nil {
		return nil, err
	}

	if address != "" {
		connInfo.Address = new(Address)
		connInfo.Address.Address = address
	}

	if err := l.nextLine(); err != nil {
		return nil, err
	}

	return &connInfo, nil
}

func unmarshalSessionBandwidth(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	bandwidth, err := unmarshalBandwidth(value)
	if err != nil {
		return nil, fmt.Errorf("%w `b=%v`", errSDPInvalidValue, value)
	}
	l.desc.Bandwidth = append(l.desc.Bandwidth, *bandwidth)

	return s5, nil
}

func unmarshalBandwidth(value string) (*Bandwidth, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w `b=%v`", errSDPInvalidValue, parts)
	}

	experimental := strings.HasPrefix(parts[0], "X-")
	if experimental {
		parts[0] = strings.TrimPrefix(parts[0], "X-")
	} else if !anyOf(parts[0], "CT", "AS", "TIAS", "RS", "RR") {

		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, parts[0])
	}

	bandwidth, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidNumericValue, parts[1])
	}

	return &Bandwidth{
		Experimental: experimental,
		Type:         parts[0],
		Bandwidth:    bandwidth,
	}, nil
}

func unmarshalTiming(lex *lexer) (stateFn, error) {
	var err error
	var td TimeDescription

	td.Timing.StartTime, err = lex.readUint64Field()
	if err != nil {
		return nil, err
	}

	td.Timing.StopTime, err = lex.readUint64Field()
	if err != nil {
		return nil, err
	}

	if err := lex.nextLine(); err != nil {
		return nil, err
	}

	lex.desc.TimeDescriptions = append(lex.desc.TimeDescriptions, td)

	return s9, nil
}

func unmarshalRepeatTimes(lex *lexer) (stateFn, error) {
	var err error
	var newRepeatTime RepeatTime

	latestTimeDesc := &lex.desc.TimeDescriptions[len(lex.desc.TimeDescriptions)-1]

	field, err := lex.readField()
	if err != nil {
		return nil, err
	}

	newRepeatTime.Interval, err = parseTimeUnits(field)
	if err != nil {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, field)
	}

	field, err = lex.readField()
	if err != nil {
		return nil, err
	}

	newRepeatTime.Duration, err = parseTimeUnits(field)
	if err != nil {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, field)
	}

	for {
		field, err := lex.readField()
		if err != nil {
			return nil, err
		}
		if field == "" {
			break
		}
		offset, err := parseTimeUnits(field)
		if err != nil {
			return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, field)
		}
		newRepeatTime.Offsets = append(newRepeatTime.Offsets, offset)
	}

	if err := lex.nextLine(); err != nil {
		return nil, err
	}

	latestTimeDesc.RepeatTimes = append(latestTimeDesc.RepeatTimes, newRepeatTime)

	return s9, nil
}

func unmarshalTimeZones(lex *lexer) (stateFn, error) {

	for {
		var err error
		var timeZone TimeZone

		timeZone.AdjustmentTime, err = lex.readUint64Field()
		if err != nil {
			return nil, err
		}

		offset, err := lex.readField()
		if err != nil {
			return nil, err
		}

		if offset == "" {
			break
		}

		timeZone.Offset, err = parseTimeUnits(offset)
		if err != nil {
			return nil, err
		}

		lex.desc.TimeZones = append(lex.desc.TimeZones, timeZone)
	}

	if err := lex.nextLine(); err != nil {
		return nil, err
	}

	return s13, nil
}

func unmarshalSessionEncryptionKey(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	encryptionKey := EncryptionKey(value)
	l.desc.EncryptionKey = &encryptionKey

	return s11, nil
}

func unmarshalSessionAttribute(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	i := strings.IndexRune(value, ':')
	a := l.cache.getSessionAttribute()
	if i > 0 {
		a.Key = value[:i]
		a.Value = value[i+1:]
	} else {
		a.Key = value
	}

	return s11, nil
}

func unmarshalMediaDescription(lex *lexer) (stateFn, error) {
	populateMediaAttributes(lex.cache, lex.desc)
	var newMediaDesc MediaDescription

	field, err := lex.readField()
	if err != nil {
		return nil, err
	}

	if !anyOf(field, "audio", "video", "text", "application", "message") {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, field)
	}
	newMediaDesc.MediaName.Media = field

	field, err = lex.readField()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(field, "/")
	newMediaDesc.MediaName.Port.Value, err = parsePort(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w `%v`", errSDPInvalidPortValue, parts[0])
	}

	if len(parts) > 1 {
		var portRange int
		portRange, err = strconv.Atoi(parts[1])
		if err != nil {
			return nil, fmt.Errorf("%w `%v`", errSDPInvalidValue, parts)
		}
		newMediaDesc.MediaName.Port.Range = &portRange
	}

	field, err = lex.readField()
	if err != nil {
		return nil, err
	}

	for _, proto := range strings.Split(field, "/") {
		if !anyOf(
			proto,
			"UDP",
			"RTP",
			"AVP",
			"SAVP",
			"SAVPF",
			"TLS",
			"DTLS",
			"SCTP",
			"AVPF",
			"TCP",
			"MSRP",
			"BFCP",
			"UDT",
			"IX",
			"MRCPv2",
			"FEC",
		) {
			return nil, fmt.Errorf("%w `%v`", errSDPInvalidNumericValue, field)
		}
		newMediaDesc.MediaName.Protos = append(newMediaDesc.MediaName.Protos, proto)
	}

	for {
		field, err = lex.readField()
		if err != nil {
			return nil, err
		}
		if field == "" {
			break
		}
		newMediaDesc.MediaName.Formats = append(newMediaDesc.MediaName.Formats, field)
	}

	if err := lex.nextLine(); err != nil {
		return nil, err
	}

	lex.desc.MediaDescriptions = append(lex.desc.MediaDescriptions, &newMediaDesc)

	return s12, nil
}

func unmarshalMediaTitle(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	latestMediaDesc := l.desc.MediaDescriptions[len(l.desc.MediaDescriptions)-1]
	mediaTitle := Information(value)
	latestMediaDesc.MediaTitle = &mediaTitle

	return s16, nil
}

func unmarshalMediaConnectionInformation(l *lexer) (stateFn, error) {
	var err error
	latestMediaDesc := l.desc.MediaDescriptions[len(l.desc.MediaDescriptions)-1]
	latestMediaDesc.ConnectionInformation, err = l.unmarshalConnectionInformation()
	if err != nil {
		return nil, err
	}

	return s15, nil
}

func unmarshalMediaBandwidth(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	latestMediaDesc := l.desc.MediaDescriptions[len(l.desc.MediaDescriptions)-1]
	bandwidth, err := unmarshalBandwidth(value)
	if err != nil {
		return nil, fmt.Errorf("%w `b=%v`", errSDPInvalidSyntax, value)
	}
	latestMediaDesc.Bandwidth = append(latestMediaDesc.Bandwidth, *bandwidth)

	return s15, nil
}

func unmarshalMediaEncryptionKey(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	latestMediaDesc := l.desc.MediaDescriptions[len(l.desc.MediaDescriptions)-1]
	encryptionKey := EncryptionKey(value)
	latestMediaDesc.EncryptionKey = &encryptionKey

	return s14, nil
}

func unmarshalMediaAttribute(l *lexer) (stateFn, error) {
	value, err := l.readLine()
	if err != nil {
		return nil, err
	}

	i := strings.IndexRune(value, ':')
	a := l.cache.getMediaAttribute()
	if i > 0 {
		a.Key = value[:i]
		a.Value = value[i+1:]
	} else {
		a.Key = value
	}

	return s14, nil
}

func parseTimeUnits(value string) (num int64, err error) {
	if len(value) == 0 {
		return 0, fmt.Errorf("%w `%v`", errSDPInvalidValue, value)
	}
	k := timeShorthand(value[len(value)-1])
	if k > 0 {
		num, err = strconv.ParseInt(value[:len(value)-1], 10, 64)
	} else {
		k = 1
		num, err = strconv.ParseInt(value, 10, 64)
	}
	if err != nil {
		return 0, fmt.Errorf("%w `%v`", errSDPInvalidValue, value)
	}

	return num * k, nil
}

func timeShorthand(b byte) int64 {

	switch b {
	case 'd':
		return 86400
	case 'h':
		return 3600
	case 'm':
		return 60
	case 's':
		return 1
	default:
		return 0
	}
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%w `%v`", errSDPInvalidPortValue, value)
	}

	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("%w -- out of range `%v`", errSDPInvalidPortValue, port)
	}

	return port, nil
}

func populateMediaAttributes(c *unmarshalCache, s *SessionDescription) {
	if len(s.MediaDescriptions) != 0 {
		lastMediaDesc := s.MediaDescriptions[len(s.MediaDescriptions)-1]
		lastMediaDesc.Attributes = c.cloneMediaAttributes()
	}
}

type unmarshalCache struct {
	sessionAttributes []Attribute
	mediaAttributes   []Attribute
}

func (c *unmarshalCache) reset() {
	c.sessionAttributes = c.sessionAttributes[:0]
	c.mediaAttributes = c.mediaAttributes[:0]
}

func (c *unmarshalCache) getSessionAttribute() *Attribute {
	c.sessionAttributes = append(c.sessionAttributes, Attribute{})

	return &c.sessionAttributes[len(c.sessionAttributes)-1]
}

func (c *unmarshalCache) cloneSessionAttributes() []Attribute {
	if len(c.sessionAttributes) == 0 {
		return nil
	}
	s := make([]Attribute, len(c.sessionAttributes))
	copy(s, c.sessionAttributes)
	c.sessionAttributes = c.sessionAttributes[:0]

	return s
}

func (c *unmarshalCache) getMediaAttribute() *Attribute {
	c.mediaAttributes = append(c.mediaAttributes, Attribute{})

	return &c.mediaAttributes[len(c.mediaAttributes)-1]
}

func (c *unmarshalCache) cloneMediaAttributes() []Attribute {
	if len(c.mediaAttributes) == 0 {
		return nil
	}
	s := make([]Attribute, len(c.mediaAttributes))
	copy(s, c.mediaAttributes)
	c.mediaAttributes = c.mediaAttributes[:0]

	return s
}

var (
	errExtractCodecRtpmap  = errors.New("could not extract codec from rtpmap")
	errExtractCodecFmtp    = errors.New("could not extract codec from fmtp")
	errExtractCodecRtcpFb  = errors.New("could not extract codec from rtcp-fb")
	errPayloadTypeNotFound = errors.New("payload type not found")
	errCodecNotFound       = errors.New("codec not found")
	errSyntaxError         = errors.New("SyntaxError")
	errFieldMissing        = errors.New("field missing")
)

type ConnectionRole int

const (
	ConnectionRoleActive ConnectionRole = iota + 1

	ConnectionRolePassive

	ConnectionRoleActpass

	ConnectionRoleHoldconn
)

func (t ConnectionRole) String() string {
	switch t {
	case ConnectionRoleActive:
		return "active"
	case ConnectionRolePassive:
		return "passive"
	case ConnectionRoleActpass:
		return "actpass"
	case ConnectionRoleHoldconn:
		return "holdconn"
	default:
		return "Unknown"
	}
}

func newSessionID() (uint64, error) {

	id, err := webrtc.CryptoUint64()

	return id & (^(uint64(1) << 63)), err
}

type Codec struct {
	PayloadType        uint8
	Name               string
	ClockRate          uint32
	EncodingParameters string
	Fmtp               string
	RTCPFeedback       []string
}

const (
	unknown = iota
)

func (c Codec) String() string {
	return fmt.Sprintf(
		"%d %s/%d/%s (%s) [%s]",
		c.PayloadType,
		c.Name,
		c.ClockRate,
		c.EncodingParameters,
		c.Fmtp,
		strings.Join(c.RTCPFeedback, ", "),
	)
}

func (c *Codec) appendRTCPFeedback(rtcpFeedback string) {
	if slices.Contains(c.RTCPFeedback, rtcpFeedback) {
		return
	}

	c.RTCPFeedback = append(c.RTCPFeedback, rtcpFeedback)
}

func parseRtpmap(rtpmap string) (Codec, error) {
	var codec Codec
	parsingFailed := errExtractCodecRtpmap

	split := strings.Split(rtpmap, " ")
	if len(split) != 2 {
		return codec, parsingFailed
	}

	ptSplit := strings.Split(split[0], ":")
	if len(ptSplit) != 2 {
		return codec, parsingFailed
	}

	ptInt, err := strconv.ParseUint(ptSplit[1], 10, 8)
	if err != nil {
		return codec, parsingFailed
	}

	codec.PayloadType = uint8(ptInt)

	split = strings.Split(split[1], "/")
	codec.Name = split[0]
	parts := len(split)
	if parts > 1 {
		rate, err := strconv.ParseUint(split[1], 10, 32)
		if err != nil {
			return codec, parsingFailed
		}
		codec.ClockRate = uint32(rate)
	}
	if parts > 2 {
		codec.EncodingParameters = split[2]
	}

	return codec, nil
}

func parseFmtp(fmtp string) (Codec, error) {
	var codec Codec
	parsingFailed := errExtractCodecFmtp

	split := strings.SplitN(fmtp, " ", 2)
	if len(split) != 2 {
		return codec, parsingFailed
	}

	formatParams := split[1]

	split = strings.Split(split[0], ":")
	if len(split) != 2 {
		return codec, parsingFailed
	}

	ptInt, err := strconv.ParseUint(split[1], 10, 8)
	if err != nil {
		return codec, parsingFailed
	}

	codec.PayloadType = uint8(ptInt)
	codec.Fmtp = formatParams

	return codec, nil
}

func parseRtcpFb(rtcpFb string) (codec Codec, isWildcard bool, err error) {
	var ptInt uint64
	err = errExtractCodecRtcpFb

	split := strings.SplitN(rtcpFb, " ", 2)
	if len(split) != 2 {
		return
	}

	ptSplit := strings.Split(split[0], ":")
	if len(ptSplit) != 2 {
		return
	}

	isWildcard = ptSplit[1] == "*"
	if !isWildcard {
		ptInt, err = strconv.ParseUint(ptSplit[1], 10, 8)
		if err != nil {
			return
		}

		codec.PayloadType = uint8(ptInt)
	}

	codec.RTCPFeedback = append(codec.RTCPFeedback, split[1])

	return codec, isWildcard, nil
}

func mergeCodecs(codec Codec, codecs map[uint8]Codec) {
	savedCodec := codecs[codec.PayloadType]

	if savedCodec.PayloadType == 0 {
		savedCodec.PayloadType = codec.PayloadType
	}
	if savedCodec.Name == "" {
		savedCodec.Name = codec.Name
	}
	if savedCodec.ClockRate == 0 {
		savedCodec.ClockRate = codec.ClockRate
	}
	if savedCodec.EncodingParameters == "" {
		savedCodec.EncodingParameters = codec.EncodingParameters
	}
	if savedCodec.Fmtp == "" {
		savedCodec.Fmtp = codec.Fmtp
	}
	savedCodec.RTCPFeedback = append(savedCodec.RTCPFeedback, codec.RTCPFeedback...)

	codecs[savedCodec.PayloadType] = savedCodec
}

func (s *SessionDescription) buildCodecMap() map[uint8]Codec {
	codecs := map[uint8]Codec{

		0: {
			PayloadType: 0,
			Name:        "PCMU",
			ClockRate:   8000,
		},
		8: {
			PayloadType: 8,
			Name:        "PCMA",
			ClockRate:   8000,
		},
		9: {
			PayloadType: 9,
			Name:        "G722",
			ClockRate:   8000,
		},
	}

	wildcardRTCPFeedback := []string{}
	for _, m := range s.MediaDescriptions {
		for _, a := range m.Attributes {
			attr := a.String()
			switch {
			case strings.HasPrefix(attr, "rtpmap:"):
				codec, err := parseRtpmap(attr)
				if err == nil {
					mergeCodecs(codec, codecs)
				}
			case strings.HasPrefix(attr, "fmtp:"):
				codec, err := parseFmtp(attr)
				if err == nil {
					mergeCodecs(codec, codecs)
				}
			case strings.HasPrefix(attr, "rtcp-fb:"):
				codec, isWildcard, err := parseRtcpFb(attr)
				switch {
				case err != nil:
				case isWildcard:
					wildcardRTCPFeedback = append(wildcardRTCPFeedback, codec.RTCPFeedback...)
				default:
					mergeCodecs(codec, codecs)
				}
			}
		}
	}

	for i, codec := range codecs {
		for _, newRTCPFeedback := range wildcardRTCPFeedback {
			codec.appendRTCPFeedback(newRTCPFeedback)
		}

		codecs[i] = codec
	}

	return codecs
}

func equivalentFmtp(want, got string) bool {
	wantSplit := strings.Split(want, ";")
	gotSplit := strings.Split(got, ";")

	if len(wantSplit) != len(gotSplit) {
		return false
	}

	sort.Strings(wantSplit)
	sort.Strings(gotSplit)

	for i, wantPart := range wantSplit {
		wantPart = strings.TrimSpace(wantPart)
		gotPart := strings.TrimSpace(gotSplit[i])
		if gotPart != wantPart {
			return false
		}
	}

	return true
}

func codecsMatch(wanted, got Codec) bool {
	if wanted.Name != "" && !strings.EqualFold(wanted.Name, got.Name) {
		return false
	}
	if wanted.ClockRate != 0 && wanted.ClockRate != got.ClockRate {
		return false
	}
	if wanted.EncodingParameters != "" && wanted.EncodingParameters != got.EncodingParameters {
		return false
	}
	if wanted.Fmtp != "" && !equivalentFmtp(wanted.Fmtp, got.Fmtp) {
		return false
	}

	return true
}

func (s *SessionDescription) GetCodecForPayloadType(payloadType uint8) (Codec, error) {
	codecs := s.buildCodecMap()

	codec, ok := codecs[payloadType]
	if ok {
		return codec, nil
	}

	return codec, errPayloadTypeNotFound
}

func (s *SessionDescription) GetCodecsForPayloadTypes(payloadTypes []uint8) ([]Codec, error) {
	codecs := s.buildCodecMap()

	result := make([]Codec, 0, len(payloadTypes))
	for _, payloadType := range payloadTypes {
		codec, ok := codecs[payloadType]
		if ok {
			result = append(result, codec)
		}
	}

	return result, nil
}

func (s *SessionDescription) GetPayloadTypeForCodec(wanted Codec) (uint8, error) {
	codecs := s.buildCodecMap()

	for payloadType, codec := range codecs {
		if codecsMatch(wanted, codec) {
			return payloadType, nil
		}
	}

	return 0, errCodecNotFound
}

type stateFn func(*lexer) (stateFn, error)

type lexer struct {
	desc  *SessionDescription
	cache *unmarshalCache
	baseLexer
}

type keyToState func(key byte) stateFn

func (l *lexer) handleType(fn keyToState) (stateFn, error) {
	key, err := l.readType()
	if errors.Is(err, io.EOF) && key == 0 {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	if res := fn(key); res != nil {
		return res, nil
	}

	return nil, l.syntaxError()
}
