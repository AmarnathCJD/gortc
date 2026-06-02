// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package interceptor

import (
	"errors"
	"io"
	"strings"

	"github.com/amarnathcjd/gortc/webrtc"
)

type Factory interface {
	NewInterceptor(id string) (Interceptor, error)
}

type Interceptor interface {
	BindRTCPReader(reader RTCPReader) RTCPReader
	BindRTCPWriter(writer RTCPWriter) RTCPWriter
	BindLocalStream(info *StreamInfo, writer RTPWriter) RTPWriter
	UnbindLocalStream(info *StreamInfo)
	BindRemoteStream(info *StreamInfo, reader RTPReader) RTPReader
	UnbindRemoteStream(info *StreamInfo)
	io.Closer
}

type RTPWriter interface {
	Write(header *webrtc.RtpHeader, payload []byte, attributes Attributes) (int, error)
}

type RTPReader interface {
	Read([]byte, Attributes) (int, Attributes, error)
}

type RTCPWriter interface {
	Write(pkts []webrtc.RtcpPacket, attributes Attributes) (int, error)
}

type RTCPReader interface {
	Read([]byte, Attributes) (int, Attributes, error)
}

type RTPWriterFunc func(header *webrtc.RtpHeader, payload []byte, attributes Attributes) (int, error)
type RTPReaderFunc func([]byte, Attributes) (int, Attributes, error)
type RTCPWriterFunc func(pkts []webrtc.RtcpPacket, attributes Attributes) (int, error)
type RTCPReaderFunc func([]byte, Attributes) (int, Attributes, error)

func (f RTPWriterFunc) Write(header *webrtc.RtpHeader, payload []byte, attributes Attributes) (int, error) {
	return f(header, payload, attributes)
}

func (f RTPReaderFunc) Read(b []byte, a Attributes) (int, Attributes, error) {
	return f(b, a)
}

func (f RTCPWriterFunc) Write(pkts []webrtc.RtcpPacket, attributes Attributes) (int, error) {
	return f(pkts, attributes)
}

func (f RTCPReaderFunc) Read(b []byte, a Attributes) (int, Attributes, error) {
	return f(b, a)
}

type unmarshaledDataKeyType int

const (
	rtpHeaderKey unmarshaledDataKeyType = iota
	rtcpPacketsKey
)

var errInvalidType = errors.New("found value of invalid type in attributes map")

type Attributes map[any]any

func (a Attributes) Set(key any, val any) {
	a[key] = val
}

func (a Attributes) GetRTPHeader(raw []byte) (*webrtc.RtpHeader, error) {
	if val, ok := a[rtpHeaderKey]; ok {
		if header, ok := val.(*webrtc.RtpHeader); ok {
			return header, nil
		}
		return nil, errInvalidType
	}
	header := &webrtc.RtpHeader{}
	if _, err := header.Unmarshal(raw); err != nil {
		return nil, err
	}
	a[rtpHeaderKey] = header

	return header, nil
}

func (a Attributes) GetRTCPPackets(raw []byte) ([]webrtc.RtcpPacket, error) {
	if val, ok := a[rtcpPacketsKey]; ok {
		if packets, ok := val.([]webrtc.RtcpPacket); ok {
			return packets, nil
		}
		return nil, errInvalidType
	}
	pkts, err := webrtc.RtcpUnmarshal(raw)
	if err != nil {
		return nil, err
	}
	a[rtcpPacketsKey] = pkts

	return pkts, nil
}

type RTPHeaderExtension struct {
	URI string
	ID  int
}

type StreamInfo struct {
	ID                                string
	Attributes                        Attributes
	SSRC                              uint32
	SSRCRetransmission                uint32
	SSRCForwardErrorCorrection        uint32
	PayloadType                       uint8
	PayloadTypeRetransmission         uint8
	PayloadTypeForwardErrorCorrection uint8
	RTPHeaderExtensions               []RTPHeaderExtension
	MimeType                          string
	ClockRate                         uint32
	Channels                          uint16
	SDPFmtpLine                       string
	RTCPFeedback                      []RTCPFeedback
}

type RTCPFeedback struct {
	Type      string
	Parameter string
}

type NoOp struct{}

func (i *NoOp) BindRTCPReader(reader RTCPReader) RTCPReader                { return reader }
func (i *NoOp) BindRTCPWriter(writer RTCPWriter) RTCPWriter                { return writer }
func (i *NoOp) BindLocalStream(_ *StreamInfo, writer RTPWriter) RTPWriter  { return writer }
func (i *NoOp) UnbindLocalStream(_ *StreamInfo)                            {}
func (i *NoOp) BindRemoteStream(_ *StreamInfo, reader RTPReader) RTPReader { return reader }
func (i *NoOp) UnbindRemoteStream(_ *StreamInfo)                           {}
func (i *NoOp) Close() error                                               { return nil }

type Chain struct {
	interceptors []Interceptor
}

func NewChain(interceptors []Interceptor) *Chain {
	return &Chain{interceptors: interceptors}
}

func (i *Chain) BindRTCPReader(reader RTCPReader) RTCPReader {
	for _, interceptor := range i.interceptors {
		reader = interceptor.BindRTCPReader(reader)
	}
	return reader
}

func (i *Chain) BindRTCPWriter(writer RTCPWriter) RTCPWriter {
	for _, interceptor := range i.interceptors {
		writer = interceptor.BindRTCPWriter(writer)
	}
	return writer
}

func (i *Chain) BindLocalStream(ctx *StreamInfo, writer RTPWriter) RTPWriter {
	for _, interceptor := range i.interceptors {
		writer = interceptor.BindLocalStream(ctx, writer)
	}
	return writer
}

func (i *Chain) UnbindLocalStream(ctx *StreamInfo) {
	for _, interceptor := range i.interceptors {
		interceptor.UnbindLocalStream(ctx)
	}
}

func (i *Chain) BindRemoteStream(ctx *StreamInfo, reader RTPReader) RTPReader {
	for _, interceptor := range i.interceptors {
		reader = interceptor.BindRemoteStream(ctx, reader)
	}
	return reader
}

func (i *Chain) UnbindRemoteStream(ctx *StreamInfo) {
	for _, interceptor := range i.interceptors {
		interceptor.UnbindRemoteStream(ctx)
	}
}

func (i *Chain) Close() error {
	var errs []error
	for _, interceptor := range i.interceptors {
		errs = append(errs, interceptor.Close())
	}
	return flattenErrs(errs)
}

type Registry struct {
	factories []Factory
}

func (r *Registry) Add(f Factory) {
	r.factories = append(r.factories, f)
}

func (r *Registry) Build(id string) (Interceptor, error) {
	if len(r.factories) == 0 {
		return &NoOp{}, nil
	}
	interceptors := make([]Interceptor, 0, len(r.factories))
	for _, f := range r.factories {
		i, err := f.NewInterceptor(id)
		if err != nil {
			return nil, err
		}
		interceptors = append(interceptors, i)
	}
	return NewChain(interceptors), nil
}

func flattenErrs(errs []error) error {
	errs2 := []error{}
	for _, e := range errs {
		if e != nil {
			errs2 = append(errs2, e)
		}
	}
	if len(errs2) == 0 {
		return nil
	}
	return multiError(errs2)
}

type multiError []error

func (me multiError) Error() string {
	var errstrings []string
	for _, err := range me {
		if err != nil {
			errstrings = append(errstrings, err.Error())
		}
	}
	if len(errstrings) == 0 {
		return "multiError must contain multiple error but is empty"
	}
	return strings.Join(errstrings, "\n")
}
