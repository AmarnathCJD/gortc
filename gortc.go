// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

// Package gortc is a Telegram group-call streaming library built on top of
// gogram. It joins voice/video group calls and streams audio and video from
// flexible sources (files, URLs, readers, raw frames, or pre-encoded media).
//
// Quick start:
//
//	client, _ := telegram.NewClient(telegram.ClientConfig{ ... })
//	client.Conn()
//
//	call := gortc.NewCall(client, gortc.WithLogLevel(slog.LevelInfo))
//	call.OnConnected(func() {
//		go call.Stream(context.Background(), media.FromFile("movie.mkv"))
//	})
//	if err := call.Join("@mychat"); err != nil { ... }
//	defer call.Leave()
//
// The client is a *telegram.Client from gogram; gortc does not replace it.
package gortc

import (
	"context"
	"errors"
	"log/slog"

	"github.com/amarnathcjd/gortc/confcall"
	"github.com/amarnathcjd/gortc/groupcall"
	"github.com/amarnathcjd/gortc/media"
	"github.com/amarnathcjd/gortc/phonecall"
	"github.com/amarnathcjd/gortc/transport"

	"github.com/amarnathcjd/gogram/telegram"
)

var errNotInCall = errors.New("gortc: not in a call")

type (
	Logger         = transport.Logger
	Source         = media.Source
	SeekableSource = media.SeekableSource
	EncodeOptions  = media.EncodeOptions
	Player         = media.Player
	Track          = media.Track
	IncomingTrack  = media.IncomingTrack
	TrackKind      = media.TrackKind

	Option           = groupcall.Option
	PhoneOption      = phonecall.Option
	ConferenceOption = confcall.Option

	PhoneCall              = phonecall.PhoneCall
	IncomingCall           = phonecall.IncomingCall
	ConferenceCall         = confcall.ConferenceCall
	IncomingConferenceCall = confcall.IncomingConferenceCall

	Participant       = groupcall.Participant
	ParticipantEvent  = groupcall.ParticipantEvent
	BandwidthEstimate = groupcall.BandwidthEstimate
)

const (
	TrackAudio     = media.TrackAudio
	TrackVideo     = media.TrackVideo
	TrackKindAudio = media.TrackKindAudio
	TrackKindVideo = media.TrackKindVideo

	VideoCodecVP8 = media.VideoCodecVP8
	VideoCodecVP9 = media.VideoCodecVP9
	MimeTypeVP8   = "video/VP8"
	MimeTypeVP9   = "video/VP9"

	ParticipantJoined  = groupcall.ParticipantJoined
	ParticipantLeft    = groupcall.ParticipantLeft
	ParticipantUpdated = groupcall.ParticipantUpdated
)

var (
	ErrNotSeekable = media.ErrNotSeekable

	Res480  = media.Res480
	Res720  = media.Res720
	Res1080 = media.Res1080

	FromFile     = media.FromFile
	FromURL      = media.FromURL
	FromReader   = media.FromReader
	FromOggOpus  = media.FromOggOpus
	FromIVF      = media.FromIVF
	FromEncoded  = media.FromEncoded
	FromRawPCM   = media.FromRawPCM
	FromRawVideo = media.FromRawVideo
	Loop         = media.Loop
	Concat       = media.Concat

	WithLogger     = groupcall.WithLogger
	WithLogLevel   = groupcall.WithLogLevel
	WithReconnect  = groupcall.WithReconnect
	WithVideoCodec = groupcall.WithVideoCodec

	WithPhoneLogger   = phonecall.WithLogger
	WithPhoneLogLevel = phonecall.WithLogLevel

	WithConferenceLogger   = confcall.WithLogger
	WithConferenceLogLevel = confcall.WithLogLevel
)

// NewLogger builds a Logger that writes at the given slog level (e.g.
// slog.LevelDebug). Pass it to WithLogger / WithPhoneLogger / WithConferenceLogger.
func NewLogger(level slog.Level) *Logger {
	return transport.NewLogger(transport.WithLogLevel(level))
}

// NewCall constructs a group-call handle (regular voice chat / livestream).
func NewCall(client *telegram.Client, opts ...Option) *Call {
	return &Call{gc: groupcall.New(client, opts...)}
}

// NewPhoneCall constructs a 1:1 phone-call handle.
func NewPhoneCall(client *telegram.Client, opts ...PhoneOption) *PhoneCall {
	return phonecall.New(client, opts...)
}

// NewConferenceCall constructs an E2E conference-call handle. Use Create to
// start a new call (and get a shareable slug) or Join/JoinFromInvite to join one.
func NewConferenceCall(client *telegram.Client, opts ...ConferenceOption) *ConferenceCall {
	return confcall.New(client, opts...)
}

// Call is a single Telegram group-call session.
type Call struct {
	gc *groupcall.GroupCall
}

func (c *Call) OnConnected(fn func())                          { c.gc.OnConnected = fn }
func (c *Call) OnDisconnected(fn func())                       { c.gc.OnDisconnected = fn }
func (c *Call) OnStateChange(fn func(state string))            { c.gc.OnStateChange = fn }
func (c *Call) OnStreamEnded(fn func(error))                   { c.gc.OnStreamEnded = fn }
func (c *Call) OnTrack(fn func(*IncomingTrack))                { c.gc.OnTrack = fn }
func (c *Call) OnReconnecting(fn func(attempt int))            { c.gc.OnReconnecting = fn }
func (c *Call) OnReconnected(fn func())                        { c.gc.OnReconnected = fn }
func (c *Call) OnReconnectFailed(fn func(error))               { c.gc.OnReconnectFailed = fn }
func (c *Call) OnParticipant(fn func(ParticipantEvent, Participant)) {
	c.gc.OnParticipant = fn
}
func (c *Call) OnBandwidthEstimate(fn func(BandwidthEstimate)) { c.gc.OnBandwidthEstimate = fn }

func (c *Call) Participants() []Participant          { return c.gc.Participants() }
func (c *Call) BandwidthEstimate() BandwidthEstimate { return c.gc.BandwidthEstimate() }
func (c *Call) State() string                        { return c.gc.State() }

// Join joins the group call of the given chat (username, ID, or peer).
func (c *Call) Join(chatID any) error { return c.gc.JoinCall(context.Background(), chatID) }

// JoinContext is Join with a cancellable context.
func (c *Call) JoinContext(ctx context.Context, chatID any) error {
	return c.gc.JoinCall(ctx, chatID)
}

func (c *Call) Stream(ctx context.Context, src Source) error { return c.gc.Stream(ctx, src) }
func (c *Call) Play(ctx context.Context, src Source) *Player { return c.gc.Play(ctx, src) }

// SetVolume sets the bot's outgoing volume in the call, 0..200 (percent).
func (c *Call) SetVolume(percent int) error {
	v := min(max(int32(percent)*100, 1), 20000)
	return c.editSelf(&telegram.PhoneEditGroupCallParticipantParams{Volume: v})
}

func (c *Call) SetVideoStopped(stopped bool) error {
	return c.editSelf(&telegram.PhoneEditGroupCallParticipantParams{VideoStopped: stopped})
}

func (c *Call) SetMuted(muted bool) error {
	return c.editSelf(&telegram.PhoneEditGroupCallParticipantParams{Muted: muted})
}

func (c *Call) editSelf(params *telegram.PhoneEditGroupCallParticipantParams) error {
	call := c.gc.Call()
	if call == nil {
		return errNotInCall
	}
	params.Call = *call
	params.Participant = &telegram.InputPeerSelf{}
	_, err := c.gc.Client().PhoneEditGroupCallParticipant(params)
	return err
}

func (c *Call) Leave() error { return c.gc.Leave() }

// GroupCall exposes the underlying low-level handle for advanced use.
func (c *Call) GroupCall() *groupcall.GroupCall { return c.gc }
