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

	"github.com/amarnathcjd/gortc/groupcall"
	"github.com/amarnathcjd/gortc/logger"
	"github.com/amarnathcjd/gortc/media"

	"github.com/amarnathcjd/gogram/telegram"
)

var errNotInCall = errors.New("gortc: not in a call")

type (
	Logger         = logger.Logger
	Source         = media.Source
	SeekableSource = media.SeekableSource
	EncodeOptions  = media.EncodeOptions
	Player         = media.Player
	Track          = media.Track
)

const (
	TrackAudio = media.TrackAudio
	TrackVideo = media.TrackVideo
)

var ErrNotSeekable = media.ErrNotSeekable

var (
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
)

type Option = groupcall.Option

var (
	WithLogger   = groupcall.WithLogger
	WithLogLevel = groupcall.WithLogLevel
)

func NewLogger(opts ...logger.Option) *Logger { return logger.New(opts...) }

// Call is a single Telegram group-call session.
type Call struct {
	gc *groupcall.GroupCall
}

func NewCall(client *telegram.Client, opts ...Option) *Call {
	return &Call{gc: groupcall.New(client, opts...)}
}

func (c *Call) OnConnected(fn func()) { c.gc.OnConnected = fn }

func (c *Call) OnDisconnected(fn func()) { c.gc.OnDisconnected = fn }

// OnStateChange fires on every connection state transition (new, connecting,
// connected, disconnected, failed, closed).
func (c *Call) OnStateChange(fn func(state string)) { c.gc.OnStateChange = fn }

// State returns the current connection state.
func (c *Call) State() string { return c.gc.State() }

// Join joins the group call of the given chat (username, ID, or peer),
// retrying internally until connected or retries are exhausted.
func (c *Call) Join(chatID any) error { return c.gc.JoinCall(context.Background(), chatID) }

// JoinContext is Join with a cancellable context (cancel aborts retries/wait).
func (c *Call) JoinContext(ctx context.Context, chatID any) error {
	return c.gc.JoinCall(ctx, chatID)
}

// Stream sends a media source into the call, blocking until it ends or ctx is cancelled.
func (c *Call) Stream(ctx context.Context, src Source) error { return c.gc.Stream(ctx, src) }

// Play starts a media source and returns a controllable Player (pause/resume/stop).
func (c *Call) Play(ctx context.Context, src Source) *Player { return c.gc.Play(ctx, src) }

// SetVolume sets the bot's own outgoing volume in the call, 0..200 (percent).
func (c *Call) SetVolume(percent int) error {
	v := min(max(int32(percent)*100, 1), 20000)
	return c.editSelf(&telegram.PhoneEditGroupCallParticipantParams{Volume: v})
}

// SetVideoStopped tells the SFU whether this participant has video, clearing or
// restoring the remote video placeholder.
func (c *Call) SetVideoStopped(stopped bool) error {
	return c.editSelf(&telegram.PhoneEditGroupCallParticipantParams{VideoStopped: stopped})
}

// SetMuted mutes or unmutes the bot's own outgoing audio in the call.
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
