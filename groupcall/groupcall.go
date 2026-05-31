// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package groupcall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/amarnathcjd/gortc/logger"
	"github.com/amarnathcjd/gortc/media"
	"github.com/amarnathcjd/gortc/transport"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

type GroupCall struct {
	client     *telegram.Client
	conn       *transport.GroupConnection
	call       *telegram.InputGroupCall
	audioTrack *webrtc.TrackLocalStaticRTP
	videoTrack *webrtc.TrackLocalStaticRTP
	log        *logger.Logger

	OnConnected    func()
	OnDisconnected func()
	OnStateChange  func(string)
}

func (gc *GroupCall) State() string { return gc.conn.State() }

type Option func(*GroupCall)

// WithLogger sets the logger for the call and its transport (default: WARN+).
func WithLogger(l *logger.Logger) Option {
	return func(gc *GroupCall) {
		if l != nil {
			gc.log = l
		}
	}
}

// WithLogLevel bumps the default logger's verbosity, e.g. slog.LevelDebug.
func WithLogLevel(level slog.Level) Option {
	return func(gc *GroupCall) {
		gc.log = logger.New(logger.WithLevel(level))
	}
}

func New(client *telegram.Client, opts ...Option) *GroupCall {
	gc := &GroupCall{
		client: client,
		log:    logger.New(),
	}
	for _, o := range opts {
		o(gc)
	}
	gc.conn = transport.NewGroupConnection(gc.log.With("subsystem", "transport"))
	return gc
}

var errRetryable = errors.New("retryable")

func (gc *GroupCall) JoinCall(ctx context.Context, chatID any) error {
	const maxAttempts = 5
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 1 {
			gc.log.Infof("rejoining (attempt %d/%d)", attempt, maxAttempts)
			gc.conn = transport.NewGroupConnection(gc.log.With("subsystem", "transport"))
		}
		err := gc.joinOnce(ctx, chatID)
		if err == nil {
			return nil
		}
		lastErr = err
		gc.log.Warnf("join attempt %d failed: %v", attempt, err)
		_ = gc.leaveCallSilent()

		if !errors.Is(err, errRetryable) {
			return err
		}
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
	}
	return fmt.Errorf("join failed after %d attempts: %w", maxAttempts, lastErr)
}

func (gc *GroupCall) joinOnce(ctx context.Context, chatID any) error {
	call, err := gc.client.GetGroupCall(chatID)
	if err != nil {
		return fmt.Errorf("get group call: %w", err)
	}
	gc.call = call

	connected := make(chan struct{}, 1)
	disconnected := make(chan struct{}, 1)
	gc.conn.OnConnected(func() {
		gc.log.Infof("connected to group call")
		select {
		case connected <- struct{}{}:
		default:
		}
		if gc.OnConnected != nil {
			gc.OnConnected()
		}
	})
	gc.conn.OnDisconnected(func() {
		gc.log.Infof("disconnected from group call")
		select {
		case disconnected <- struct{}{}:
		default:
		}
		if gc.OnDisconnected != nil {
			gc.OnDisconnected()
		}
	})
	gc.conn.OnStateChange(func(state string) {
		if gc.OnStateChange != nil {
			gc.OnStateChange(state)
		}
	})

	if err := gc.conn.Open(); err != nil {
		return fmt.Errorf("open connection: %w", err)
	}

	track, err := gc.conn.AddAudioTrack()
	if err != nil {
		return fmt.Errorf("add audio track: %w", err)
	}
	gc.audioTrack = track

	videoTrack, err := gc.conn.AddVideoTrack("")
	if err != nil {
		return fmt.Errorf("add video track: %w", err)
	}
	gc.videoTrack = videoTrack

	joinPayload, err := gc.conn.GetJoinPayload()
	if err != nil {
		return fmt.Errorf("get join payload: %w", err)
	}

	gc.log.Debugf("join payload: %s", joinPayload)

	me, err := gc.client.GetMe()
	if err != nil {
		return fmt.Errorf("get me: %w", err)
	}

	updates, err := gc.client.PhoneJoinGroupCall(&telegram.PhoneJoinGroupCallParams{
		Call:   *call,
		JoinAs: &telegram.InputPeerUser{UserID: me.ID, AccessHash: me.AccessHash},
		Params: &telegram.DataJson{Data: joinPayload},
		Muted:  false,
	})
	if err != nil {
		return fmt.Errorf("join group call: %w", err)
	}

	serverResponse, err := extractConnectionParams(updates)
	if err != nil {
		return fmt.Errorf("extract connection params: %w", err)
	}

	gc.log.Debugf("server response: %s", serverResponse)

	if err := gc.conn.Connect(serverResponse); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	select {
	case <-connected:
		return nil
	case <-disconnected:
		return fmt.Errorf("%w: disconnected before connected (ICE failed)", errRetryable)
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return fmt.Errorf("%w: timed out waiting for connected state", errRetryable)
	}
}

func (gc *GroupCall) leaveCallSilent() error {
	if gc.call != nil {
		_, _ = gc.client.PhoneLeaveGroupCall(*gc.call, 0)
	}
	return gc.conn.Close()
}

func (gc *GroupCall) AudioTrack() *webrtc.TrackLocalStaticRTP {
	return gc.audioTrack
}

func (gc *GroupCall) VideoTrack() *webrtc.TrackLocalStaticRTP {
	return gc.videoTrack
}

func (gc *GroupCall) Sender() *transport.Dispatcher {
	return gc.conn.Dispatcher()
}

func (gc *GroupCall) AudioSSRC() uint32 {
	return gc.conn.OutgoingAudioSsrc()
}

func (gc *GroupCall) VideoSSRC() uint32 {
	return gc.conn.OutgoingVideoSsrc()
}

// Stream sends a media source into the call, blocking until it ends or ctx is cancelled.
func (gc *GroupCall) Stream(ctx context.Context, src media.Source) error {
	return media.Stream(ctx, gc.Sender(), gc.AudioSSRC(), gc.VideoSSRC(), src)
}

// Play starts a media source and returns a controllable Player (pause/resume/stop).
func (gc *GroupCall) Play(ctx context.Context, src media.Source) *media.Player {
	return media.Play(ctx, gc.Sender(), gc.AudioSSRC(), gc.VideoSSRC(), src)
}

func (gc *GroupCall) Client() *telegram.Client { return gc.client }

func (gc *GroupCall) Call() *telegram.InputGroupCall { return gc.call }

func (gc *GroupCall) Connection() *transport.GroupConnection {
	return gc.conn
}

func (gc *GroupCall) Leave() error {
	if gc.call != nil {
		_, err := gc.client.PhoneLeaveGroupCall(*gc.call, 0)
		if err != nil {
			gc.log.Warnf("leave group call error: %v", err)
		}
	}
	return gc.conn.Close()
}

func extractConnectionParams(updates telegram.Updates) (string, error) {
	switch u := updates.(type) {
	case *telegram.UpdatesObj:
		for _, update := range u.Updates {
			if conn, ok := update.(*telegram.UpdateGroupCallConnection); ok {
				if conn.Params != nil {
					return conn.Params.Data, nil
				}
			}
		}
	}

	raw, _ := json.MarshalIndent(updates, "", "  ")
	return "", fmt.Errorf("no UpdateGroupCallConnection found in response: %s", string(raw))
}
