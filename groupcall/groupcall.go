// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

// Package groupcall implements joining and streaming media into Telegram
// group voice/video chats (regular non-E2E group calls).
package groupcall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/amarnathcjd/gortc/media"
	"github.com/amarnathcjd/gortc/transport"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"
)

// GroupCall is a single Telegram group voice/video chat session. Build one
// with New, then drive it via JoinCall / Stream / Play / Leave.
type GroupCall struct {
	client     *telegram.Client
	conn       *transport.GroupConnection
	call       *telegram.InputGroupCall
	audioTrack *webrtc.TrackLocalStaticRTP
	videoTrack *webrtc.TrackLocalStaticRTP
	log        *transport.Logger

	chatID         any
	leaving        bool
	everConnected  bool
	reconnMu       sync.Mutex
	reconnRun      bool
	reconnect      reconnectPolicy
	videoCodecMime string

	participants     *participantStore
	participantsOnce sync.Once

	bwe *bweTracker

	OnConnected         func()
	OnDisconnected      func()
	OnStateChange       func(string)
	OnStreamEnded       func(error)
	OnTrack             func(*media.IncomingTrack)
	OnReconnecting      func(attempt int)
	OnReconnected       func()
	OnReconnectFailed   func(error)
	OnParticipant       func(ParticipantEvent, Participant)
	OnBandwidthEstimate func(BandwidthEstimate)
}

func (gc *GroupCall) BandwidthEstimate() BandwidthEstimate {
	if gc.bwe == nil {
		return BandwidthEstimate{}
	}
	return gc.bwe.snapshot()
}

type reconnectPolicy struct {
	enabled     bool
	maxAttempts int
	base        time.Duration
	max         time.Duration
}

func (gc *GroupCall) State() string { return gc.conn.State() }

type Option func(*GroupCall)

// WithLogger sets the logger for the call and its transport (default: WARN+).
func WithLogger(l *transport.Logger) Option {
	return func(gc *GroupCall) {
		if l != nil {
			gc.log = l
		}
	}
}

// WithLogLevel bumps the default logger's verbosity, e.g. slog.LevelDebug.
func WithLogLevel(level slog.Level) Option {
	return func(gc *GroupCall) {
		gc.log = transport.NewLogger(transport.WithLogLevel(level))
	}
}

func WithVideoCodec(mime string) Option {
	return func(gc *GroupCall) {
		gc.videoCodecMime = mime
	}
}

func WithReconnect(attempts int, base, maxBackoff time.Duration) Option {
	return func(gc *GroupCall) {
		gc.reconnect = reconnectPolicy{enabled: true, maxAttempts: attempts, base: base, max: maxBackoff}
	}
}

func New(client *telegram.Client, opts ...Option) *GroupCall {
	gc := &GroupCall{
		client: client,
		log:    transport.NewLogger(),
		reconnect: reconnectPolicy{
			enabled:     false,
			maxAttempts: 0,
			base:        time.Second,
			max:         30 * time.Second,
		},
	}
	for _, o := range opts {
		o(gc)
	}
	if gc.reconnect.base <= 0 {
		gc.reconnect.base = time.Second
	}
	if gc.reconnect.max <= 0 {
		gc.reconnect.max = 30 * time.Second
	}
	gc.conn = transport.NewGroupConnection(gc.log.With("subsystem", "transport"))
	gc.participants = newParticipantStore()
	gc.bwe = newBWETracker()
	return gc
}

var errRetryable = errors.New("retryable")

func (gc *GroupCall) JoinCall(ctx context.Context, chatID any) error {
	gc.reconnMu.Lock()
	gc.chatID = chatID
	gc.leaving = false
	gc.reconnMu.Unlock()
	gc.installParticipantHandler()
	const maxAttempts = 3
	var lastErr error
	var cachedServerResponse string
	backoff := 2 * time.Second
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt > 1 {
			gc.log.Infof("rejoining (attempt %d/%d)", attempt, maxAttempts)
			gc.conn = transport.NewGroupConnection(gc.log.With("subsystem", "transport"))
		}
		reuse := ""
		if attempt == 2 {
			reuse = cachedServerResponse
		}
		gotResp, err := gc.joinOnce(ctx, chatID, reuse)
		if err == nil {
			return nil
		}
		if gotResp != "" {
			cachedServerResponse = gotResp
		}
		lastErr = err
		gc.log.Warnf("join attempt %d failed: %v", attempt, err)
		_ = gc.leaveCallSilent()

		if !errors.Is(err, errRetryable) && !transport.IsSignalingNotReady(err) {
			return err
		}
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > 8*time.Second {
				backoff = 8 * time.Second
			}
		}
	}
	return fmt.Errorf("join failed after %d attempts: %w", maxAttempts, lastErr)
}

func (gc *GroupCall) joinOnce(ctx context.Context, chatID any, reuseServerResponse string) (string, error) {
	call, err := gc.client.GetGroupCall(chatID)
	if err != nil {
		return "", fmt.Errorf("get group call: %w", err)
	}
	gc.call = call

	connected := make(chan struct{}, 1)
	disconnected := make(chan struct{}, 1)
	gc.conn.OnConnected(func() {
		gc.log.Infof("connected to group call")
		gc.reconnMu.Lock()
		gc.everConnected = true
		gc.reconnMu.Unlock()
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
		gc.maybeStartReconnect()
	})
	gc.conn.OnStateChange(func(state string) {
		if gc.OnStateChange != nil {
			gc.OnStateChange(state)
		}
	})

	if err := gc.conn.Open(); err != nil {
		return "", fmt.Errorf("open connection: %w", err)
	}

	gc.conn.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if gc.OnTrack == nil {
			return
		}
		gc.OnTrack(media.NewIncomingTrack(track))
	})

	track, err := gc.conn.AddAudioTrack()
	if err != nil {
		return "", fmt.Errorf("add audio track: %w", err)
	}
	gc.audioTrack = track

	videoTrack, err := gc.conn.AddVideoTrack(gc.videoCodecMime)
	if err != nil {
		return "", fmt.Errorf("add video track: %w", err)
	}
	gc.videoTrack = videoTrack

	gc.bwe.setCallback(func(e BandwidthEstimate) {
		if gc.OnBandwidthEstimate != nil {
			gc.OnBandwidthEstimate(e)
		}
	})
	gc.bwe.attach(gc.conn.VideoSender())
	gc.bwe.attach(gc.conn.AudioSender())

	joinPayload, err := gc.conn.GetJoinPayload()
	if err != nil {
		return "", fmt.Errorf("get join payload: %w", err)
	}

	gc.log.Debugf("join payload: %s", joinPayload)

	serverResponse := reuseServerResponse
	if serverResponse != "" {
		gc.log.Infof("reusing cached server response (skipping PhoneJoinGroupCall to avoid flood)")
	} else {
		me, err := gc.client.GetMe()
		if err != nil {
			return "", fmt.Errorf("get me: %w", err)
		}

		updates, err := gc.client.PhoneJoinGroupCall(&telegram.PhoneJoinGroupCallParams{
			Call:   *call,
			JoinAs: &telegram.InputPeerUser{UserID: me.ID, AccessHash: me.AccessHash},
			Params: &telegram.DataJson{Data: joinPayload},
			Muted:  false,
		})
		if err != nil {
			return "", fmt.Errorf("join group call: %w", err)
		}

		serverResponse, err = extractConnectionParams(updates)
		if err != nil {
			return "", fmt.Errorf("extract connection params: %w", err)
		}
	}

	gc.log.Debugf("server response: %s", serverResponse)

	if err := gc.conn.Connect(serverResponse); err != nil {
		return serverResponse, fmt.Errorf("connect: %w", err)
	}

	select {
	case <-connected:
		return serverResponse, nil
	case <-disconnected:
		return serverResponse, fmt.Errorf("%w: disconnected before connected (ICE failed)", errRetryable)
	case <-ctx.Done():
		return serverResponse, ctx.Err()
	case <-time.After(10 * time.Second):
		return serverResponse, fmt.Errorf("%w: timed out waiting for connected state", errRetryable)
	}
}

func (gc *GroupCall) leaveCallSilent() error {
	if gc.call != nil {
		_, _ = gc.client.PhoneLeaveGroupCall(*gc.call, int32(gc.conn.OutgoingAudioSsrc()))
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
	err := media.Stream(ctx, gc.Sender(), gc.AudioSSRC(), gc.VideoSSRC(), src)
	if gc.OnStreamEnded != nil {
		gc.OnStreamEnded(err)
	}
	return err
}

// Play starts a media source and returns a controllable Player (pause/resume/stop).
func (gc *GroupCall) Play(ctx context.Context, src media.Source) *media.Player {
	p := media.Play(ctx, gc.Sender(), gc.AudioSSRC(), gc.VideoSSRC(), src)
	if gc.OnStreamEnded != nil {
		go func() {
			gc.OnStreamEnded(<-p.Done())
		}()
	}
	return p
}

func (gc *GroupCall) Client() *telegram.Client { return gc.client }

func (gc *GroupCall) Call() *telegram.InputGroupCall { return gc.call }

func (gc *GroupCall) Connection() *transport.GroupConnection {
	return gc.conn
}

func (gc *GroupCall) Leave() error {
	gc.reconnMu.Lock()
	gc.leaving = true
	gc.reconnMu.Unlock()
	if gc.call != nil {
		_, err := gc.client.PhoneLeaveGroupCall(*gc.call, int32(gc.conn.OutgoingAudioSsrc()))
		if err != nil {
			gc.log.Warnf("leave group call error: %v", err)
		}
	}
	return gc.conn.Close()
}

func (gc *GroupCall) maybeStartReconnect() {
	gc.reconnMu.Lock()
	if !gc.reconnect.enabled || gc.leaving || gc.reconnRun || gc.chatID == nil || !gc.everConnected {
		gc.reconnMu.Unlock()
		return
	}
	gc.reconnRun = true
	gc.everConnected = false
	chatID := gc.chatID
	policy := gc.reconnect
	gc.reconnMu.Unlock()

	go gc.reconnectLoop(chatID, policy)
}

func (gc *GroupCall) reconnectLoop(chatID any, p reconnectPolicy) {
	defer func() {
		gc.reconnMu.Lock()
		gc.reconnRun = false
		gc.reconnMu.Unlock()
	}()

	backoff := p.base
	for attempt := 1; ; attempt++ {
		gc.reconnMu.Lock()
		if gc.leaving {
			gc.reconnMu.Unlock()
			return
		}
		gc.reconnMu.Unlock()

		if p.maxAttempts > 0 && attempt > p.maxAttempts {
			gc.log.Warnf("reconnect: giving up after %d attempts", p.maxAttempts)
			if gc.OnReconnectFailed != nil {
				gc.OnReconnectFailed(fmt.Errorf("reconnect: exhausted %d attempts", p.maxAttempts))
			}
			return
		}

		if gc.OnReconnecting != nil {
			gc.OnReconnecting(attempt)
		}
		gc.log.Infof("reconnect attempt %d (backoff=%s)", attempt, backoff)

		time.Sleep(backoff)
		backoff *= 2
		if backoff > p.max {
			backoff = p.max
		}

		gc.reconnMu.Lock()
		if gc.leaving {
			gc.reconnMu.Unlock()
			return
		}
		gc.reconnMu.Unlock()

		_ = gc.leaveCallSilent()
		gc.conn = transport.NewGroupConnection(gc.log.With("subsystem", "transport"))

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err := gc.joinOnce(ctx, chatID, "")
		cancel()
		if err == nil {
			gc.log.Infof("reconnected after %d attempt(s)", attempt)
			if gc.OnReconnected != nil {
				gc.OnReconnected()
			}
			return
		}
		gc.log.Warnf("reconnect attempt %d failed: %v", attempt, err)
	}
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
