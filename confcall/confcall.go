// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

// Package confcall implements Telegram E2E-encrypted conference calls.
package confcall

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"sync"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/confcall/e2e"
	"github.com/amarnathcjd/gortc/media"
	"github.com/amarnathcjd/gortc/transport"
)

type Option func(*ConferenceCall)

func WithLogger(l *transport.Logger) Option {
	return func(cc *ConferenceCall) {
		if l != nil {
			cc.log = l
		}
	}
}

func WithLogLevel(level slog.Level) Option {
	return func(cc *ConferenceCall) {
		cc.log = transport.NewLogger(transport.WithLogLevel(level))
	}
}

// ConferenceCall is a single E2E-encrypted conference call session. Build one
// with New, then drive it via Create / Join / JoinFromInvite.
type ConferenceCall struct {
	client *telegram.Client
	log    *transport.Logger

	mu     sync.Mutex
	call   *telegram.InputGroupCallObj
	slug   string
	conn   *transport.GroupConnection
	chain  *e2e.Chain
	verify *e2e.VerificationChain
	cipher *e2e.PacketCipher

	signer ed25519.PrivateKey
	pubKey ed25519.PublicKey

	selfUID               int64
	lastEmojis            string
	sourceToUID           map[int32]int64
	flushingBroadcasts    bool
	lastReestablishHeight int32

	handlersOnce sync.Once

	OnIncomingConferenceCall func(*IncomingConferenceCall)
	OnConnected              func()
	OnDisconnected           func()
	OnStateChange            func(string)
	OnICEFailed              func()
	OnEmojiReady             func([]string)
	OnBlockApplied           func(height int)
	OnTrack                  func(*media.IncomingTrack)
	OnStreamEnded            func(error)
}

func New(client *telegram.Client, opts ...Option) *ConferenceCall {
	cc := &ConferenceCall{client: client, log: transport.NewLogger()}
	for _, o := range opts {
		o(cc)
	}
	return cc
}

func (cc *ConferenceCall) Call() *telegram.InputGroupCallObj { return cc.call }

func (cc *ConferenceCall) Slug() string { return cc.slug }

func (cc *ConferenceCall) Connection() *transport.GroupConnection { return cc.conn }

func (cc *ConferenceCall) State() string {
	cc.mu.Lock()
	conn := cc.conn
	cc.mu.Unlock()
	if conn == nil {
		return "new"
	}
	return conn.State()
}

func (cc *ConferenceCall) Chain() *e2e.Chain { return cc.chain }

func (cc *ConferenceCall) Cipher() *e2e.PacketCipher { return cc.cipher }

func (cc *ConferenceCall) PublicKey() ed25519.PublicKey { return cc.pubKey }

func (cc *ConferenceCall) EmojiFingerprint() []string {
	if cc.chain == nil {
		return nil
	}
	return cc.chain.EmojiFingerprint()
}

// IncomingConferenceCall represents a ringing MessageActionConferenceCall.
type IncomingConferenceCall struct {
	cc     *ConferenceCall
	msgID  int32
	callID int64
	video  bool
}

func (ic *IncomingConferenceCall) MessageID() int32 { return ic.msgID }
func (ic *IncomingConferenceCall) CallID() int64    { return ic.callID }
func (ic *IncomingConferenceCall) Video() bool      { return ic.video }

func (ic *IncomingConferenceCall) Accept(ctx context.Context) error {
	return ic.cc.JoinFromInvite(ctx, ic.msgID)
}

func (ic *IncomingConferenceCall) Decline(ctx context.Context) error {
	return ic.cc.Decline(ctx, ic.msgID)
}
