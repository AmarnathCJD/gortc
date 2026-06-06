// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

// Package confcall implements Telegram E2E-encrypted conference calls,
// the "spontaneous group call without a chat" feature introduced in
// April 2025. Unlike groupcall (which trusts the SFU), confcall layers
// an Ed25519-signed append-only chain over the call to derive a per-call
// shared key, and wraps every RTP payload with per-packet authenticated
// encryption that the server cannot read.
//
// Quick start:
//
//	cc := confcall.New(client, confcall.WithLogLevel(slog.LevelDebug))
//	slug, _ := cc.Create(ctx, true)
//	log.Printf("share: t.me/call/%s", slug)
//	cc.OnEmojiReady = func(em []string) { log.Printf("verify: %v", em) }
package confcall

import (
	"crypto/ed25519"
	"log/slog"
	"sync"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/confcall/e2e"
	"github.com/amarnathcjd/gortc/logger"
	"github.com/amarnathcjd/gortc/media"
	"github.com/amarnathcjd/gortc/transport"
)

type Option func(*ConferenceCall)

func WithLogger(l *logger.Logger) Option {
	return func(cc *ConferenceCall) {
		if l != nil {
			cc.log = l
		}
	}
}

func WithLogLevel(level slog.Level) Option {
	return func(cc *ConferenceCall) {
		cc.log = logger.New(logger.WithLevel(level))
	}
}

type ConferenceCall struct {
	client *telegram.Client
	log    *logger.Logger

	mu      sync.Mutex
	call    *telegram.InputGroupCallObj
	slug    string
	conn    *transport.GroupConnection
	chain   *e2e.Chain
	verify  *e2e.VerificationChain
	cipher  *e2e.PacketCipher
	signer  ed25519.PrivateKey
	pubKey  ed25519.PublicKey
	selfUID int64

	handlersOnce sync.Once

	OnIncomingConferenceCall func(*IncomingConferenceCall)
	OnConnected              func()
	OnDisconnected           func()
	OnStateChange            func(string)
	OnEmojiReady             func([]string)
	OnBlockApplied           func(height int)
	OnTrack                  func(*media.IncomingTrack)
	OnStreamEnded            func(error)
}

func New(client *telegram.Client, opts ...Option) *ConferenceCall {
	cc := &ConferenceCall{
		client: client,
		log:    logger.New(),
	}
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
