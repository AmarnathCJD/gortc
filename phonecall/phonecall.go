// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package phonecall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/amarnathcjd/gortc/logger"
	"github.com/amarnathcjd/gortc/media"
	"github.com/amarnathcjd/gortc/webrtc/webrtc"

	"github.com/amarnathcjd/gogram/telegram"
)

func protocol() *telegram.PhoneCallProtocol {
	return &telegram.PhoneCallProtocol{
		UdpP2P:          true,
		UdpReflector:    true,
		MinLayer:        65,
		MaxLayer:        92,
		LibraryVersions: []string{"9.0.0", "8.0.0"},
	}
}

func acceptProtocol(callerProtocol *telegram.PhoneCallProtocol) *telegram.PhoneCallProtocol {
	p := protocol()
	if callerProtocol == nil {
		return p
	}
	shared := intersectVersions(callerProtocol.LibraryVersions, p.LibraryVersions)
	if len(shared) == 0 {
		shared = callerProtocol.LibraryVersions
	}
	p.LibraryVersions = shared
	if callerProtocol.MinLayer != 0 {
		p.MinLayer = callerProtocol.MinLayer
	}
	if callerProtocol.MaxLayer != 0 {
		p.MaxLayer = callerProtocol.MaxLayer
	}
	return p
}

func intersectVersions(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, v := range b {
		set[v] = struct{}{}
	}
	var out []string
	for _, v := range a {
		if _, ok := set[v]; ok {
			out = append(out, v)
		}
	}
	return out
}

type Option func(*PhoneCall)

func WithLogger(l *logger.Logger) Option {
	return func(pc *PhoneCall) {
		if l != nil {
			pc.log = l
		}
	}
}

func WithLogLevel(level slog.Level) Option {
	return func(pc *PhoneCall) {
		pc.log = logger.New(logger.WithLevel(level))
	}
}

type PhoneCall struct {
	client *telegram.Client
	log    *logger.Logger

	mu       sync.Mutex
	dh       *dhParams
	call     *telegram.InputPhoneCall
	conn     *connection
	sig      *signaling
	secret   *big.Int
	gAHash   []byte
	isCaller bool

	accepted     chan *telegram.PhoneCallAccepted
	confirmed    chan *telegram.PhoneCallObj
	discarded    chan *telegram.PhoneCallDiscarded
	handlersOnce sync.Once

	onIncoming           func(*IncomingCall)
	onConnected          func()
	onDisconnected       func()
	onStateChange        func(string)
	onTrack              func(*media.IncomingTrack)
	onStreamEnded        func(error)
	onMigrationRequested func(slug string)
}

func New(client *telegram.Client, opts ...Option) *PhoneCall {
	pc := &PhoneCall{
		client:    client,
		log:       logger.New(),
		accepted:  make(chan *telegram.PhoneCallAccepted, 1),
		confirmed: make(chan *telegram.PhoneCallObj, 1),
		discarded: make(chan *telegram.PhoneCallDiscarded, 1),
	}
	for _, o := range opts {
		o(pc)
	}
	return pc
}

func (pc *PhoneCall) resetForNewCall() {
	pc.mu.Lock()
	old := pc.conn
	pc.conn = nil
	pc.sig = nil
	pc.call = nil
	pc.dh = nil
	pc.secret = nil
	pc.gAHash = nil
	pc.mu.Unlock()

	if old != nil {
		_ = old.close()
	}

	for {
		select {
		case <-pc.accepted:
		case <-pc.confirmed:
		case <-pc.discarded:
		default:
			return
		}
	}
}

func (pc *PhoneCall) OnConnected(fn func())         { pc.onConnected = fn }
func (pc *PhoneCall) OnDisconnected(fn func())      { pc.onDisconnected = fn }
func (pc *PhoneCall) OnStateChange(fn func(string)) { pc.onStateChange = fn }

// OnMigrationRequested fires when the peer ends the 1:1 with a
// MigrateConferenceCall discard reason — they want to promote the call
// into an E2E conference. The user is handed the conference link slug
// and can choose to join it via confcall.Join.
func (pc *PhoneCall) OnMigrationRequested(fn func(slug string)) {
	pc.onMigrationRequested = fn
}

func (pc *PhoneCall) OnIncomingCall(fn func(*IncomingCall)) {
	pc.onIncoming = fn
	pc.installHandlers()
}

func (pc *PhoneCall) State() string {
	pc.mu.Lock()
	conn := pc.conn
	pc.mu.Unlock()
	if conn == nil {
		return "new"
	}
	return conn.State()
}

func (pc *PhoneCall) installHandlers() {
	pc.handlersOnce.Do(func() {
		pc.client.OnRaw(&telegram.UpdatePhoneCall{}, func(m telegram.Update, _ *telegram.Client) error {
			u, ok := m.(*telegram.UpdatePhoneCall)
			if !ok {
				return nil
			}
			pc.routeCallUpdate(u.PhoneCall)
			return nil
		})
		pc.client.OnRaw(&telegram.UpdatePhoneCallSignalingData{}, func(m telegram.Update, _ *telegram.Client) error {
			u, ok := m.(*telegram.UpdatePhoneCallSignalingData)
			if !ok {
				return nil
			}
			pc.routeSignaling(u)
			return nil
		})
	})
}

func (pc *PhoneCall) routeCallUpdate(call telegram.PhoneCall) {
	switch c := call.(type) {
	case *telegram.PhoneCallAccepted:
		pc.log.Debugf("[p2p] update: phoneCallAccepted id=%d", c.ID)
		select {
		case pc.accepted <- c:
		default:
		}
	case *telegram.PhoneCallObj:
		pc.log.Debugf("[p2p] update: phoneCall(obj) id=%d connections=%d", c.ID, len(c.Connections))
		select {
		case pc.confirmed <- c:
		default:
		}
	case *telegram.PhoneCallDiscarded:
		pc.log.Debugf("[p2p] update: phoneCallDiscarded id=%d reason=%s need_rating=%v need_debug=%v",
			c.ID, discardReasonName(c.Reason), c.NeedRating, c.NeedDebug)
		if mig, ok := c.Reason.(*telegram.PhoneCallDiscardReasonMigrateConferenceCall); ok {
			pc.log.Debugf("[p2p] migrate-to-conference requested: slug=%q", mig.Slug)
			if pc.onMigrationRequested != nil {
				pc.onMigrationRequested(mig.Slug)
			}
		}
		select {
		case pc.discarded <- c:
		default:
		}
		pc.mu.Lock()
		conn := pc.conn
		pc.conn = nil
		pc.sig = nil
		pc.mu.Unlock()
		if conn != nil {
			pc.log.Debugf("[p2p] peer ended call; closing connection")
			_ = conn.close()
		}
	case *telegram.PhoneCallWaiting:
		pc.log.Debugf("[p2p] update: phoneCallWaiting id=%d", c.ID)
	case *telegram.PhoneCallRequested:
		pc.log.Debugf("[p2p] update: phoneCallRequested id=%d from=%d", c.ID, c.AdminID)
		if pc.onIncoming != nil {
			pc.onIncoming(&IncomingCall{pc: pc, req: c})
		}
	default:
		pc.log.Debugf("[p2p] update: phoneCall variant %T", c)
	}
}

func discardReasonName(r telegram.PhoneCallDiscardReason) string {
	switch r.(type) {
	case *telegram.PhoneCallDiscardReasonBusy:
		return "busy"
	case *telegram.PhoneCallDiscardReasonMissed:
		return "missed"
	case *telegram.PhoneCallDiscardReasonDisconnect:
		return "disconnect"
	case *telegram.PhoneCallDiscardReasonHangup:
		return "hangup"
	case *telegram.PhoneCallDiscardReasonMigrateConferenceCall:
		return "migrate-to-conference"
	default:
		return fmt.Sprintf("%T", r)
	}
}

func (pc *PhoneCall) routeSignaling(u *telegram.UpdatePhoneCallSignalingData) {
	pc.mu.Lock()
	call, sig, conn := pc.call, pc.sig, pc.conn
	pc.mu.Unlock()
	pc.log.Debugf("[p2p] <- signaling update for call %d (%d bytes)", u.PhoneCallID, len(u.Data))
	if call == nil || sig == nil || conn == nil {
		pc.log.Debugf("[p2p] signaling arrived before connection ready (call=%v sig=%v conn=%v); dropping",
			call != nil, sig != nil, conn != nil)
		return
	}
	if call.ID != u.PhoneCallID {
		pc.log.Debugf("[p2p] signaling call-id mismatch: have %d, got %d", call.ID, u.PhoneCallID)
		return
	}
	msgs, err := sig.decryptMessages(u.Data)
	if err != nil {
		pc.log.Debugf("[p2p] drop signaling: %v", err)
		return
	}
	for _, plain := range msgs {
		pc.log.Debugf("[p2p] <- decrypted signaling (%d bytes): %s", len(plain), truncate(plain, 200))
		if err := conn.onSignal(plain); err != nil {
			pc.log.Warnf("[p2p] handle signaling: %v", err)
		}
	}
	pc.flushAcks()
}

func (pc *PhoneCall) flushAcks() {
	pc.mu.Lock()
	sig, call := pc.sig, pc.call
	pc.mu.Unlock()
	if sig == nil || call == nil {
		return
	}
	seqs := sig.drainAcks()
	if len(seqs) == 0 {
		return
	}
	ct, err := sig.encryptAcks(seqs)
	if err != nil || ct == nil {
		return
	}
	if _, err := pc.client.PhoneSendSignalingData(call, ct); err != nil {
		pc.log.Debugf("[p2p] send acks: %v", err)
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

func (pc *PhoneCall) Request(ctx context.Context, userID any) error {
	pc.installHandlers()
	pc.resetForNewCall()

	user, err := pc.client.GetSendableUser(userID)
	if err != nil {
		return fmt.Errorf("resolve user: %w", err)
	}
	pc.log.Debugf("[p2p] requesting call: resolved user")

	dh, err := getDH(pc.client)
	if err != nil {
		return err
	}
	pc.log.Debugf("[p2p] got dh config (prime %d bits)", dh.p.BitLen())
	a, gA, gAHash, err := dh.genGA()
	if err != nil {
		return err
	}

	resp, err := pc.client.PhoneRequestCall(&telegram.PhoneRequestCallParams{
		Video:    true,
		UserID:   user,
		RandomID: randomID(),
		GAHash:   gAHash,
		Protocol: protocol(),
	})
	if err != nil {
		return fmt.Errorf("request call: %w", err)
	}

	waiting, ok := resp.PhoneCall.(*telegram.PhoneCallWaiting)
	if !ok {
		return fmt.Errorf("unexpected request-call response %T", resp.PhoneCall)
	}
	pc.log.Debugf("[p2p] requestCall ok: call id=%d, waiting for peer to accept", waiting.ID)

	pc.mu.Lock()
	pc.dh = dh
	pc.secret = a
	pc.gAHash = gAHash
	pc.isCaller = true
	pc.call = &telegram.InputPhoneCall{ID: waiting.ID, AccessHash: waiting.AccessHash}
	pc.mu.Unlock()

	var accepted *telegram.PhoneCallAccepted
	select {
	case accepted = <-pc.accepted:
		pc.log.Debugf("[p2p] peer accepted (call id=%d); computing shared key", accepted.ID)
	case d := <-pc.discarded:
		pc.log.Debugf("[p2p] call discarded while waiting for accept")
		return discardError(d)
	case <-ctx.Done():
		return ctx.Err()
	}

	key, fingerprint, err := dh.computeKey(accepted.GB, a)
	if err != nil {
		return err
	}

	pc.mu.Lock()
	pc.call = &telegram.InputPhoneCall{ID: accepted.ID, AccessHash: accepted.AccessHash}
	call := *pc.call
	pc.mu.Unlock()

	pc.log.Debugf("[p2p] sending confirmCall (fingerprint=%d)", fingerprint)
	confirm, err := pc.client.PhoneConfirmCall(&call, gA, fingerprint, protocol())
	if err != nil {
		return fmt.Errorf("confirm call: %w", err)
	}
	obj, ok := confirm.PhoneCall.(*telegram.PhoneCallObj)
	if !ok {
		return fmt.Errorf("unexpected confirm-call response %T", confirm.PhoneCall)
	}
	pc.log.Debugf("[p2p] confirmCall ok: phoneCallObj id=%d, %d connections", obj.ID, len(obj.Connections))

	return pc.startCall(ctx, key, true, obj.Connections)
}

func (pc *PhoneCall) startCall(ctx context.Context, key []byte, isOutgoing bool, conns []telegram.PhoneConnection) error {
	pc.log.Debugf("[p2p] starting call: outgoing=%v, %d connection endpoints", isOutgoing, len(conns))
	for _, c := range conns {
		if w, ok := c.(*telegram.PhoneConnectionWebrtc); ok {
			pc.log.Debugf("[p2p] endpoint webrtc: ip=%s ipv6=%s port=%d turn=%v stun=%v",
				w.Ip, w.Ipv6, w.Port, w.Turn, w.Stun)
		} else {
			pc.log.Debugf("[p2p] endpoint (non-webrtc/legacy reflector): %T", c)
		}
	}

	conn := newConnection(isOutgoing, pc.log)
	conn.onDisconnected = pc.onDisconnected
	conn.onStateChange = pc.onStateChange
	conn.onTrack = func(t *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		if pc.onTrack != nil {
			pc.onTrack(media.NewIncomingTrack(t))
		}
	}

	connected := make(chan struct{}, 1)
	conn.onConnected = func() {
		select {
		case connected <- struct{}{}:
		default:
		}
		if pc.onConnected != nil {
			pc.onConnected()
		}
	}

	sig := newSignaling(key, isOutgoing)
	conn.emit = func(plain []byte) {
		pc.log.Debugf("[p2p] -> sending signaling (%d bytes plaintext)", len(plain))
		ct, err := sig.encryptMessage(plain)
		if err != nil {
			pc.log.Warnf("[p2p] encrypt signaling: %v", err)
			return
		}
		pc.mu.Lock()
		call := pc.call
		pc.mu.Unlock()
		if call == nil {
			return
		}
		if _, err := pc.client.PhoneSendSignalingData(call, ct); err != nil {
			pc.log.Warnf("[p2p] send signaling: %v", err)
		}
	}

	if err := conn.open(conns); err != nil {
		return err
	}

	pc.mu.Lock()
	pc.conn = conn
	pc.sig = sig
	pc.mu.Unlock()

	if err := conn.start(); err != nil {
		return err
	}

	select {
	case <-connected:
		pc.log.Debugf("[p2p] call connected")
		return nil
	case d := <-pc.discarded:
		_ = conn.close()
		return discardError(d)
	case <-time.After(45 * time.Second):
		_ = conn.close()
		return fmt.Errorf("timed out waiting for call to connect")
	case <-ctx.Done():
		_ = conn.close()
		return ctx.Err()
	}
}

func (pc *PhoneCall) Stream(ctx context.Context, src media.Source) error {
	pc.mu.Lock()
	conn := pc.conn
	pc.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("not in a call")
	}
	err := media.Stream(ctx, conn.Dispatcher(), conn.AudioSSRC(), conn.VideoSSRC(), src)
	if pc.onStreamEnded != nil {
		pc.onStreamEnded(err)
	}
	return err
}

func (pc *PhoneCall) Play(ctx context.Context, src media.Source) (*media.Player, error) {
	pc.mu.Lock()
	conn := pc.conn
	pc.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("not in a call")
	}
	p := media.Play(ctx, conn.Dispatcher(), conn.AudioSSRC(), conn.VideoSSRC(), src)
	if pc.onStreamEnded != nil {
		go func() {
			pc.onStreamEnded(<-p.Done())
		}()
	}
	return p, nil
}

func (pc *PhoneCall) OnStreamEnded(fn func(error)) { pc.onStreamEnded = fn }

func (pc *PhoneCall) Hangup() error {
	return pc.discard(&telegram.PhoneCallDiscardReasonHangup{})
}

func (pc *PhoneCall) discard(reason telegram.PhoneCallDiscardReason) error {
	pc.mu.Lock()
	call := pc.call
	conn := pc.conn
	pc.call = nil
	pc.conn = nil
	pc.mu.Unlock()

	var firstErr error
	if call != nil {
		if _, err := pc.client.PhoneDiscardCall(&telegram.PhoneDiscardCallParams{
			Peer:   call,
			Reason: reason,
		}); err != nil {
			firstErr = err
		}
	}
	if conn != nil {
		if err := conn.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func discardError(d *telegram.PhoneCallDiscarded) error {
	reason := "ended"
	switch d.Reason.(type) {
	case *telegram.PhoneCallDiscardReasonBusy:
		reason = "busy"
	case *telegram.PhoneCallDiscardReasonMissed:
		reason = "missed"
	case *telegram.PhoneCallDiscardReasonDisconnect:
		reason = "disconnected"
	case *telegram.PhoneCallDiscardReasonHangup:
		reason = "hung up"
	}
	return fmt.Errorf("call discarded: %s", reason)
}

func verifyCommitment(gA, hash []byte) error {
	sum := sha256.Sum256(gA)
	if !bytes.Equal(sum[:], hash) {
		return fmt.Errorf("g_a hash commitment mismatch")
	}
	return nil
}
