// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package confcall

import "context"

type IncomingConferenceCall struct {
	cc     *ConferenceCall
	msgID  int32
	callID int64
	video  bool
}

func (ic *IncomingConferenceCall) MessageID() int32 { return ic.msgID }

func (ic *IncomingConferenceCall) CallID() int64 { return ic.callID }

func (ic *IncomingConferenceCall) Video() bool { return ic.video }

// Accept joins the conference call by message ID.
func (ic *IncomingConferenceCall) Accept(ctx context.Context) error {
	return ic.cc.JoinFromInvite(ctx, ic.msgID)
}

// Decline sends phone.declineConferenceCallInvite.
func (ic *IncomingConferenceCall) Decline(ctx context.Context) error {
	return ic.cc.Decline(ctx, ic.msgID)
}
