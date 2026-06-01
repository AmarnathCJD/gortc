// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package groupcall

import (
	"sync"

	"github.com/amarnathcjd/gogram/telegram"
)

type ParticipantEvent int

const (
	ParticipantJoined ParticipantEvent = iota
	ParticipantLeft
	ParticipantUpdated
)

func (e ParticipantEvent) String() string {
	switch e {
	case ParticipantJoined:
		return "joined"
	case ParticipantLeft:
		return "left"
	case ParticipantUpdated:
		return "updated"
	default:
		return "unknown"
	}
}

type Participant struct {
	PeerID        int64
	Source        int32
	Muted         bool
	MutedByYou    bool
	Self          bool
	Volume        int32
	HasVideo      bool
	HasScreencast bool
	RaisedHand    bool
	About         string
	Raw           *telegram.GroupCallParticipant
}

func toParticipant(p *telegram.GroupCallParticipant) Participant {
	return Participant{
		PeerID:        peerID(p.Peer),
		Source:        p.Source,
		Muted:         p.Muted,
		MutedByYou:    p.MutedByYou,
		Self:          p.Self,
		Volume:        p.Volume,
		HasVideo:      p.Video != nil,
		HasScreencast: p.Presentation != nil,
		RaisedHand:    p.RaiseHandRating != 0,
		About:         p.About,
		Raw:           p,
	}
}

func peerID(p telegram.Peer) int64 {
	switch v := p.(type) {
	case *telegram.PeerUser:
		return v.UserID
	case *telegram.PeerChat:
		return v.ChatID
	case *telegram.PeerChannel:
		return v.ChannelID
	}
	return 0
}

type participantStore struct {
	mu sync.Mutex
	m  map[int64]Participant
}

func newParticipantStore() *participantStore {
	return &participantStore{m: make(map[int64]Participant)}
}

func (s *participantStore) snapshot() []Participant {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Participant, 0, len(s.m))
	for _, p := range s.m {
		out = append(out, p)
	}
	return out
}

func (s *participantStore) apply(updates []*telegram.GroupCallParticipant) []participantDelta {
	s.mu.Lock()
	defer s.mu.Unlock()
	var deltas []participantDelta
	for _, raw := range updates {
		id := peerID(raw.Peer)
		if id == 0 {
			continue
		}
		if raw.Left {
			if prev, ok := s.m[id]; ok {
				delete(s.m, id)
				deltas = append(deltas, participantDelta{event: ParticipantLeft, p: prev})
			}
			continue
		}
		next := toParticipant(raw)
		prev, existed := s.m[id]
		s.m[id] = next
		switch {
		case !existed, raw.JustJoined:
			deltas = append(deltas, participantDelta{event: ParticipantJoined, p: next})
		case participantChanged(prev, next):
			deltas = append(deltas, participantDelta{event: ParticipantUpdated, p: next})
		}
	}
	return deltas
}

func participantChanged(a, b Participant) bool {
	return a.Muted != b.Muted ||
		a.MutedByYou != b.MutedByYou ||
		a.Volume != b.Volume ||
		a.HasVideo != b.HasVideo ||
		a.HasScreencast != b.HasScreencast ||
		a.RaisedHand != b.RaisedHand ||
		a.About != b.About
}

type participantDelta struct {
	event ParticipantEvent
	p     Participant
}

func (gc *GroupCall) installParticipantHandler() {
	gc.participantsOnce.Do(func() {
		gc.client.OnRaw(&telegram.UpdateGroupCallParticipants{}, func(u telegram.Update, _ *telegram.Client) error {
			upd, ok := u.(*telegram.UpdateGroupCallParticipants)
			if !ok {
				return nil
			}
			gc.reconnMu.Lock()
			call := gc.call
			gc.reconnMu.Unlock()
			if call == nil {
				return nil
			}
			mine, ok1 := (*call).(*telegram.InputGroupCallObj)
			theirs, ok2 := upd.Call.(*telegram.InputGroupCallObj)
			if !ok1 || !ok2 || mine.ID != theirs.ID {
				return nil
			}
			deltas := gc.participants.apply(upd.Participants)
			fn := gc.OnParticipant
			if fn == nil {
				return nil
			}
			for _, d := range deltas {
				fn(d.event, d.p)
			}
			return nil
		})
	})
}

func (gc *GroupCall) Participants() []Participant {
	if gc.participants == nil {
		return nil
	}
	return gc.participants.snapshot()
}
