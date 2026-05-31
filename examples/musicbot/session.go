package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/amarnathcjd/gortc"
)

type track struct {
	title string
	path  string
	video bool
}

type session struct {
	mu       sync.Mutex
	mgr      *manager
	chatID   int64
	call     *gortc.Call
	queue    []track
	current  *track
	player   *gortc.Player
	gen      uint64
	hadVideo bool
	playing  bool
	volume   int
}

type manager struct {
	mu       sync.Mutex
	sessions map[int64]*session
}

type clientFactory func() *gortc.Call

func newManager() *manager {
	return &manager{sessions: map[int64]*session{}}
}

func (m *manager) get(chatID int64) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[chatID]
	if !ok {
		s = &session{mgr: m, chatID: chatID, volume: 100}
		m.sessions[chatID] = s
	}
	return s
}

func (m *manager) drop(chatID int64) {
	m.mu.Lock()
	delete(m.sessions, chatID)
	m.mu.Unlock()
}

func (s *session) enqueue(t track) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queue = append(s.queue, t)
	if !s.playing {
		return 0, true
	}
	return len(s.queue), false
}

func (s *session) ensureCall(factory clientFactory, chatID any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.call != nil {
		return nil
	}
	call := factory()
	if err := call.Join(chatID); err != nil {
		return err
	}
	s.call = call
	return nil
}

func (s *session) startNext() {
	s.mu.Lock()
	if old := s.player; old != nil {
		s.player = nil
		s.mu.Unlock()
		old.Stop()
		<-old.Done()
		s.mu.Lock()
	}
	if len(s.queue) == 0 {
		s.playing = false
		s.current = nil
		s.hadVideo = false
		call := s.call
		s.call = nil
		s.mu.Unlock()
		if call != nil {
			_ = call.Leave()
		}
		s.mgr.drop(s.chatID)
		return
	}
	next := s.queue[0]
	s.queue = s.queue[1:]
	s.current = &next
	s.playing = true
	s.gen++
	gen := s.gen
	call := s.call
	wasVideo := s.hadVideo
	s.hadVideo = next.video
	ctx, cancel := context.WithCancel(context.Background())
	src := sourceFor(next)
	p := call.Play(ctx, src)
	s.player = p
	s.mu.Unlock()

	if call != nil {
		_ = call.SetVideoStopped(!next.video)
	}
	_ = wasVideo

	go func() {
		<-p.Done()
		cancel()
		removeFile(next.path)
		s.mu.Lock()
		stale := gen != s.gen
		s.mu.Unlock()
		if stale {
			return
		}
		s.startNext()
	}()
}

func (s *session) skip() bool {
	s.mu.Lock()
	if s.player == nil && len(s.queue) == 0 {
		s.mu.Unlock()
		return false
	}
	s.mu.Unlock()
	s.startNext()
	return true
}

func (s *session) pause() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.player == nil || s.player.Paused() {
		return false
	}
	s.player.Pause()
	return true
}

func (s *session) resume() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.player == nil || !s.player.Paused() {
		return false
	}
	s.player.Resume()
	return true
}

func (s *session) stop() {
	s.mu.Lock()
	for _, t := range s.queue {
		removeFile(t.path)
	}
	s.queue = nil
	p := s.player
	s.player = nil
	s.current = nil
	s.playing = false
	s.mu.Unlock()
	if p != nil {
		p.Stop()
	}
}

func (s *session) leave() error {
	s.stop()
	s.mu.Lock()
	call := s.call
	s.call = nil
	s.mu.Unlock()
	if call != nil {
		return call.Leave()
	}
	return nil
}

func (s *session) setVolume(percent int) error {
	s.mu.Lock()
	call := s.call
	s.volume = percent
	s.mu.Unlock()
	if call == nil {
		return fmt.Errorf("not in a call")
	}
	return call.SetVolume(percent)
}

func (s *session) nowPlaying() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return "", false
	}
	return s.current.title, true
}

func (s *session) list() []track {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]track(nil), s.queue...)
}

func sourceFor(t track) gortc.Source {
	if t.video {
		return gortc.FromFile(t.path)
	}
	return gortc.FromFile(t.path, gortc.EncodeOptions{Tracks: gortc.TrackAudio})
}

func removeFile(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

func loadEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("missing required env var: " + key)
	}
	return v
}
