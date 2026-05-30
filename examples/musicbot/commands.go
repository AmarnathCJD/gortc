package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/amarnathcjd/gortc"

	"github.com/amarnathcjd/gogram/telegram"
)

type bot struct {
	client    *telegram.Client
	assistant *telegram.Client
	mgr       *manager
	logLevel  gortc.Option
	downDir   string
}

func (b *bot) callFactory() *gortc.Call {
	return gortc.NewCall(b.assistant, b.logLevel)
}

func (b *bot) handlePlay(video bool) telegram.MessageHandler {
	return func(m *telegram.NewMessage) error {
		if !m.IsReply() {
			_, err := m.Reply("reply to an audio file with /play")
			return err
		}
		reply, err := m.GetReplyMessage()
		if err != nil {
			return reply2(m, "could not read replied message")
		}
		if !reply.IsMedia() {
			return reply2(m, "replied message has no media")
		}

		status, _ := m.Reply("downloading...")

		name := mediaTitle(reply)
		dst := filepath.Join(b.downDir, fmt.Sprintf("%d_%d_%s", m.ChatID(), reply.ID, sanitize(name)))
		path, err := reply.Download(&telegram.DownloadOptions{FileName: dst})
		if err != nil {
			return edit(status, "download failed: "+err.Error())
		}

		s := b.mgr.get(m.ChatID())
		if err := s.ensureCall(b.callFactory, m.ChatID()); err != nil {
			removeFile(path)
			return edit(status, "failed to join voice chat: "+err.Error())
		}

		pos, startNow := s.enqueue(track{title: name, path: path, video: video})
		if startNow {
			s.startNext()
			return edit(status, "playing: "+name)
		}

		return edit(status, fmt.Sprintf("queued #%d: %s", pos, name))
	}
}

func (b *bot) handleSkip(m *telegram.NewMessage) error {
	s := b.mgr.get(m.ChatID())
	if !s.skip() {
		return reply2(m, "nothing is playing")
	}

	return reply2(m, "skipped")
}

func (b *bot) handlePause(m *telegram.NewMessage) error {
	s := b.mgr.get(m.ChatID())
	if !s.pause() {
		return reply2(m, "nothing to pause")
	}

	return reply2(m, "paused")
}

func (b *bot) handleResume(m *telegram.NewMessage) error {
	s := b.mgr.get(m.ChatID())
	if !s.resume() {
		return reply2(m, "nothing to resume")
	}

	return reply2(m, "resumed")
}

func (b *bot) handleEnd(m *telegram.NewMessage) error {
	s := b.mgr.get(m.ChatID())
	s.stop()
	if err := s.leave(); err != nil {
		return reply2(m, "stopped (leave error: "+err.Error()+")")
	}
	b.mgr.drop(m.ChatID())

	return reply2(m, "stopped and left")
}

func (b *bot) handleLeave(m *telegram.NewMessage) error {
	s := b.mgr.get(m.ChatID())
	if err := s.leave(); err != nil {
		return reply2(m, "leave error: "+err.Error())
	}
	b.mgr.drop(m.ChatID())

	return reply2(m, "left the voice chat")
}

func (b *bot) handleVolume(m *telegram.NewMessage) error {
	args := strings.TrimSpace(m.Args())
	if args == "" {
		return reply2(m, "usage: /volume <0-200>")
	}
	v, err := strconv.Atoi(args)
	if err != nil || v < 0 || v > 200 {
		return reply2(m, "volume must be 0-200")
	}
	s := b.mgr.get(m.ChatID())
	if err := s.setVolume(v); err != nil {
		return reply2(m, "volume error: "+err.Error())
	}

	return reply2(m, fmt.Sprintf("volume set to %d%%", v))
}

func (b *bot) handleQueue(m *telegram.NewMessage) error {
	s := b.mgr.get(m.ChatID())
	now, ok := s.nowPlaying()
	list := s.list()
	var sb strings.Builder
	if ok {
		sb.WriteString("now playing: " + now + "\n")
	} else {
		sb.WriteString("nothing playing\n")
	}
	if len(list) == 0 {
		sb.WriteString("queue is empty")
	} else {
		sb.WriteString("queue:\n")
		for i, t := range list {
			fmt.Fprintf(&sb, "%d. %s\n", i+1, t.title)
		}
	}

	return reply2(m, sb.String())
}

func (b *bot) register() {
	b.client.OnCommand("play", b.handlePlay(false))
	b.client.OnCommand("vplay", b.handlePlay(true))
	b.client.OnCommand("skip", b.handleSkip)
	b.client.OnCommand("pause", b.handlePause)
	b.client.OnCommand("resume", b.handleResume)
	b.client.OnCommand("end", b.handleEnd)
	b.client.OnCommand("stop", b.handleEnd)
	b.client.OnCommand("leave", b.handleLeave)
	b.client.OnCommand("volume", b.handleVolume)
	b.client.OnCommand("queue", b.handleQueue)
}

func reply2(m *telegram.NewMessage, text string) error {
	_, err := m.Reply(text)
	return err
}

func edit(m *telegram.NewMessage, text string) error {
	if m == nil {
		return nil
	}
	_, err := m.Edit(text)
	return err
}

func mediaTitle(m *telegram.NewMessage) string {
	if a := m.Audio(); a != nil {
		for _, attr := range a.Attributes {
			if t, ok := attr.(*telegram.DocumentAttributeAudio); ok {
				if t.Title != "" {
					if t.Performer != "" {
						return t.Performer + " - " + t.Title
					}

					return t.Title
				}
			}
			if f, ok := attr.(*telegram.DocumentAttributeFilename); ok && f.FileName != "" {
				return f.FileName
			}
		}
	}

	return "audio"
}

func sanitize(name string) string {
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	return repl.Replace(name)
}
