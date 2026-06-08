// Minimal example: create or join a Telegram E2E conference call and
// stream a media file into it.
//
//	go run . create path/to/audio.mp3          # create + share slug
//	go run . join <slug> path/to/audio.mp3     # join by slug
//
// Accepts any format ffmpeg understands (mp3, mp4, mkv, wav, ogg, ...).
package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/confcall"
	"github.com/amarnathcjd/gortc/media"
	_ "github.com/joho/godotenv/autoload"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s {create|join <slug>} <audio.ogg>", os.Args[0])
	}

	apiID, _ := strconv.Atoi(mustEnv("API_ID"))
	client, err := telegram.NewClient(telegram.ClientConfig{
		AppID:   int32(apiID),
		AppHash: mustEnv("API_HASH"),
		Session: "examples/confcall/session.dat",
	})
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	if _, err := client.Conn(); err != nil {
		log.Fatalf("conn: %v", err)
	}
	client.AuthPrompt()

	cc := confcall.New(client, confcall.WithLogLevel(slog.LevelDebug))
	connected := make(chan struct{}, 1)
	peerReady := make(chan struct{}, 1)
	cc.OnConnected = func() {
		log.Println("connected")
		select {
		case connected <- struct{}{}:
		default:
		}
	}
	cc.OnDisconnected = func() { log.Println("disconnected") }
	cc.OnEmojiReady = func(em []string) {
		log.Printf("verify emojis: %v", em)
		// A peer has joined and finished commit-reveal; safe to send media.
		if cc.Chain() != nil && len(cc.Chain().Snapshot().Participants) > 1 {
			select {
			case peerReady <- struct{}{}:
			default:
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var audioPath string
	switch os.Args[1] {
	case "create":
		slug, err := cc.Create(ctx, true)
		if err != nil {
			log.Fatalf("create: %v", err)
		}
		log.Printf("call created — share slug: %s", slug)
		audioPath = os.Args[2]
	case "join":
		if len(os.Args) < 4 {
			log.Fatalf("usage: %s join <slug> <audio.ogg>", os.Args[0])
		}
		if err := cc.Join(ctx, os.Args[2]); err != nil {
			log.Fatalf("join: %v", err)
		}
		audioPath = os.Args[3]
	default:
		log.Fatalf("unknown command %q (use create or join)", os.Args[1])
	}

	go func() {
		// Wait for the WebRTC PeerConnection AND for a peer to finish E2E
		// verification — otherwise the SFU drops our RTP or the peer can't
		// decrypt it (you hear silence on the other end).
		select {
		case <-connected:
		case <-ctx.Done():
			return
		}
		log.Println("waiting for a peer to join + verify...")
		select {
		case <-peerReady:
		case <-ctx.Done():
			return
		}
		// Pre-transcode to raw Ogg/Opus once, then stream the file directly via
		// FromOggOpus. The runtime FromFile path runs ffmpeg in a pipe, which
		// can stall on inputs with non-monotonic timestamps (Theora/Vorbis ogg
		// containers in particular).
		oggPath, err := ensureOpus(audioPath)
		if err != nil {
			log.Printf("transcode to opus: %v", err)
			return
		}
		f, err := os.Open(oggPath)
		if err != nil {
			log.Printf("open ogg: %v", err)
			return
		}
		defer f.Close()
		log.Printf("streaming %s...", oggPath)
		if err := cc.Stream(ctx, media.FromOggOpus(f)); err != nil {
			log.Printf("stream: %v", err)
			return
		}
		log.Println("stream finished")
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("leaving call...")
	_ = cc.Leave(context.Background())
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env: %s", k)
	}
	return v
}

// ensureOpus returns a path to a raw Ogg/Opus version of src. If src already
// has a .opus or .ogg extension AND its first packet is OpusHead, it's used
// as-is; otherwise ffmpeg transcodes it to a sibling file with .opus.ogg
// appended (cached: skipped if the transcoded file already exists).
func ensureOpus(src string) (string, error) {
	if isOggOpus(src) {
		return src, nil
	}
	out := strings.TrimSuffix(src, filepath.Ext(src)) + ".opus.ogg"
	if _, err := os.Stat(out); err == nil {
		return out, nil
	}
	log.Printf("transcoding to ogg/opus: %s", out)
	cmd := exec.Command("ffmpeg",
		"-y",
		"-i", src,
		"-vn",
		"-c:a", "libopus",
		"-b:a", "64k",
		"-ar", "48000",
		"-ac", "2",
		out,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return out, nil
}

// isOggOpus returns true if path begins with an Ogg page that carries an
// OpusHead packet — i.e. it's already raw Ogg/Opus and can be streamed
// without re-encoding.
func isOggOpus(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	buf = buf[:n]
	return strings.HasPrefix(string(buf), "OggS") && strings.Contains(string(buf), "OpusHead")
}
