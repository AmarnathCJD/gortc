// Minimal example: create or join a Telegram E2E conference call and
// stream an audio file into it.
//
//	go run . create path/to/audio.ogg          # create + share slug
//	go run . join <slug> path/to/audio.ogg     # join by slug
package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
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

	cc := confcall.New(client, confcall.WithLogLevel(slog.LevelInfo))
	cc.OnConnected = func() { log.Println("connected") }
	cc.OnDisconnected = func() { log.Println("disconnected") }
	cc.OnEmojiReady = func(em []string) { log.Printf("verify emojis: %v", em) }

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
		f, err := os.Open(audioPath)
		if err != nil {
			log.Printf("open audio: %v", err)
			return
		}
		defer f.Close()
		log.Printf("streaming %s...", audioPath)
		if err := cc.Stream(ctx, media.FromOggOpus(f)); err != nil {
			log.Printf("stream: %v", err)
		}
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
