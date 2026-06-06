// Minimal example: create a Telegram E2E conference call, share the
// slug, and stream a media file into it. Joiners can use Join(slug).
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/amarnathcjd/gogram/telegram"
	"github.com/amarnathcjd/gortc/confcall"
	"github.com/amarnathcjd/gortc/logger"
	"github.com/amarnathcjd/gortc/media"
	_ "github.com/joho/godotenv/autoload"
)

// notifyTG sends `text` to TG_CHAT_ID via TG_BOT_TOKEN. Silent fail if either is unset.
func notifyTG(text string) {
	tok := os.Getenv("TG_BOT_TOKEN")
	chat := os.Getenv("TG_CHAT_ID")
	if tok == "" || chat == "" {
		return
	}
	resp, err := http.PostForm(
		fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tok),
		url.Values{"chat_id": {chat}, "text": {text}, "disable_web_page_preview": {"false"}},
	)
	if err != nil {
		log.Printf("tg notify: %v", err)
		return
	}
	resp.Body.Close()
}

func main() {
	apiID, _ := strconv.Atoi(env("API_ID"))
	apiHash := env("API_HASH")

	client, err := telegram.NewClient(telegram.ClientConfig{
		AppID:         int32(apiID),
		AppHash:       apiHash,
		StringSession: os.Getenv("SESSION_STRING"),
		Session:       "examples/confcall/session.dat",
	})
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	if _, err := client.Conn(); err != nil {
		log.Fatalf("conn: %v", err)
	}
	if _, err := client.GetMe(); err != nil {
		log.Fatalf("not logged in: %v", err)
	}

	cc := confcall.New(client, confcall.WithLogger(logger.New(logger.WithLevel(slog.LevelDebug))))
	cc.OnConnected = func() { log.Println("connected to conference call") }
	cc.OnDisconnected = func() { log.Println("disconnected") }
	cc.OnEmojiReady = func(em []string) { log.Printf("verify emojis: %v", em) }
	cc.OnBlockApplied = func(h int) { log.Printf("chain advanced to height %d", h) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Toggle: GORTC_CREATE_ONLY=1 to call create without joining
	// (skips WebRTC offer, simpler diagnostic).
	joinImmediately := os.Getenv("GORTC_CREATE_ONLY") != "1"
	slug, err := cc.Create(ctx, joinImmediately)
	if err != nil {
		log.Printf("create FAILED: %v", err)
		// GORTC_EXIT_ON_ERR=1 makes this script exit non-zero on create
		// failure so it can be driven from a debug loop.
		if os.Getenv("GORTC_EXIT_ON_ERR") == "1" {
			os.Exit(1)
		}
		log.Fatalf("create: %v", err)
	}
	log.Printf("call created. slug: %s", slug)
	log.Printf("share: %s", slug)
	notifyTG(fmt.Sprintf("📞 gortc conference call live!\n\nJoin: %s\n\nStreaming audio in 2s.", slug))

	// GORTC_EXIT_AFTER_CREATE=1: success path bails out after creating.
	if os.Getenv("GORTC_EXIT_AFTER_CREATE") == "1" {
		log.Println("create succeeded, exiting (GORTC_EXIT_AFTER_CREATE=1)")
		_ = cc.Leave(context.Background())
		return
	}

	// If a target user is set, ring them.
	if uid := os.Getenv("RING_USER"); uid != "" {
		if err := cc.Invite(ctx, uid, false); err != nil {
			log.Printf("invite %s: %v", uid, err)
		} else {
			log.Printf("rang user %s", uid)
		}
	}

	// Stream a file if given.
	if path := os.Getenv("STREAM_FILE"); path != "" {
		go func() {
			time.Sleep(2 * time.Second)
			log.Printf("streaming %s...", path)
			src := media.FromFile(path, media.EncodeOptions{AudioBitrateKbps: 64})
			if err := cc.Stream(ctx, src); err != nil {
				log.Printf("stream: %v", err)
				notifyTG(fmt.Sprintf("⚠️ stream error: %v", err))
				return
			}
			log.Printf("stream finished")
			notifyTG("✅ audio stream finished playing.")
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("leaving call...")
	if err := cc.Leave(context.Background()); err != nil {
		log.Printf("leave: %v", err)
	}
}

func env(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env: %s", k)
	}
	return v
}
