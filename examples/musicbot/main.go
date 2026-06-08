package main

import (
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/amarnathcjd/gortc"
	"github.com/amarnathcjd/gortc/transport"

	"github.com/amarnathcjd/gogram/telegram"
)

func main() {
	loadEnv(".env")
	loadEnv("examples/musicbot/.env")

	apiID, err := strconv.Atoi(mustEnv("API_ID"))
	if err != nil {
		log.Fatalf("invalid API_ID: %v", err)
	}
	apiHash := mustEnv("API_HASH")

	botClient, err := telegram.NewClient(telegram.ClientConfig{
		AppID:   int32(apiID),
		AppHash: apiHash,
		Session: "examples/musicbot/bot.session",
	})
	if err != nil {
		log.Fatalf("create bot client: %v", err)
	}
	if err := botClient.LoginBot(mustEnv("BOT_TOKEN")); err != nil {
		log.Fatalf("login bot: %v", err)
	}

	assistant, err := telegram.NewClient(telegram.ClientConfig{
		AppID:         int32(apiID),
		AppHash:       apiHash,
		StringSession: os.Getenv("SESSION_STRING"),
		Session:       "examples/musicbot/session.dat",
	})
	if err != nil {
		log.Fatalf("create assistant client: %v", err)
	}
	if _, err := assistant.Conn(); err != nil {
		log.Fatalf("connect assistant: %v", err)
	}
	if _, err := assistant.GetMe(); err != nil {
		log.Fatalf("assistant not logged in: set SESSION_STRING or place a valid assistant.session (login a user account first): %v", err)
	}

	downDir := "examples/musicbot/downloads"
	_ = os.MkdirAll(downDir, 0o755)

	b := &bot{
		client:    botClient,
		assistant: assistant,
		mgr:       newManager(),
		logLevel:  gortc.WithLogger(gortc.NewLogger(transport.WithLogLevel(slog.LevelDebug))),
		downDir:   downDir,
	}
	b.register()

	if me, err := assistant.GetMe(); err == nil {
		log.Printf("assistant: @%s (id %d) will join voice chats", me.Username, me.ID)
	}
	if me, err := botClient.GetMe(); err == nil {
		log.Printf("music bot @%s up. commands: /play /vplay /vp9play /skip /pause /resume /end /leave /volume /queue /stats /participants", me.Username)
	} else {
		log.Println("music bot up")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}
