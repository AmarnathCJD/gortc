// Command basic joins a Telegram group call and streams a media file into it
// using the high-level gortc API.
//
//	export API_ID=...    # https://my.telegram.org/apps
//	export API_HASH=...
//	go run ./examples/basic <source> [chat]
//
// source may be a file path, a URL, or anything ffmpeg can decode.
// chat defaults to @gogrammers.
package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/amarnathcjd/gortc"

	"github.com/amarnathcjd/gogram/telegram"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <source> [chat]", os.Args[0])
	}
	source := os.Args[1]
	chatID := "@gogrammers"
	if len(os.Args) > 2 {
		chatID = os.Args[2]
	}

	apiID, _ := strconv.Atoi(mustEnv("API_ID"))
	client, err := telegram.NewClient(telegram.ClientConfig{
		AppID:   int32(apiID),
		AppHash: mustEnv("API_HASH"),
		Session: "examples/basic/session.dat",
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	if _, err := client.Conn(); err != nil {
		log.Fatalf("connect: %v", err)
	}
	client.AuthPrompt()

	call := gortc.NewCall(client, gortc.WithLogLevel(slog.LevelInfo))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	call.OnConnected(func() {
		log.Printf("connected, streaming %s ...", source)
		go func() {
			if err := call.Stream(ctx, gortc.FromFile(source)); err != nil {
				log.Printf("stream error: %v", err)
				return
			}
			log.Println("stream finished")
		}()
	})

	log.Printf("joining group call in %s ...", chatID)
	if err := call.Join(chatID); err != nil {
		log.Fatalf("join call: %v", err)
	}
	log.Println("joined, press Ctrl+C to leave")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("leaving group call ...")
	if err := call.Leave(); err != nil {
		log.Printf("leave error: %v", err)
	}
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env: %s", k)
	}
	return v
}
