// Command basic joins a Telegram group call and streams a media file into it
// using the high-level gortc API.
//
//	go run ./examples/basic [source]
//
// source may be a file path, a URL, or anything ffmpeg can decode. If omitted,
// a default file is used.
package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/amarnathcjd/gortc"

	"github.com/amarnathcjd/gogram/telegram"
)

func main() {
	client, err := telegram.NewClient(telegram.ClientConfig{
		AppID:   2040,
		AppHash: "b18441a1ff607e10a989891a5462e627",
		Session: "session.dat",
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	client.Conn()

	source := "movie.mp4"
	if len(os.Args) > 1 {
		source = os.Args[1]
	}

	call := gortc.NewCall(client, gortc.WithLogLevel(slog.LevelInfo))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	call.OnConnected(func() {
		log.Printf("connected, streaming %s ...", source)
		go func() {
			if err := call.Stream(ctx, gortc.FromFile(source)); err != nil {
				log.Printf("stream error: %v", err)
			}
			log.Println("stream finished")
		}()
	})

	const chatID = "@gogrammers"
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
