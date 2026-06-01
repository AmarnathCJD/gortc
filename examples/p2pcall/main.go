package main

import (
	"bufio"
	"context"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/amarnathcjd/gortc"

	"github.com/amarnathcjd/gogram/telegram"
)

const sampleMedia = "media_file.mp4"

func main() {
	loadEnv(".env")
	loadEnv("examples/p2pcall/.env")

	apiID, err := strconv.Atoi(mustEnv("API_ID"))
	if err != nil {
		log.Fatalf("invalid API_ID: %v", err)
	}

	client, err := telegram.NewClient(telegram.ClientConfig{
		AppID:         int32(apiID),
		AppHash:       mustEnv("API_HASH"),
		StringSession: os.Getenv("SESSION_STRING"),
		Session:       "examples/p2pcall/session.dat",
		LogLevel:      telegram.WarnLevel,
	})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	if _, err := client.Conn(); err != nil {
		log.Fatalf("connect: %v", err)
	}
	me, err := client.GetMe()
	if err != nil {
		log.Fatalf("not logged in: set SESSION_STRING or log in a user account first: %v", err)
	}
	log.Printf("logged in as @%s (id %d)", me.Username, me.ID)

	mediaPath := os.Getenv("MEDIA")
	if mediaPath == "" {
		mediaPath = sampleMedia
	}

	pc := gortc.NewPhoneCall(client, gortc.WithPhoneLogLevel(slog.LevelDebug))

	pc.OnConnected(func() {
		log.Println("call connected; streaming media")
	})
	pc.OnDisconnected(func() {
		log.Println("call disconnected")
	})
	pc.OnTrack(func(kind gortc.TrackKind) {
		if kind == gortc.PhoneTrackVideo {
			log.Println("receiving remote video")
		} else {
			log.Println("receiving remote audio")
		}
	})
	pc.OnStreamEnded(func(err error) {
		if err != nil {
			log.Printf("stream ended with error (call stays up): %v", err)
		} else {
			log.Println("stream finished (call stays up)")
		}
	})

	pc.OnIncomingCall(func(ic *gortc.IncomingCall) {
		log.Printf("incoming call from user %d (video=%v); accepting", ic.UserID(), ic.Video())
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := ic.Accept(ctx); err != nil {
				log.Printf("accept failed: %v", err)
				return
			}
			stream(pc, mediaPath)
		}()
	})

	if target := os.Getenv("TARGET"); target != "" {
		go func() {
			log.Printf("placing outgoing call to %s", target)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if err := pc.Request(ctx, resolveTarget(target)); err != nil {
				log.Printf("call failed: %v", err)
				return
			}
			stream(pc, mediaPath)
		}()
	} else {
		log.Println("no TARGET set; waiting for incoming calls. set TARGET=@user to place a call")
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("hanging up")
	_ = pc.Hangup()
}

func stream(pc *gortc.PhoneCall, path string) {
	var src gortc.Source
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		src = gortc.FromURL(path, gortc.Res720)
	} else {
		if _, err := os.Stat(path); err != nil {
			log.Printf("media %q not found; call stays connected with no media: %v", path, err)
			return
		}
		src = gortc.FromFile(path, gortc.Res720)
	}
	log.Printf("streaming %s", path)
	if err := pc.Stream(context.Background(), src); err != nil {
		log.Printf("stream ended: %v", err)
	}
}

func resolveTarget(s string) any {
	if id, err := strconv.ParseInt(s, 10, 64); err == nil {
		return id
	}
	return s
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
