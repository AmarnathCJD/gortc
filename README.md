# gortc

A Go library for streaming audio and video into Telegram group calls, built on top of [gogram](https://github.com/amarnathcjd/gogram).

It joins voice/video chats and streams from flexible sources: files, URLs, readers, raw PCM/video frames, or pre-encoded Opus/IVF.

Existing solutions (pytgcalls, ntgcalls, tgcalls, etc.) all wrap libwebrtc or other C++ stacks via bindings. **gortc is the first pure-Go implementation** — no libwebrtc, no CGo, no native dependencies. The SRTP, DTLS, ICE, and SFU signaling stack is all native Go.

## E2E conference calls — a first

gortc also ships **the first third-party implementation of Telegram's E2E-encrypted conference calls** (the "spontaneous group call without a chat" feature introduced in April 2025). pytgcalls, ntgcalls, tgcalls, and every other call library can do regular group calls — none of them support E2E conference calls. Only the official Telegram desktop/mobile clients do.

That stack — the per-call signed append-only blockchain, the per-participant shared-key derivation, the per-packet TDE2E cipher, and the emoji-fingerprint commit-reveal verification — is all implemented in [`confcall/`](confcall) and [`confcall/e2e/`](confcall/e2e), matching tdlib byte-for-byte.

```go
cc := confcall.New(client, confcall.WithLogLevel(slog.LevelInfo))
cc.OnEmojiReady = func(em []string) { log.Printf("verify: %v", em) }

slug, _ := cc.Create(ctx, true)        // share slug with peers
// or: cc.Join(ctx, "<slug>")
cc.Stream(ctx, gortc.FromFile("audio.ogg"))
```

See [`examples/confcall`](examples/confcall) for a runnable demo.

## Install

```sh
go get github.com/amarnathcjd/gortc
```

## Quick start

```go
client, _ := telegram.NewClient(telegram.ClientConfig{ /* ... */ })
client.Conn()

call := gortc.NewCall(client, gortc.WithLogLevel(slog.LevelInfo))
call.OnConnected(func() {
    go call.Stream(context.Background(), gortc.FromFile("movie.mkv"))
})

if err := call.Join("@mychat"); err != nil {
    log.Fatal(err)
}
defer call.Leave()
```

## Sources

Stream from local files, remote URLs, or any `io.Reader` — gortc transcodes on the fly. Skip the encoder by passing pre-encoded Opus or IVF, or push raw PCM/video frames directly. Compose sources with `Loop` and `Concat`.

## Examples

- [`examples/basic`](examples/basic) — join a chat and stream a single file.
- [`examples/musicbot`](examples/musicbot) — full music bot with queue, pause/resume, skip, volume.
- [`examples/confcall`](examples/confcall) — create or join an E2E conference call and stream into it.

## License

MIT — see [LICENSE](LICENSE). The WebRTC stack under [`webrtc/`](webrtc) is adapted from [pion](https://github.com/pion) (MIT).
