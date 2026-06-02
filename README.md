# gortc

A Go library for streaming audio and video into Telegram group calls, built on top of [gogram](https://github.com/amarnathcjd/gogram).

It joins voice/video chats and streams from flexible sources: files, URLs, readers, raw PCM/video frames, or pre-encoded Opus/IVF.

Existing solutions (pytgcalls, ntgcalls, tgcalls, etc.) all wrap libwebrtc or other C++ stacks via bindings. **gortc is the first pure-Go implementation** — no libwebrtc, no CGo, no native dependencies. The SRTP, DTLS, ICE, and SFU signaling stack is all native Go.

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

`FromFile`, `FromURL`, `FromReader`, `FromOggOpus`, `FromIVF`, `FromEncoded`, `FromRawPCM`, `FromRawVideo`, plus `Loop` and `Concat` for composition.

## Examples

- [`examples/basic`](examples/basic) — join a chat and stream a single file.
- [`examples/musicbot`](examples/musicbot) — full music bot with queue, pause/resume, skip, volume.

## License

MIT — see [LICENSE](LICENSE). The WebRTC stack under [`webrtc/`](webrtc) is adapted from [pion](https://github.com/pion) (MIT).
