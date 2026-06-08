# gortc

A Go library for streaming audio and video into Telegram calls — group voice/video chats, 1:1 phone calls, and **E2E-encrypted conference calls** — built on top of [gogram](https://github.com/amarnathcjd/gogram).

## Why gortc

- **First-ever third-party E2E conference call implementation.** Telegram's E2E-encrypted "spontaneous group call without a chat" (shipped April 2025) is supported only by the official Telegram desktop/mobile clients — until now. gortc ships the full stack: signed append-only chain, per-participant shared-key derivation, per-packet TDE2E cipher, emoji-fingerprint commit-reveal verification. All in [`confcall/`](confcall) and [`confcall/e2e/`](confcall/e2e), matching tdlib byte-for-byte.
- **First pure-Go implementation of Telegram calls.** Existing libraries (pytgcalls, ntgcalls, tgcalls, …) all wrap libwebrtc or other C++ stacks via bindings. gortc has zero C dependencies — the SRTP, DTLS, ICE, RTP/RTCP, and SFU signaling stack under [`webrtc/`](webrtc) is all native Go (adapted from [pion](https://github.com/pion)). One static binary, no CGo, no libwebrtc.
- **Three call types, one API.** Regular group calls ([`groupcall`](groupcall)), 1:1 phone calls ([`phonecall`](phonecall)), and E2E conference calls ([`confcall`](confcall)) all consume the same source pipeline: local files, URLs, readers, raw PCM/video frames, or pre-encoded Opus/IVF. One `Stream` API, three transports.

## Install

```sh
go get github.com/amarnathcjd/gortc
```

You'll also need [`ffmpeg`](https://ffmpeg.org) on `$PATH` (only for transcoding sources — pre-encoded sources skip it).

## Quick start

```sh
# Get API credentials at https://my.telegram.org/apps
export API_ID=<your-app-id>
export API_HASH=<your-app-hash>
```

```go
package main

import (
    "context"
    "log"
    "log/slog"

    "github.com/amarnathcjd/gogram/telegram"
    "github.com/amarnathcjd/gortc"
)

func main() {
    client, _ := telegram.NewClient(telegram.ClientConfig{
        AppID:   int32(/* API_ID */),
        AppHash: /* API_HASH */,
        Session: "session.dat",
    })
    client.Conn()
    client.AuthPrompt()

    call := gortc.NewCall(client, gortc.WithLogLevel(slog.LevelInfo))
    call.OnConnected(func() {
        go call.Stream(context.Background(), gortc.FromFile("movie.mkv"))
    })

    if err := call.Join("@mychat"); err != nil {
        log.Fatal(err)
    }
    defer call.Leave()

    client.Idle() // block until Ctrl+C
}
```

## E2E conference calls

```go
cc := confcall.New(client, confcall.WithLogLevel(slog.LevelInfo))
cc.OnEmojiReady = func(em []string) { log.Printf("verify: %v", em) }

slug, _ := cc.Create(ctx, true)        // share slug with peers
// or: cc.Join(ctx, "<slug>")
cc.Stream(ctx, media.FromOggOpus(file))
```

See [`examples/confcall`](examples/confcall) for a runnable end-to-end demo.

## Sources

Stream from local files, remote URLs, or any `io.Reader` — gortc transcodes on the fly. Skip the encoder by passing pre-encoded Opus or IVF, or push raw PCM/video frames directly. Compose sources with `Loop` and `Concat`.

## Examples

- [`examples/basic`](examples/basic) — join a chat and stream a single file.
- [`examples/musicbot`](examples/musicbot) — full music bot with queue, pause/resume, skip, volume.
- [`examples/confcall`](examples/confcall) — create or join an E2E conference call and stream into it.

## License

MIT — see [LICENSE](LICENSE). The WebRTC stack under [`webrtc/`](webrtc) is adapted from [pion](https://github.com/pion) (MIT).
