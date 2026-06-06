// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

// Package e2e implements the per-call E2E chain and per-packet cipher
// used by Telegram conference calls. See
// https://core.telegram.org/api/end-to-end/group-calls for the spec.
//
// The protocol layers a signed append-only blockchain over the call
// (Block / Change / StateProof, all custom TL) to authoritatively track
// participants and rotate a shared key. Every audio/video frame is
// wrapped with a per-packet key that is itself encrypted under each
// active epoch's shared key, so the SFU only ever sees ciphertext.
package e2e
