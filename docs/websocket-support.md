# WebSocket MITM Support

This document tracks the engineering journey of getting WebSocket traffic (specifically `codex` CLI traffic to `api.openai.com/v1/responses`) captured and decoded by greyproxy.

---

## Background

The OpenAI `/v1/responses` endpoint uses WebSocket (`Upgrade: websocket`) instead of HTTP chunked streaming. When `codex` CLI sends requests through the proxy, they go over SOCKS5, then MITM TLS termination, then HTTP — so the 101 Switching Protocols response redirects the connection into WebSocket territory that greyproxy did not previously handle.

The WebSocket connection also uses the `permessage-deflate` extension, which compresses each message using raw DEFLATE. This added a second layer of complexity on top of the WebSocket framing.

---

## Issue History

### Issue 1: 101 Switching Protocols exits `httpRoundTrip` before hooks fire

**Symptom:** No traffic from `api.openai.com/v1/responses` appeared in the activity log. The proxy was transparently passing the WebSocket tunnel without capturing anything.

**Root cause:** `httpRoundTrip` checked `resp.StatusCode == 200` before firing `OnHTTPRoundTrip`. A 101 response caused an early return via `handleUpgradeResponse`, bypassing the hook entirely.

**Fix:** Added an explicit 101 branch before the main response path that fires the hook with the upgrade request/response metadata, then hands off to `handleUpgradeResponse`. This makes the 101 visible in the activity log with full request and response headers.

---

### Issue 2: WebSocket frames not captured at all

**Symptom:** Even after the 101 appeared in the UI, no frame-level content was captured. `handleUpgradeResponse` fell through to a plain `io.Copy` pipe.

**Root cause:** `sniffing.websocket` was not set to `true` in the service metadata config, so `h.Websocket` was false and `handleUpgradeResponse` skipped the `sniffingWebsocketFrame` path.

**Fix:** Added `sniffing.websocket: true` to both HTTP and SOCKS5 service metadata in `greyproxy.yml` and in the test matrix isolated config.

---

### Issue 3: Captured WebSocket frame payloads were binary (masked, not unmasked)

**Symptom:** Frames were being captured and stored in the DB, but the `request_body` column contained binary garbage rather than readable JSON.

**Root cause (part 1 — masking):** RFC 6455 requires client→server frames to be XOR-masked with a 4-byte key. In `copyWebsocketFrame`, the in-place XOR was done on `buf.Bytes()` directly:

```go
payload := buf.Bytes()          // slice into buf's backing array
payload[i] ^= mask[i%4]        // modifies buf in-place!
```

Then the forwarding used:
```go
fr.Data = io.MultiReader(bytes.NewReader(buf.Bytes()), fr.Data)
```

Because `buf.Bytes()` was modified in-place, the forwarded bytes were already unmasked but the frame header still declared `Masked=true` with the original key. The server XOR'd the data again, producing garbage. `codex` detected the corrupted responses and fell back from WebSocket to plain HTTP after 5 attempts.

**Fix:** Make an independent copy before unmasking, so the captured payload is plaintext but the forwarded wire bytes remain correctly masked:

```go
payload := make([]byte, buf.Len())
copy(payload, buf.Bytes())       // independent copy
for i := range payload {
    payload[i] ^= mask[i%4]     // unmask the copy only
}
```

---

### Issue 4: permessage-deflate frames could not be decompressed (shared context)

**Symptom:** After the masking fix, WebSocket traffic stayed connected and frames were captured with `rsv1=true`. Decompression failed with `unexpected EOF` or `invalid code lengths set`. Server returned `Sec-Websocket-Extensions: permessage-deflate` (no `no_context_takeover`).

**Root cause:** `permessage-deflate` by default uses a shared DEFLATE context across all frames in a session. Each frame's compressed bytes are a continuation of the previous frame's DEFLATE stream. Decompressing each frame independently (with a fresh `flate.NewReader`) fails for any frame after the first.

**Fix:** Rewrite `Sec-Websocket-Extensions` in the WebSocket upgrade request (before sending to the upstream server) to force no-context-takeover on both sides:

```go
if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
    ext := req.Header.Get("Sec-Websocket-Extensions")
    if strings.Contains(strings.ToLower(ext), "permessage-deflate") {
        req.Header.Set("Sec-Websocket-Extensions",
            "permessage-deflate; client_no_context_takeover; server_no_context_takeover")
    }
}
```

OpenAI's server accepted this and responded with `permessage-deflate; server_no_context_takeover; client_no_context_takeover`. Each frame is now independently decompressible.

---

### Issue 5: Go's `compress/flate` returns `unexpected EOF` on valid DEFLATE frames

**Symptom:** Even after forcing `no_context_takeover`, decompression still failed with `unexpected EOF` for every frame. Python's `zlib.decompressobj(-15)` successfully decompressed the same bytes.

**Root cause:** The `permessage-deflate` spec requires senders to strip the 4-byte SYNC_FLUSH trailer (`\x00\x00\xff\xff`) from the end of each frame's compressed payload. Receivers are expected to re-append it before decompressing. The initial `decompressWebSocketFrame` did this:

```go
payload = append(payload, 0x00, 0x00, 0xff, 0xff)
r := flate.NewReader(bytes.NewReader(payload))
```

However, the SYNC_FLUSH block has `BFINAL=0` (not the last block). Go's pure-Go `compress/flate` implementation requires a `BFINAL=1` block to signal end-of-stream and return clean `io.EOF`. Python's `libz` handles `BFINAL=0` SYNC_FLUSH implicitly.

**Fix (gorilla/websocket technique):** Append both the SYNC_FLUSH trailer AND an additional empty `BFINAL=1` stored block:

```go
const tail = "\x00\x00\xff\xff\x01\x00\x00\xff\xff"
//            ^^^^^^^^^^^^^^^^  SYNC_FLUSH (stripped by sender)
//                              ^^^^^^^^^^^^^^^^^^^^^^^^  BFINAL=1 empty block (Go needs this)
mr := io.MultiReader(bytes.NewReader(payload), strings.NewReader(tail))
r := flate.NewReader(mr)
```

`\x01\x00\x00\xff\xff` = BFINAL=1, BTYPE=00 (non-compressed), LEN=0, NLEN=0xFFFF. This makes Go's flate reader terminate cleanly.

---

### Issue 6: Conversation assembler crashes on WS_REQ/WS_RESP rows (NULL `response_content_type`)

**Symptom:** After WebSocket frames were stored as `WS_REQ`/`WS_RESP` transactions, the conversation assembler logged 27+ warnings:

```
WARN assembler: failed to scan transaction row error="sql: Scan error on column index 8,
name \"response_content_type\": converting NULL to string is unsupported"
```

The assembler skipped every WS transaction, so no WebSocket sessions appeared in the conversation view.

**Root cause:** WS frame rows have `response_content_type = NULL` (they have no HTTP response, only a WebSocket payload). The assembler scanned this column into a `string` variable, which Go's `database/sql` refuses to do for NULL values.

**Fix:** Changed the scan variable type from `string` to `*string` and added a `derefString` helper that returns `""` for nil pointers.

---

## Current State

| Capability | Status |
|---|---|
| 101 Switching Protocols logged | ✅ |
| WebSocket frames captured | ✅ |
| Client→server frames correctly forwarded (masking preserved) | ✅ |
| permessage-deflate frames decompressed | ✅ |
| no_context_takeover negotiated transparently | ✅ |
| WS frames visible in activity log as `WS_REQ`/`WS_RESP` | ✅ |
| Conversation assembler handles WS rows without crashing | ✅ |
| Conversation assembly from WebSocket sessions | work in progress |

---

## Architecture Notes

### Frame capture flow

```
Client (codex)
  │  [SOCKS5]
  ▼
greyproxy SOCKS5 listener
  │  [MITM TLS termination]
  ▼
httpRoundTrip (sniffer.go)
  │  GET /v1/responses → 101
  │  [rewrites Sec-Websocket-Extensions before req.Write to force no_context_takeover]
  ▼
handleUpgradeResponse → sniffingWebsocketFrame
  │  two goroutines: client→server and server→client
  ▼
copyWebsocketFrame (per frame)
  │  1. fr.ReadFrom(r)           — reads frame header + LimitReader for body
  │  2. io.Copy(buf, fr.Data)    — drains body into buffer
  │  3. make+copy → payload      — independent copy for hook
  │  4. XOR unmask payload       — client frames only (Masked=true)
  │  5. GlobalWebSocketFrameHook — fires with unmasked payload
  │  6. fr.Data = MultiReader(buf.Bytes(), fr.Data)  — reassemble masked wire bytes
  │  7. fr.WriteTo(w)            — forward original masked frame
  ▼
program.go hook goroutine
  │  if RSV1: decompressWebSocketFrame (append 9-byte tail, flate.NewReader)
  ▼
greyproxy.CreateHttpTransaction (WS_REQ or WS_RESP)
```

### Compression tail breakdown

```
Bytes appended before decompression:
  00 00 FF FF           — SYNC_FLUSH terminator (stripped by RFC 7692)
  01 00 00 FF FF        — BFINAL=1 empty stored block (required by Go's flate)
```
