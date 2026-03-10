# MITM Traffic Sniffing POC - Execution Plan

## Objective
Make `curl --proxy socks5h://localhost:43052 https://greyhaven.co` print decrypted HTTP request/response in greyproxy's log output via MITM TLS interception.

## Status: COMPLETE

## What was done

### Files created
- `cmd/greyproxy/cert.go` — `greyproxy cert generate/install` CLI commands

### Files modified
- `cmd/greyproxy/main.go` — Added `case "cert":` dispatch
- `cmd/greyproxy/program.go` — Auto-inject MITM cert paths into handler metadata
- `greyproxy.yml` — Added `sniffing: true` to HTTP and SOCKS5 handlers
- `internal/gostx/internal/util/sniffing/sniffer.go` — Added `OnHTTPRoundTrip` callback + body capture
- `internal/gostx/internal/util/tls/tls.go` — Fixed `GenerateCertificate` to detect key type (ECDSA/Ed25519/RSA)
- `internal/gostx/handler/http/handler.go` — Wired `mitmLogHook` on Sniffer
- `internal/gostx/handler/socks/v5/connect.go` — Wired `mitmLogHook` on Sniffer

### Bugs fixed along the way
1. **SignatureAlgorithm mismatch**: `GenerateCertificate()` hardcoded `x509.SHA256WithRSA` but CA key is ECDSA P-256. Added `sigAlgorithm()` helper to auto-detect key type.
2. **macOS cert install**: `sudo security add-trusted-cert -d` fails with `SecTrustSettingsSetTrustSettings` in non-GUI contexts. Changed to `open` which launches Keychain Access GUI.
3. **Duplicate cert import**: macOS returns `-25294` (errSecDuplicateItem) on re-import. Added `security delete-certificate -c "Greyproxy CA"` before import.

## Verified output
```
[MITM] GET greyhaven.co/ → 200
[MITM] Request Headers: map[Accept:[*/*] User-Agent:[curl/8.7.1]]
[MITM] Response Headers: map[Content-Type:[text/html; charset=utf-8] Server:[Vercel] ...]
[MITM] Response Body (48852 bytes): <!DOCTYPE html>...
```
