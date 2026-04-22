# Secret Scanner

Blocks outbound requests that contain accidentally leaked secrets such as API keys, AWS credentials, private keys, or passwords.

> **Not for production use.** The patterns cover a handful of common formats but will miss encoded, split, or obfuscated credentials. A production scanner should use a purpose-built tool (truffleHog, detect-secrets, Gitleaks) and scan all content types, not just request bodies.

## What it does

- Hooks `http-request` only (outbound traffic scanning)
- No host filter: scans requests to all destinations
- Detects AWS access keys, AWS secret keys, OpenAI-style keys, GitHub PATs, PEM private keys, Slack tokens, Stripe secret keys, Bearer tokens, passwords in JSON, and generic API key patterns
- Skips known OAuth/login endpoints to avoid false positives
- Blocks matching requests with HTTP 403 and a message listing what was found

## Example

A request body containing:
```json
{"prompt": "Use this key: sk-abc123def456ghi789jkl012mno345pqr678"}
```

Gets blocked with:
```
HTTP 403: Request blocked: detected leaked credentials (OpenAI-style API Key).
Remove secrets from the request body before retrying.
```

## Run

### Stdio (preferred)

Greyproxy spawns the scanner as a child process:

```bash
greyproxy serve --middleware-cmd 'uv run examples/middleware-secret-scanner-py/middleware.py'
```

No port, no separate terminal, no "is my middleware still running?" question — the scanner's lifecycle belongs to greyproxy.

### WebSocket

For a shared scanner service used by multiple greyproxy instances, run as a WS server:

```bash
uv run examples/middleware-secret-scanner-py/middleware.py
# then
greyproxy serve --middleware ws://localhost:9000/middleware
```

Same handler code, different transport — the helper in `examples/_lib/greyproxy_middleware.py` picks based on how we were launched.
