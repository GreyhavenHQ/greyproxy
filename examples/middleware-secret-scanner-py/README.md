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

```bash
uv run middleware.py
```

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
```
