# Audit Log

Writes every request and response to a structured JSONL file with timestamps, container names, durations, and body sizes. Read-only: never blocks or rewrites anything. Bodies are not logged, only their sizes.

> **Not for production use.** Writes to a local file with no rotation, no compression, and no access controls. A production audit system should use a proper log pipeline (syslog, SIEM, or a cloud logging service) with tamper-proof storage.

## What it does

- Hooks both `http-request` and `http-response` with no filters (logs everything)
- Sets `max_body_bytes` to 0 (accepts null bodies since it only logs sizes, not content)
- Appends one JSON line per event to `audit.jsonl`
- Logs a stats summary every 100 requests

## Output

`audit.jsonl`:
```json
{"ts":"2025-03-15T14:32:01Z","direction":"request","container":"my-app","method":"POST","host":"api.openai.com:443","uri":"/v1/chat/completions","proto":"HTTP/1.1","body_bytes":1234,"tls":true}
{"ts":"2025-03-15T14:32:01Z","direction":"response","container":"my-app","method":"POST","host":"api.openai.com:443","uri":"/v1/chat/completions","status_code":200,"request_body_bytes":1234,"response_body_bytes":5678,"duration_ms":312}
```

## Run

```bash
uv run middleware.py
```

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
tail -f audit.jsonl
```
