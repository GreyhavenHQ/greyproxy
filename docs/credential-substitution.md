# Credential Substitution

Greyproxy provides transparent credential substitution for sandboxed environments. Real API keys are replaced with opaque placeholders inside the sandbox; greyproxy injects the real values into HTTP requests before forwarding them upstream.

## Overview

```
 Sandbox                    Greyproxy                    Upstream
+--------+                 +-----------+                +---------+
| App    | -- Bearer <ph> -->| Substitute| -- Bearer <real> -->| API     |
|        |                 | ph -> real |                |         |
+--------+                 +-----------+                +---------+
```

The sandboxed process never sees real credentials. Greyproxy holds the mapping and performs substitution at the MITM layer.

## Two types of credentials

### Session credentials (automatic)

When greywall launches a sandbox, it detects credential-like environment variables, generates placeholders, and registers them with greyproxy via `POST /api/sessions`. These credentials are tied to the session lifetime.

### Global credentials (stored in dashboard)

Global credentials are stored persistently in the greyproxy dashboard (Settings > Credentials). They are not injected automatically; greywall must explicitly request them using the `--inject` flag.

```bash
greywall --inject ANTHROPIC_API_KEY -- opencode
```

At session creation, greywall sends the requested labels via the `global_credentials` field. Greyproxy resolves each label to its stored placeholder and returns the mappings. Greywall then sets these as environment variables in the sandbox.

## Session API

### Create session

```
POST /api/sessions
```

```json
{
  "session_id": "gw-abc123",
  "container_name": "opencode",
  "mappings": {
    "greyproxy:credential:v1:gw-abc123:aabb...": "sk-real-key"
  },
  "labels": {
    "greyproxy:credential:v1:gw-abc123:aabb...": "ANTHROPIC_API_KEY"
  },
  "global_credentials": ["OPENAI_API_KEY"],
  "ttl_seconds": 900
}
```

- `mappings`: placeholder-to-real-value pairs (for session credentials detected by greywall)
- `labels`: placeholder-to-label pairs (for display in the dashboard)
- `global_credentials`: list of global credential labels to resolve and merge into the session
- `ttl_seconds`: session lifetime (max 3600, default 900)

Either `mappings` or `global_credentials` (or both) must be provided.

**Response:**

```json
{
  "session_id": "gw-abc123",
  "expires_at": "2026-03-25T23:15:00Z",
  "credential_count": 2,
  "global_credentials": {
    "OPENAI_API_KEY": "greyproxy:credential:v1:global:ccdd..."
  }
}
```

The `global_credentials` field in the response maps each requested label to its placeholder. Greywall uses these to set environment variables in the sandbox.

### Heartbeat

```
POST /api/sessions/:id/heartbeat
```

Resets the session TTL. Returns 404 if the session has expired (greywall will re-register).

### Delete session

```
DELETE /api/sessions/:id
```

Removes the session and its credentials from memory.

### List sessions

```
GET /api/sessions
```

Returns all active sessions with credential labels and substitution counts.

## Global credentials API

### List

```
GET /api/credentials
```

Returns all global credentials with labels, placeholders, and value previews (never the real value).

### Create

```
POST /api/credentials
```

```json
{
  "label": "ANTHROPIC_API_KEY",
  "value": "sk-ant-real-secret"
}
```

The value is encrypted at rest with a per-installation key (`session.key`).

### Delete

```
DELETE /api/credentials/:id
```

## Substitution behavior

When a request passes through the MITM layer, greyproxy scans HTTP headers and URL query parameters for strings matching the placeholder prefix (`greyproxy:credential:v1:`). Every occurrence is replaced with the corresponding real value.

- **All occurrences** are replaced, not just the first match
- Substitution applies to both session and global credentials in the same pass
- Substitution happens after headers are cloned for storage, so the dashboard never shows real values
- Request bodies are NOT scanned (most APIs accept credentials via headers)

## Tracking

Each substitution increments a counter on the session. Counts are flushed to the database every 60 seconds and broadcast via WebSocket (`session.substitution` event) so the dashboard updates in real time.

In the Activity view, requests that had credentials substituted show a shield icon. Expanding the row shows which credential labels were involved.

## Dashboard UI

The Settings > Credentials tab shows:

- **Protection status**: whether HTTP and HTTPS traffic are protected (HTTPS requires TLS interception)
- **Global credentials**: stored credentials with add/delete controls and usage instructions
- **Active sessions**: currently registered sessions with credential labels, substitution counts, creation time, and active duration
