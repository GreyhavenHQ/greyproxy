# Credential Substitution API

This document describes the REST API that greywall (or any sandbox client) uses to register credential substitution sessions with greyproxy.

## Overview

When greywall launches a sandboxed process, it:

1. Reads the process's environment variables for sensitive values (API keys, tokens, etc.)
2. Generates opaque placeholder strings for each credential
3. Passes the placeholders to the sandboxed process (via modified env vars)
4. Registers a session with greyproxy, providing the placeholder-to-real-value mappings

GreyProxy then transparently replaces placeholders with real credentials in HTTP headers and query parameters before forwarding requests upstream.

## Session Lifecycle

### Create or Update Session

```
POST /api/sessions
Content-Type: application/json
```

**Request body:**

```json
{
  "session_id": "uuid-string",
  "container_name": "opencode",
  "mappings": {
    "greyproxy:credential:v1:SESSION_ID:HEX": "sk-real-api-key-value",
    "greyproxy:credential:v1:SESSION_ID:HEX2": "another-real-key"
  },
  "labels": {
    "greyproxy:credential:v1:SESSION_ID:HEX": "OPENAI_API_KEY",
    "greyproxy:credential:v1:SESSION_ID:HEX2": "ANTHROPIC_API_KEY"
  },
  "metadata": {
    "pwd": "/home/user/project",
    "cmd": "opencode",
    "args": "--model claude-sonnet-4-20250514",
    "binary_path": "/usr/bin/opencode",
    "pid": "12345"
  },
  "ttl_seconds": 900
}
```

**Fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `session_id` | string | Yes | Unique session identifier (UUID recommended). Used for upserts. |
| `container_name` | string | Yes | Name of the sandboxed container/process. Used for log correlation. |
| `mappings` | map[string]string | Yes | Placeholder string to real credential value. Keys must use the `greyproxy:credential:` prefix format. |
| `labels` | map[string]string | No | Placeholder string to human-readable label (e.g. env var name). Same keys as `mappings`. |
| `metadata` | map[string]string | No | Arbitrary key-value metadata about the session. Displayed in the dashboard. |
| `ttl_seconds` | int | No | Session TTL in seconds (default: 900, max: 3600). |

**Response (200):**

```json
{
  "session_id": "uuid-string",
  "expires_at": "2026-03-25T16:00:00Z",
  "credential_count": 2
}
```

### Heartbeat

Reset the TTL for an active session. Call this periodically to keep the session alive.

```
POST /api/sessions/:id/heartbeat
```

**Response (200):**

```json
{
  "session_id": "uuid-string",
  "expires_at": "2026-03-25T16:15:00Z"
}
```

**Response (404):** Session not found or expired.

### Delete Session

Immediately expire and remove a session.

```
DELETE /api/sessions/:id
```

**Response (200):**

```json
{
  "session_id": "uuid-string",
  "deleted": true
}
```

### List Sessions

Returns all active (non-expired) sessions.

```
GET /api/sessions
```

**Response (200):** Array of session objects with credential labels, counts, metadata, and timestamps.

## Metadata Convention

The `metadata` field is a flexible string map. Greywall can send any keys it finds useful. The following keys are recognized and displayed prominently in the dashboard:

| Key | Description | Example |
|---|---|---|
| `pwd` | Working directory of the sandboxed process | `/home/user/project` |
| `cmd` | Command name | `opencode` |
| `args` | Command arguments | `--model claude-sonnet-4-20250514` |
| `binary_path` | Absolute path to the binary | `/usr/bin/opencode` |
| `pid` | PID of the greywall sandbox process | `12345` |
| `created_by` | What created the session | `greywall v0.2.0` |

## Placeholder Format

Placeholders follow this format:

```
greyproxy:credential:v1:<scope>:<hex>
```

- `v1` is the version prefix
- `<scope>` is either a session ID or `"global"` for global credentials
- `<hex>` is a random hex string for uniqueness

The client can generate these using `GeneratePlaceholder()` or construct them manually. The only requirement is that they start with `greyproxy:credential:` so the proxy's fast-path check can skip scanning headers that don't contain any placeholders.

## What Gets Substituted

The proxy scans and substitutes placeholders in:

- **HTTP request headers** (all header values)
- **URL query parameters**

It does **not** substitute in:

- Request bodies (the body is stored as-is with placeholders visible)
- Response data

## Transaction Tracking

When credentials are substituted in a request, the resulting HTTP transaction is tagged with:

- `substituted_credentials`: JSON array of credential label names that were substituted
- `session_id`: The session that provided the credentials

These fields are visible in the transaction detail view and can be used for filtering via `GET /api/transactions?session_id=...`.
