---
id: api
title: REST API
---

# Greyproxy REST API

Greyproxy exposes a full REST API at `http://localhost:43080` for automation and integration. Every dashboard feature is backed by this API, so you can script anything the UI can do.

## Base URL

```
http://localhost:43080
```

If you set `greyproxy.pathPrefix` in the config, all API routes are nested under that prefix (for example `http://localhost:43080/proxy/api/...`).

## Authentication

The API does not require authentication when accessed from localhost. Greyproxy is intended to run as a local tool; exposing it on a public interface is not supported.

## Health and Status

```http
GET /api/health
GET /api/dashboard
```

`/api/health` returns a simple liveness check. `/api/dashboard` returns the summary payload used to populate the main dashboard view (active connections, recent traffic, counters).

## Rules

Rules are stored in SQLite and evaluated on every connection. See [Rules Reference](./rules) for the evaluation semantics.

```http
GET    /api/rules
POST   /api/rules
POST   /api/rules/ingest
PUT    /api/rules/:id
DELETE /api/rules/:id
```

A rule has the following shape:

```json
{
  "id": 42,
  "container_pattern": "opencode",
  "destination_pattern": "*.npmjs.org",
  "port_pattern": "443",
  "rule_type": "glob",
  "action": "allow",
  "created_at": "2026-04-10T12:00:00Z",
  "expires_at": null,
  "last_used_at": null,
  "created_by": "dashboard",
  "notes": null,
  "is_active": true
}
```

| Field | Description |
|-------|-------------|
| `container_pattern` | Glob to match against the source container or process name. `*` matches any container. |
| `destination_pattern` | Glob to match against the destination hostname. |
| `port_pattern` | Port to match. `*` or an empty value means any port. |
| `rule_type` | Pattern dialect. Currently always `glob`. |
| `action` | `allow` or `deny`. |
| `expires_at` | Optional RFC 3339 timestamp. After this time the rule is inactive. |
| `notes` | Optional free-form annotation. |

### Example: add an allow rule

```bash
curl -X POST http://localhost:43080/api/rules \
  -H 'Content-Type: application/json' \
  -d '{
    "container_pattern": "*",
    "destination_pattern": "registry.npmjs.org",
    "port_pattern": "443",
    "action": "allow"
  }'
```

### Query filters

`GET /api/rules` accepts `container`, `destination`, `action`, `include_expired`, `limit`, and `offset` query parameters for filtering and pagination.

## Pending Requests

Connections that match no rule land in the pending queue.

```http
GET    /api/pending
GET    /api/pending/count
POST   /api/pending/:id/allow
POST   /api/pending/:id/deny
DELETE /api/pending/:id
POST   /api/pending/bulk-allow
POST   /api/pending/bulk-dismiss
```

`POST /api/pending/:id/allow` creates a corresponding allow rule; `/deny` creates a deny rule. The bulk endpoints accept arrays of pending IDs.

## Transactions and Logs

```http
GET /api/logs
GET /api/logs/stats
GET /api/transactions
GET /api/transactions/:id
```

`/api/logs` returns the connection log (one entry per allow/deny decision). `/api/transactions` returns captured HTTP and WebSocket transactions, which include request and response headers, bodies, and any credential substitution metadata. Both endpoints accept `limit` and `offset`.

## Conversations

See [LLM Conversation Tracking](./conversations) for the feature overview.

```http
GET /api/conversations
GET /api/conversations/:id
GET /api/conversations/:id/subagents
GET /api/dissectors
GET    /api/endpoint-rules
POST   /api/endpoint-rules
PUT    /api/endpoint-rules/:id
DELETE /api/endpoint-rules/:id
```

`/api/dissectors` lists the available decoders. The endpoint-rule endpoints manage URL pattern to decoder mappings for custom or self-hosted LLM APIs.

## Credentials and Sessions

See [Credential Substitution](./credentials) for the feature overview.

```http
GET    /api/sessions
POST   /api/sessions
POST   /api/sessions/:id/heartbeat
DELETE /api/sessions/:id

GET    /api/credentials
POST   /api/credentials
DELETE /api/credentials/:id
```

Sessions are short-lived; global credentials are persisted and encrypted on disk.

## Settings

```http
GET /api/settings
PUT /api/settings
```

Accepts partial updates. Recognized fields include `theme`, `notificationsEnabled`, `browserNotificationsEnabled`, `mitmEnabled`, `conversationsEnabled`, and `redactedHeaders`. See [Configuration](./configuration) for details.

Browser notifications can also be toggled via the nested `notifications.browserEnabled` field, e.g. `PUT /api/settings` with `{"notifications": {"browserEnabled": true}}`. When enabled, the dashboard claims notification handling over the control WebSocket and shows browser-native notifications for pending requests — useful when greyproxy runs in a container where `notify-send` / `terminal-notifier` are unavailable.

## Certificate Management

```http
GET  /api/cert/status
POST /api/cert/generate
GET  /api/cert/download
POST /api/cert/reload
```

`/api/cert/reload` is what `greyproxy cert reload` calls behind the scenes to pick up a freshly regenerated CA without restarting the service.

## Notifications and Allow-All

```http
GET /api/notifications
PUT /api/notifications

GET    /api/allowall
POST   /api/allowall
DELETE /api/allowall
```

`/api/notifications` reports and toggles OS desktop notifications, and also surfaces the current companion-app notification claim count. `/api/allowall` controls the silent allow-all mode used for quick unblocking during debugging.

## Maintenance

```http
POST /api/maintenance/rebuild-conversations
POST /api/maintenance/redact-headers
GET  /api/maintenance/status
```

These long-running jobs run in the background. Use `/api/maintenance/status` to poll progress, or subscribe to the `maintenance.progress` event over the [control WebSocket](./control-websocket).

## WebSocket

```
GET /ws
```

The dashboard and companion apps connect to `/ws` for real-time events and to drive greyproxy programmatically. See [Control WebSocket](./control-websocket) for the full protocol.

:::note
The full OpenAPI-style surface is embedded in the greyproxy binary. You can inspect it live from the running server; the routes listed here are the stable public-facing ones.
:::
