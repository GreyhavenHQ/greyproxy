---
id: control-websocket
title: Control WebSocket
---

# Control WebSocket

Greyproxy exposes a WebSocket endpoint at `GET /ws` that companion apps and external tools can use to receive real-time events and drive the proxy programmatically. The dashboard itself is a client of this same endpoint.

## Connection

Connect to `ws://<host>:<port>/ws`. On success, greyproxy sends:

```json
{
  "type": "connected",
  "message": "Connected to proxy event stream",
  "timestamp": "2026-04-10T10:30:00Z"
}
```

Each connection is assigned a random client ID for internal tracking. By default, a new connection receives every event type; sending a `subscribe` command switches it into filtered mode.

## Commands

Commands are JSON objects with a `command` field. Unknown commands return an error of the form `{"type": "error", "error": "...", "timestamp": "..."}`.

### `ping`

Keep-alive heartbeat.

```json
{"command": "ping"}
```

Response: `{"type": "pong", "timestamp": "..."}`.

### `allow`

Approve a pending request and create an allow rule for it.

```json
{
  "command": "allow",
  "pending_id": 123,
  "scope": "exact",
  "duration": "permanent",
  "notes": "optional note"
}
```

| Field | Default | Values |
|-------|---------|--------|
| `scope` | `exact` | Rule scope for the generated allow rule |
| `duration` | `permanent` | `permanent` or a Go duration string (for example `1h`, `30m`) |
| `notes` | none | Free-text annotation |

On success:

```json
{"type": "command_success", "command": "allow", "pending_id": 123, "rule_id": 456, "timestamp": "..."}
```

### `dismiss`

Dismiss a pending request without creating a rule.

```json
{"command": "dismiss", "pending_id": 123}
```

### `subscribe` and `unsubscribe`

Filter which events this connection receives. After `subscribe`, only subscribed event types are forwarded. `unsubscribe` removes a type from the filter.

```json
{"command": "subscribe", "event_type": "pending_request.created"}
{"command": "unsubscribe", "event_type": "pending_request.created"}
```

### `claim_notifications`

Tell greyproxy that this connection is handling user notifications itself (for example, a native companion app that shows its own UI). While at least one connection holds a claim, greyproxy suppresses OS desktop notifications (notify-send, terminal-notifier).

```json
{"command": "claim_notifications"}
```

Response:

```json
{"type": "notification_claimed", "active_claims": 1, "timestamp": "..."}
```

The claim is released automatically when the WebSocket closes for any reason (graceful disconnect, crash, network failure). If several connections hold claims at once, all of them must disconnect before system notifications resume. Claiming twice on the same connection returns an error.

Every change to the claim count is broadcast to all connected clients:

```json
{"type": "notification.claims_changed", "data": {"active_claims": 0}}
```

The current claim count is also visible via REST at `GET /api/notifications`.

### `release_notifications`

Release a notification claim held by this connection, without closing the WebSocket. This is the inverse of `claim_notifications` and lets a companion app stop handling notifications while staying connected.

```json
{"command": "release_notifications"}
```

Response:

```json
{"type": "notification_released", "active_claims": 0, "timestamp": "..."}
```

Releasing when this connection holds no claim returns an error.

## Events

Events flow from server to client and carry a `type` plus a `data` field. The table below lists the events a companion app is likely to care about.

| Event | Trigger | Data |
|-------|---------|------|
| `pending_request.created` | New connection awaiting a decision | `PendingRequest` |
| `pending_request.updated` | Pending metadata changed | `PendingRequest` |
| `pending_request.allowed` | Pending request approved | `{pending_id, rule}` |
| `pending_request.dismissed` | Pending request dismissed | `{pending_id}` |
| `waiters.changed` | Active connection count changed for a pending | `{container_name, host, port, previous_count, current_count}` |
| `transaction.new` | New HTTP or WebSocket transaction recorded | Transaction object |
| `conversation.updated` | Dissector produced new conversation data | Conversation object |
| `maintenance.progress` | Background maintenance task progress | Progress object |
| `allowall.changed` | Allow-all (silent) mode toggled | AllowAll status |
| `notification.claims_changed` | Notification claim count changed | `{active_claims}` |

## Example: companion app flow

```
1. Connect to ws://<proxy>/ws
2. Send {"command": "claim_notifications"}
3. Receive {"type": "notification_claimed", "active_claims": 1}
4. Listen for pending_request.created events
5. Show native UI for each pending request
6. Send allow or dismiss commands as the user decides
7. On app exit, the connection closes and the claim is auto-released
```
