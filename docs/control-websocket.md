# Control WebSocket Protocol

GreyProxy exposes a WebSocket endpoint at `GET /ws` that allows companion apps and external tools to receive real-time events and control the proxy.

## Connection

Connect to `ws://<host>:<port>/ws`. On success, the server sends:

```json
{
  "type": "connected",
  "message": "Connected to proxy event stream",
  "timestamp": "2025-01-15T10:30:00Z"
}
```

Each connection is assigned a random client ID (16 hex characters) for internal tracking.

## Commands (client to server)

All commands are JSON objects with a `command` field. Unknown commands return an error.

### ping

Keep-alive heartbeat.

```json
{"command": "ping"}
```

Response:

```json
{"type": "pong", "timestamp": "..."}
```

### allow

Approve a pending request and create an allow rule.

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
| `scope` | `"exact"` | `"exact"`, other scope values |
| `duration` | `"permanent"` | `"permanent"`, Go duration string (e.g. `"1h"`, `"30m"`) |
| `notes` | none | Free-text annotation |

Response on success:

```json
{
  "type": "command_success",
  "command": "allow",
  "pending_id": 123,
  "rule_id": 456,
  "timestamp": "..."
}
```

### dismiss

Dismiss a pending request without creating a rule.

```json
{"command": "dismiss", "pending_id": 123}
```

Response on success:

```json
{
  "type": "command_success",
  "command": "dismiss",
  "pending_id": 123,
  "timestamp": "..."
}
```

### subscribe

Filter which events this connection receives. By default, new connections receive all events. Sending `subscribe` switches the connection to filtered mode where only subscribed event types are forwarded.

```json
{"command": "subscribe", "event_type": "pending_request.created"}
```

Response:

```json
{"type": "subscribed", "event_type": "pending_request.created", "timestamp": "..."}
```

### unsubscribe

Stop receiving a specific event type.

```json
{"command": "unsubscribe", "event_type": "pending_request.created"}
```

Response:

```json
{"type": "unsubscribed", "event_type": "pending_request.created", "timestamp": "..."}
```

### claim_notifications

Tell the proxy that this connection is handling user notifications (e.g. a companion app showing its own UI). While at least one connection holds a claim, the proxy suppresses system desktop notifications (notify-send / terminal-notifier).

```json
{"command": "claim_notifications"}
```

Response:

```json
{
  "type": "notification_claimed",
  "active_claims": 1,
  "timestamp": "..."
}
```

The claim is automatically released when the WebSocket connection closes (disconnect, crash, network failure). If multiple connections claim notifications, all of them must disconnect before system notifications resume.

Claiming twice on the same connection returns an error:

```json
{"type": "error", "error": "notifications already claimed by this connection", "timestamp": "..."}
```

When any claim count changes, all connected clients receive a broadcast:

```json
{"type": "notification.claims_changed", "data": {"active_claims": 0}}
```

## Events (server to client)

Events are broadcast to all connected clients (filtered by subscriptions). Each event has a `type` and `data` field.

| Event Type | Trigger | Data |
|------------|---------|------|
| `pending_request.created` | New pending connection request | `PendingRequest` object |
| `pending_request.updated` | Pending request metadata changed | `PendingRequest` object |
| `pending_request.allowed` | Pending request approved | `{pending_id, rule}` |
| `pending_request.dismissed` | Pending request dismissed | `{pending_id}` |
| `waiters.changed` | Active connection count changed for a pending | `{container_name, host, port, previous_count, current_count}` |
| `transaction.new` | New HTTP/WS transaction recorded | Transaction object |
| `conversation.updated` | Conversation dissector produced new data | Conversation object |
| `maintenance.progress` | Background maintenance task progress | Progress object |
| `allowall.changed` | Allow-all mode toggled | AllowAll status |
| `notification.claims_changed` | Notification claim count changed | `{active_claims}` |

## Errors

All errors have the same shape:

```json
{"type": "error", "error": "description", "timestamp": "..."}
```

## Notification claim status via REST

The `GET /api/notifications` endpoint also reports the current claim count:

```json
{"enabled": true, "active_claims": 1}
```

## Example: companion app flow

```
1. Connect to ws://<proxy>/ws
2. Send: {"command": "claim_notifications"}
3. Receive: {"type": "notification_claimed", "active_claims": 1}
4. Listen for pending_request.created events
5. Show native UI for each pending request
6. Send allow/dismiss commands as the user decides
7. On app exit: connection closes, claim auto-released
```
