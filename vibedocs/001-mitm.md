# Greyproxy v2: Human-in-the-Middle for AI Agent Loops

## The Problem

Today greyproxy operates at the **TCP connection level**: you see "claude-code wants to connect to api.anthropic.com:443" and you either allow or deny. That tells you nothing about **what** the agent is actually doing. You're approving a domain blindly — is it a normal LLM request? Posting credentials? A DELETE to production?

## The Vision

Greyproxy becomes a **human-in-the-middle** proxy. When a new destination appears, instead of just showing "api.anthropic.com:443", you see the actual HTTP request: method, URL, headers, body. You approve with full context. Every transaction is logged. Dangerous patterns are auto-held.

---

## Core Idea: Deferred Connect

Today's flow:
```
1. SOCKS5 CONNECT host:port
2. Bypass check → no rule → HOLD (show "host:port" pending)
3. User approves → dial upstream → MITM → HTTP flows
```

The problem: at step 2, we don't have HTTP details yet. The TLS handshake hasn't happened.

**New flow** (when MITM is available):
```
1. SOCKS5 CONNECT host:port
2. Quick check → explicit deny rule? → BLOCK immediately
3. No rule or allow rule → send SOCKS5 "Succeeded" to client
4. Client starts TLS → we do MITM handshake (client side only, no upstream yet)
5. Client sends HTTP request → we read and buffer it
6. NOW we have full context: method, URL, headers, body
7. Evaluate request rules:
   a. Auto-allow → connect upstream, forward request
   b. Hold → show rich pending with full HTTP details, wait for user
   c. Deny → send HTTP 403 back, never connect upstream
8. On approval → connect upstream, TLS handshake with server, forward buffered request
```

**One stone, two birds**: the pending request now shows everything. The user approves with full context. The same mechanism works for subsequent requests on the same connection (each request is evaluated).

**Fallback** (no MITM — non-HTTP, cert not installed, MITM bypass):
```
Same as today: pending shows host:port only, approval is connection-level.
```

No degradation for non-MITM scenarios.

---

## What the User Sees

### Pending Request (today)
```
claude-code → api.anthropic.com:443  (3 attempts)  [Allow] [Deny]
```

### Pending Request (with MITM)
```
claude-code → api.anthropic.com:443
POST /v1/messages  HTTP/1.1
Content-Type: application/json
Authorization: Bearer sk-ant-***REDACTED***

{
  "model": "claude-sonnet-4-20250514",
  "messages": [{"role": "user", "content": "Read src/main.go..."}],
  "tools": [...]
}

[Allow Once] [Allow Destination] [Allow Pattern] [Deny]
```

### Approval Actions

| Action | What it does |
|--------|-------------|
| **Allow Once** | Forward this request only. Next request re-evaluates. |
| **Allow Destination** | Create a destination rule (same as today's Allow). All future requests to this host:port auto-forward + log. |
| **Allow Pattern** | Create a request-level rule: e.g. "allow POST /v1/messages to api.anthropic.com". Other methods/paths still held. |
| **Deny** | Return HTTP 403. Optionally create deny rule. |

### Safe Methods: Auto-Allow After Destination Approval

When a user clicks "Allow Destination", a sensible default: **GET requests auto-forward** (logged), **mutating requests (POST/PUT/DELETE/PATCH) are held** for review. This balances speed with safety. Configurable per-rule.

### Global Kill Switch

A prominent button in the dashboard header: **KILL ALL**
- Immediately denies all pending requests
- Closes all active connections (via ConnTracker)
- Pauses the proxy (new connections get instant deny)
- Requires explicit "Resume" to re-enable

---

## Request Rules

Extend the existing rules with optional HTTP-level fields:

### Schema Changes

```sql
ALTER TABLE rules ADD COLUMN method_pattern TEXT NOT NULL DEFAULT '*';
ALTER TABLE rules ADD COLUMN path_pattern TEXT NOT NULL DEFAULT '*';
ALTER TABLE rules ADD COLUMN content_action TEXT NOT NULL DEFAULT 'allow';
-- content_action: 'allow' (forward+log), 'hold' (pause for approval), 'deny' (block)
```

### Rule Matching (extended)

Existing specificity system stays. New dimensions add specificity:
- Method exact match: +4 points
- Method wildcard: +0
- Path exact match: +3 points
- Path with glob: +2 points
- Path wildcard: +0

### Rule Examples

```
# After "Allow Destination" for anthropic: all requests auto-forward, logged
container=claude-code  dest=api.anthropic.com  port=443  method=*  path=*  action=allow

# After "Allow Pattern" for chat completions: only this endpoint auto-forwards
container=claude-code  dest=api.anthropic.com  port=443  method=POST  path=/v1/messages  action=allow

# Global: hold any DELETE request anywhere
container=*  dest=*  port=*  method=DELETE  path=*  action=hold

# Global: hold PUT requests to non-API destinations
container=*  dest=*  port=*  method=PUT  path=*  action=hold
```

### Backward Compatibility

- Existing rules get `method_pattern='*'`, `path_pattern='*'`, `content_action='allow'`
- Behavior is identical to today: destination allowed = everything flows through
- New fields only matter when MITM is active and request-level evaluation runs

---

## HTTP Transaction Logging

Every MITM-intercepted HTTP request/response is stored:

### New Table: `http_transactions`

```sql
CREATE TABLE http_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    container_name TEXT NOT NULL,
    destination_host TEXT NOT NULL,
    destination_port INTEGER NOT NULL,

    -- Request
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    request_headers TEXT,          -- JSON object
    request_body BLOB,             -- up to max_body_capture bytes
    request_body_size INTEGER,     -- actual size before truncation
    request_content_type TEXT,

    -- Response
    status_code INTEGER,
    response_headers TEXT,         -- JSON object
    response_body BLOB,            -- up to max_body_capture bytes
    response_body_size INTEGER,
    response_content_type TEXT,

    -- Metadata
    duration_ms INTEGER,
    rule_id INTEGER,
    result TEXT NOT NULL DEFAULT 'auto'  -- 'auto', 'allowed', 'held', 'denied'
);

CREATE INDEX idx_http_transactions_ts ON http_transactions(timestamp);
CREATE INDEX idx_http_transactions_dest ON http_transactions(destination_host, destination_port);
```

### Body Capture Config

```yaml
greyproxy:
  max_body_capture: 1048576   # 1MB default, configurable
```

- Bodies larger than max are truncated; `request_body_size` stores the real size
- Binary content stored as-is; UI shows "binary, N bytes" or hex preview
- JSON bodies: stored raw, UI renders with syntax highlighting and collapsible sections

### Data Retention

Logs and transactions are retained for **2 weeks** by default (configurable).

```yaml
greyproxy:
  log_retention_days: 14      # delete logs + transactions older than this
```

A cleanup routine runs on startup and then every hour:
```sql
DELETE FROM http_transactions WHERE timestamp < datetime('now', '-14 days');
DELETE FROM request_logs WHERE timestamp < datetime('now', '-14 days');
```

The dashboard shows a storage indicator: "Logs: 12,430 transactions, 847 MB, oldest 13 days".

### SSE / Streaming Responses

LLM APIs stream via Server-Sent Events. Approach: **tee the stream**.

- Forward SSE chunks to the client in real-time (don't buffer/block the agent)
- Simultaneously capture chunks into a buffer
- When the stream ends, store the assembled response body in `http_transactions`
- The agent experiences no latency impact from logging

For now, response-side inspection is **post-hoc** (visible in logs after it happened). Request-side inspection happens **before forwarding** (hold/deny).

**Future: response-side pre-hoc inspection.** The architecture is designed to support this. Step 5's deferred connect establishes the pattern: "buffer first, decide, then forward." The same applies to responses — buffer the full response before writing to the client, run content filters, then forward or block. When we add response-side rules, we swap the tee approach for full response buffering on filtered destinations. This is how we'd catch dangerous tool calls in LLM responses before they reach the agent. The SSE tee is the interim optimization for unfiltered traffic; filtered traffic will use buffer-then-decide.

---

## Content Filters (Phase 3)

Regex-based rules that auto-trigger on request content:

```yaml
greyproxy:
  content_filters:
    - name: "Credential leak"
      field: body
      regex: "private_key|BEGIN RSA|BEGIN EC"
      action: hold
      exclude_destinations:
        - "api.anthropic.com"
        - "api.openai.com"

    - name: "Dangerous methods"
      method: "DELETE"
      action: hold
```

When a filter matches:
- `hold` → request pending appears with filter name highlighted and matched content shown
- `deny` → HTTP 403 returned immediately
- `flag` → forwarded but log entry gets a warning badge

---

## Schema Migrations

The project already uses a versioned migration system (`schema_migrations` table in `migrations.go`). All new tables and column additions are added as new numbered migrations, so existing databases upgrade safely on restart.

| Migration | What |
|-----------|------|
| 4 | Create `http_transactions` table + indexes |
| 5 | Add `method_pattern`, `path_pattern`, `content_action` columns to `rules` (with defaults for existing rows) |
| 6 | Create `pending_http_requests` table |

Existing data is never modified or deleted by migrations. New columns use `DEFAULT` values so existing rules keep working identically. The migration runner skips already-applied versions via `schema_migrations`.

---

## Dashboard Additions

The dashboard gets new sections reflecting the HTTP transaction data:

### Stats Panel (existing, extended)
- **HTTP Transactions today**: count of MITM-captured requests
- **Top endpoints**: most-hit method+path combinations (e.g., "POST /v1/messages — 342 calls")
- **Storage usage**: "12,430 transactions, 847 MB, oldest 13 days" with retention indicator

### New: Live Activity Feed
A real-time stream of HTTP transactions as they happen (via WebSocket):
```
10:32:05  POST api.anthropic.com/v1/messages → 200 (1.2s)
10:32:04  GET  api.github.com/repos/... → 200 (0.3s)
10:32:01  POST api.openai.com/v1/chat/completions → 200 (2.1s)
```
Click any entry to expand full request/response details.

### New: Request Pending Section
When request-level holds are active, the dashboard shows them prominently — same data as the Pending page but inline for quick action without navigating away.

---

## Implementation Plan: Tiny Verifiable Steps

Each step produces a working, testable increment. Every step has:
- **Unit tests** for the new logic
- **Live test** you can run against the running proxy with curl

### Step 1: `http_transactions` table + model + CRUD

**What**: Create the new table, Go model, and basic CRUD operations.

**Test**:
- Unit: TestCreateHttpTransaction, TestGetHttpTransaction, TestListHttpTransactions
- Unit: TestHttpTransactionBodyTruncation (verify max_body_capture works)

---

### Step 2: Wire MITM callback to store transactions

**What**: Replace the current `mitmLogHook` (which only logs to console) with a hook that writes to `http_transactions`. Pass DB + config through to the sniffer setup.

**Test**:
- Unit: TestMitmCallbackCreatesTransaction (mock DB, verify fields)
- Live:
  ```bash
  # Terminal 1: proxy is running with MITM enabled, destination already allowed
  # Terminal 2:
  curl --proxy socks5h://localhost:43052 --insecure https://httpbin.org/get
  # Terminal 3: check it was captured
  curl http://localhost:43080/api/transactions | jq '.[] | {method, url, status_code}'
  # Expected: GET https://httpbin.org/get → 200
  ```

---

### Step 3: API endpoint for transactions

**What**: `GET /api/transactions` — list transactions with filters (destination, method, time range). `GET /api/transactions/:id` — full detail including body.

**Test**:
- Unit: TestTransactionsAPIList, TestTransactionsAPIDetail
- Live:
  ```bash
  # After making a few requests through the proxy:
  curl http://localhost:43080/api/transactions?destination=httpbin.org | jq
  curl http://localhost:43080/api/transactions/1 | jq '.request_body'
  ```

---

### Step 4: Transaction detail in Logs UI

**What**: Update the Logs tab to show HTTP transaction info. Each log entry expands to show method, URL, status, headers, body (collapsible).

**Test**:
- Live: Open dashboard, make requests through proxy, verify Logs tab shows HTTP details with expandable body sections.

---

### Step 5: Deferred connect — refactor sniffer for split handshake

**What**: This is the core architectural change. Refactor `terminateTLS` so it can:
1. Do TLS handshake with client (MITM) WITHOUT connecting to upstream
2. Return the decrypted client connection for reading
3. Later, when approved, connect to upstream and forward

Currently `terminateTLS` dials upstream first, then does client handshake. We reverse this.

**Test**:
- Unit: TestDeferredTlsHandshake — verify we can MITM-handshake with client, read HTTP request bytes, then separately connect upstream and forward
- Live:
  ```bash
  # With a test destination not yet in rules:
  curl --proxy socks5h://localhost:43052 --insecure https://httpbin.org/post \
    -X POST -d '{"test": "hello"}'
  # In dashboard: pending should show POST /post with body {"test": "hello"}
  ```

---

### Step 6: Request-level pending model + API

**What**: New `pending_http_requests` table. API endpoints to list/approve/deny request-level pendings. WebSocket events for real-time updates.

```sql
CREATE TABLE pending_http_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    container_name TEXT NOT NULL,
    destination_host TEXT NOT NULL,
    destination_port INTEGER NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    request_headers TEXT,
    request_body BLOB,
    request_body_size INTEGER,
    created_at DATETIME NOT NULL,
    UNIQUE(container_name, destination_host, destination_port, method, url)
);
```

**Test**:
- Unit: TestCreatePendingHttpRequest, TestApprovePendingHttpRequest, TestDenyPendingHttpRequest
- Live:
  ```bash
  # API shows request pendings
  curl http://localhost:43080/api/pending/requests | jq
  # Approve via API
  curl -X POST http://localhost:43080/api/pending/requests/1/allow
  ```

---

### Step 7: Request-level hold in sniffer

**What**: In `httpRoundTrip`, before forwarding the request upstream, evaluate request-level rules. If no matching allow rule and MITM is active → buffer request, create pending, wait for approval via EventBus.

**Test**:
- Unit: TestRequestHoldAndApprove, TestRequestHoldAndDeny, TestRequestAutoAllow
- Live:
  ```bash
  # Destination allowed but no request-level rule:
  curl --proxy socks5h://localhost:43052 --insecure https://httpbin.org/delete -X DELETE
  # Dashboard shows request pending with DELETE method
  # Approve → curl completes
  # Deny → curl gets 403
  ```

---

### Step 8: Pending UI for request-level holds

**What**: Update the Pending page to show two sections:
1. Connection pendings (existing, top)
2. Request pendings (new, below, with HTTP detail)

Rich display: method badge, URL, headers, body preview with syntax highlighting.

**Test**:
- Live: Open dashboard, trigger a request-level hold, verify the UI shows full HTTP details with approve/deny buttons.

---

### Step 9: Extended rules — method + path patterns

**What**: Add `method_pattern` and `path_pattern` columns to rules. Update rule matching to include these dimensions. Update Rules UI to show/edit these fields.

**Test**:
- Unit: TestRuleMatchesMethod, TestRuleMatchesPath, TestRuleSpecificityWithHttpFields
- Live:
  ```bash
  # Create a rule that allows GET but holds POST:
  curl -X POST http://localhost:43080/api/rules -d '{
    "container_pattern": "*",
    "destination_pattern": "httpbin.org",
    "port_pattern": "443",
    "method_pattern": "GET",
    "path_pattern": "*",
    "action": "allow"
  }'
  # GET flows through:
  curl --proxy socks5h://localhost:43052 --insecure https://httpbin.org/get
  # POST gets held:
  curl --proxy socks5h://localhost:43052 --insecure https://httpbin.org/post -X POST -d 'test'
  ```

---

### Step 10: Global kill switch

**What**: API endpoint `POST /api/killswitch` that:
1. Denies all pending requests (connection + request level)
2. Cancels all active connections via ConnTracker
3. Sets a "paused" flag that makes Bypass.Contains() deny everything
4. `POST /api/killswitch/resume` to re-enable

Dashboard header gets a red KILL button and green RESUME button.

**Test**:
- Unit: TestKillSwitchDeniesAll, TestKillSwitchClosesConnections, TestResume
- Live:
  ```bash
  # Start a long-running request:
  curl --proxy socks5h://localhost:43052 --insecure https://httpbin.org/delay/30 &
  # Hit kill switch:
  curl -X POST http://localhost:43080/api/killswitch
  # Background curl should fail immediately
  # New requests should fail:
  curl --proxy socks5h://localhost:43052 --insecure https://httpbin.org/get
  # Resume:
  curl -X POST http://localhost:43080/api/killswitch/resume
  ```

---

### Step 11: Content filters

**What**: Config-based regex filters that run on request body/headers/URL. When matched, override the content_action to hold/deny/flag.

**Test**:
- Unit: TestContentFilterMatchesBody, TestContentFilterExcludesDestination
- Live:
  ```bash
  # With filter configured for "private_key":
  curl --proxy socks5h://localhost:43052 --insecure https://httpbin.org/post \
    -X POST -d '{"data": "my private_key is abc123"}'
  # Dashboard shows held request with "Credential leak" filter highlighted
  ```

---

### Step 12: UI polish — redaction, syntax highlighting, body preview

**What**: Auto-redact sensitive patterns (API keys, bearer tokens) in UI display. JSON syntax highlighting for bodies. Collapsible sections for headers.

---

## Priority Order

Steps 1-4 are **Phase 1 (Observability)**: see everything, no behavior changes.
Steps 5-9 are **Phase 2 (Control)**: hold and approve individual HTTP requests.
Step 10 is **Emergency Control**: kill switch.
Steps 11-12 are **Phase 3 (Automation)**: content filters, polish.

I recommend implementing in this order. Phase 1 alone is immediately valuable — you can see every HTTP request your agent makes. Phase 2 gives granular control. Phase 3 automates the tedious parts.

---

## Open Questions

1. **Hold timeout for request pendings**: Proposal: **60 seconds** (longer than connection-level 30s because the TCP connection is alive and the client is more patient at HTTP level). Configurable.

2. **HTTP/2 multiplexing**: For the POC (Step 5-7), we can start with HTTP/1.1 only. HTTP/2 streams are already handled per-request in `h2Handler.ServeHTTP`, so adding the hold logic there should be straightforward in a follow-up.

3. **What if MITM cert is not installed?**: Fall back to connection-level only. No request details shown. The pending says "MITM unavailable — install CA cert for request details" with a link to `greyproxy cert install`.

---

## Config Changes Summary

```yaml
greyproxy:
  addr: ":43080"
  db: "greyproxy.db"

  # New
  max_body_capture: 1048576      # 1MB, max bytes per request/response body
  request_hold_timeout: 60       # seconds to wait for request-level approval
  log_retention_days: 14         # auto-delete logs + transactions older than this

  content_filters:               # Phase 3
    - name: "Credential leak"
      field: body
      regex: "private_key|BEGIN RSA"
      action: hold
      exclude_destinations: ["api.anthropic.com"]
```

---

## Summary

| What | Before | After |
|------|--------|-------|
| **Pending shows** | host:port | Full HTTP request with body |
| **Approval means** | "Allow this domain" | "Allow this request" or "Allow this domain" |
| **Visibility** | Connection events | Full HTTP transactions |
| **Control** | Domain allow/deny | Method/path/content rules |
| **Emergency** | Close browser tab | Kill switch |
| **Safety net** | None | Content filters |

**Core principle**: When you approve a request, you see exactly what you're approving.
