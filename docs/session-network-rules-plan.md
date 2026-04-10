# Session-Scoped Network Rules Plan

## Problem

Greywall profiles manage credentials and filesystem rules, but not network rules. Network rules live in greyproxy's SQLite DB as global permanent/temporary entries. When a user runs `greywall --profile codex`, they must manually approve every network destination through the dashboard. This is the #1 friction point from user feedback.

## Solution Overview

1. **greyproxy**: Accept network rules as part of session creation, scope them to session lifetime, auto-cleanup on session end/expire.
2. **greywall**: Add network rule presets to profiles, send them with session creation, refine `--learning` to extend defaults.

## Current Flow (broken)

```
greywall --profile codex
  -> POST /api/sessions (credentials only)
  -> codex tries api.openai.com -> no rule -> pending -> user clicks allow
  -> repeat for every domain, every session
```

## Proposed Flow

```
greywall --profile codex
  -> POST /api/sessions (credentials + network rules from profile)
  -> codex tries api.openai.com -> session rule matches -> allowed instantly
  -> session ends -> session-scoped rules auto-deleted
```

---

## greyproxy Changes

### 1. DB Migration

Add `session_id` column to `rules` table:

```sql
ALTER TABLE rules ADD COLUMN session_id TEXT DEFAULT NULL;
CREATE INDEX idx_rules_session_id ON rules(session_id);
```

Add `allow_all` column to `sessions` table:

```sql
ALTER TABLE sessions ADD COLUMN allow_all INTEGER DEFAULT 0;
```

Seed built-in localhost rules:

```sql
INSERT INTO rules (container_pattern, destination_pattern, port_pattern, rule_type, action, created_by)
VALUES ('*', '127.0.0.1', '*', 'builtin', 'allow', 'builtin');
INSERT INTO rules (container_pattern, destination_pattern, port_pattern, rule_type, action, created_by)
VALUES ('*', '::1', '*', 'builtin', 'allow', 'builtin');
INSERT INTO rules (container_pattern, destination_pattern, port_pattern, rule_type, action, created_by)
VALUES ('*', 'localhost', '*', 'builtin', 'allow', 'builtin');
```

### 2. API Change: POST /api/sessions

Add optional `network_rules` and `allow_all` fields:

```json
{
  "session_id": "uuid",
  "container_name": "codex",
  "mappings": { ... },
  "network_rules": [
    { "destination_pattern": "api.openai.com", "port_pattern": "443", "action": "allow" },
    { "destination_pattern": "**.openai.com", "port_pattern": "443", "action": "allow" }
  ],
  "allow_all": false,
  "ttl_seconds": 900
}
```

Response adds `rules_created` count.

### 3. Layered Rule Resolution

Rules have three source layers, evaluated in priority order:

| Priority | Source | How identified |
|---|---|---|
| 1 (highest) | Global | `session_id IS NULL AND created_by != 'builtin'` |
| 2 | Session | `session_id IS NOT NULL` |
| 3 (lowest) | Built-in | `created_by = 'builtin'` |

Resolution: highest layer match wins. Within same layer, highest specificity wins. Deny beats allow at same specificity within same layer.

This means:
- Global deny always blocks, even if profile says allow (strict mode)
- Global allow always permits, even if profile doesn't include it
- Session rules fill the gap for common tool destinations
- Built-in localhost rules are lowest priority, overridable by session or global deny

### 4. Per-Container AllowAll

When a session has `allow_all = true`, greyproxy skips ACL evaluation for that container. Used by `--learning` mode. Only affects the specific container, not global traffic.

### 5. Session Rule Lifecycle

| Event | Effect on session rules |
|---|---|
| Session created | Rules inserted with session_id, expires_at from session TTL |
| Session heartbeat | Rules' expires_at extended to match new session expiry |
| Session deleted | Rules deleted |
| Session expired | Background cleanup deletes rules alongside session |
| Session upserted | Old session rules deleted, new ones inserted |

---

## greywall Changes

### 1. Config Extension

Add `NetworkRule` type and `Rules` field to `NetworkConfig`:

```go
type NetworkRule struct {
    Destination string `json:"destination"`
    Port        string `json:"port,omitempty"`    // default "*"
    Action      string `json:"action,omitempty"`  // default "allow"
    Notes       string `json:"notes,omitempty"`
}

type NetworkConfig struct {
    // ... existing fields
    Rules []NetworkRule `json:"rules,omitempty"`
}
```

### 2. Agent Profile Defaults

Each agent profile gets network rules for its known API endpoints:

| Profile | Default allow destinations |
|---|---|
| claude | api.anthropic.com:443, **.anthropic.com:443, github.com:443, *.githubusercontent.com:443 |
| codex | api.openai.com:443, **.openai.com:443 |
| opencode | api.openai.com:443, api.anthropic.com:443 |
| aider | api.openai.com:443, api.anthropic.com:443 |
| cursor | api2.cursor.sh:443, api.openai.com:443, api.anthropic.com:443 |
| gemini | generativelanguage.googleapis.com:443 |
| goose | api.openai.com:443, api.anthropic.com:443 |
| amp | api.anthropic.com:443, api.openai.com:443 |
| copilot | api.github.com:443, copilot-proxy.githubusercontent.com:443 |
| cline | api.anthropic.com:443, api.openai.com:443 |
| Others | api.openai.com:443, api.anthropic.com:443 (safe default) |

### 3. Session Creation with Network Rules

`RegisterSession()` sends merged network rules (profile defaults + user overrides + CLI flags) as `network_rules` in the session request.

New CLI flag: `--allow PATTERN` adds a one-off allow rule for the session.

### 4. Learning Mode Refinement

`--learning` (existing flag):
- Loads default profile for the tool
- Sends profile network rules to greyproxy
- Sets `allow_all: true` on the session (everything goes through)
- On session end: queries logs, filters out known profile destinations, shows new ones
- Offers to save discovered destinations to user profile

`--learning --blank` (new flag):
- Skips default profile network rules
- Sets `allow_all: true` only
- Shows ALL destinations in summary (for auditing or untrusted defaults)

### 5. Post-Learning Output

```
[greywall] Learning session complete for "codex"

  Default profile rules (3 rules, already known):
    ok api.openai.com:443
    ok **.openai.com:443
    ok 127.0.0.1:*

  New destinations discovered (2):
    + sentry.io:443           (4 requests)
    + registry.npmjs.org:443  (17 requests)

  Add to profile? [Y/n] y
  Saved to ~/.config/greywall/learned/codex.json
```

---

## Implementation Phases

### Phase 1: greyproxy (this repo)
1. Migration: session_id on rules, allow_all on sessions, built-in localhost rules
2. Extend SessionCreateInput with NetworkRules and AllowAll
3. Session rule CRUD (create/delete/heartbeat-extend)
4. Layered FindMatchingRule resolution
5. Per-container allow_all check
6. API handler updates
7. Tests

### Phase 2: greywall (separate repo)
1. NetworkRule type in config
2. Network rules in agent profiles
3. Send network_rules in RegisterSession
4. --allow CLI flag
5. --blank flag for learning
6. Post-learning log query and profile save
