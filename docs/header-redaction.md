# Sensitive Header Redaction

> Available since v0.3.3

Greyproxy intercepts HTTPS traffic (via MITM) and stores HTTP transactions in its SQLite database for inspection. By default, sensitive header values are replaced with `[REDACTED]` before storage, so credentials never hit the database.

## What gets redacted

The following header patterns are redacted out of the box (case-insensitive):

| Pattern                | Matches                                        |
|------------------------|------------------------------------------------|
| `Authorization`        | Bearer tokens, Basic auth, OAuth               |
| `Proxy-Authorization`  | Proxy credentials                              |
| `Cookie`               | Session cookies, auth cookies                  |
| `Set-Cookie`           | Response cookies                               |
| `*api-key*`            | `X-Api-Key`, `Anthropic-Api-Key`, etc.         |
| `*token*`              | `X-Auth-Token`, `X-Csrf-Token`, etc.           |
| `*secret*`             | `X-Client-Secret`, etc.                        |

Pattern syntax:
- **Exact match**: `Authorization` matches only `Authorization`
- **Contains** (`*word*`): matches any header containing `word`
- **Starts with** (`word*`): matches headers starting with `word`
- **Ends with** (`*word`): matches headers ending with `word`

All matching is case-insensitive.

## How it works

Redaction happens at capture time, before the transaction is written to SQLite. The original header key is preserved (so you can see that an `Authorization` header was present), but the value is replaced with `[REDACTED]`.

```
Before:  Authorization: Bearer sk-ant-api03-xxxxx
After:   Authorization: [REDACTED]
```

## Adding custom patterns

You can add extra redaction patterns via the settings API. Custom patterns are merged with the defaults and persisted to `settings.json`.

```bash
# Add custom patterns
curl -X PUT http://localhost:43080/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"redactedHeaders": ["*password*", "X-My-Internal-Auth"]}'
```

The response includes the full list of active patterns (defaults + custom):

```bash
# View current patterns
curl http://localhost:43080/api/settings | jq .redactedHeaders
```

## Redacting existing data

If you have transactions stored before redaction was enabled (or before adding a custom pattern), you can retroactively redact them from the settings UI or via the API:

**UI**: Go to Settings, expand Advanced, and click "Redact stored headers". A progress bar shows real-time status.

**API**:
```bash
curl -X POST http://localhost:43080/api/maintenance/redact-headers
```

This runs in the background, processes all stored transactions in batches, and is idempotent (safe to run multiple times). Concurrent runs are rejected with HTTP 409.

## Settings file

Custom patterns are stored in `~/.local/share/greyproxy/settings.json`:

```json
{
  "redactedHeaders": ["*password*", "X-My-Internal-Auth"]
}
```

Only your extra patterns are stored; the defaults are always applied regardless.
