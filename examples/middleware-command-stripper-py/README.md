# Dangerous Command Stripper

Rewrites LLM responses to redact shell commands that look destructive, replacing them with a visible warning marker so the user knows something was removed.

> **Not for production use.** The heuristics are intentionally naive, will miss obfuscated commands, and may produce false positives on documentation that mentions these commands. A real deployment needs sandboxed execution, not regex filtering.

## What it does

- Hooks `http-response` only, filtered by path to common LLM completion endpoints (`/v1/chat/completions`, `/v1/completions`, `/v1/responses`, `/v1/messages`) with JSON content type. Works with any provider, including self-hosted models.
- Scans response bodies for patterns like `rm -rf /`, `chmod -R 777 /`, `curl | bash`, `dd if=/dev/zero of=/dev/sda`, fork bombs, and others
- Replaces matched commands with `[STRIPPED: command removed by middleware -- flagged as: ...]`
- Logs a warning for every stripped command

## Example

Before (LLM response body):
```
To clean up, run: rm -rf /tmp/build && rm -rf /
```

After (what the client receives):
```
To clean up, run: rm -rf /tmp/build && [STRIPPED: command removed by middleware -- flagged as: recursive force-delete from root]
```

## Run

```bash
uv run middleware.py
```

```bash
greyproxy serve --middleware ws://localhost:9000/middleware
```
