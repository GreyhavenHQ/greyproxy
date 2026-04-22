# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
Dangerous command stripper -- rewrites LLM responses to redact shell
commands that look destructive (rm -rf, chmod 777, curl|bash, etc.).

Inspects response bodies from LLM completion endpoints. When it finds a
dangerous-looking command, replaces it with a warning marker so the end
user or agent sees that something was stripped rather than silently
executing it.

WARNING: Example only. Heuristics are intentionally naive and will miss
obfuscated commands, produce false positives on documentation, and do
not cover all dangerous patterns. Real deployments need a proper
sandboxed execution model, not regex.

Usage (preferred):
    greyproxy serve --middleware-cmd 'uv run examples/middleware-command-stripper-py/middleware.py'

Or as a WS server:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
"""
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_lib"))
from greyproxy_middleware import decode_body, passthrough, rewrite_response, run  # noqa: E402

log = logging.getLogger(__name__)

# Each tuple is (compiled regex, human-readable label).
DANGEROUS_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/", re.IGNORECASE),
     "recursive force-delete from root"),
    (re.compile(r"rm\s+-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+/", re.IGNORECASE),
     "recursive force-delete from root"),
    (re.compile(r"mkfs\.", re.IGNORECASE), "filesystem format"),
    (re.compile(r"dd\s+if=/dev/zero\s+of=/dev/", re.IGNORECASE), "disk overwrite"),
    (re.compile(r"chmod\s+-R\s+777\s+/", re.IGNORECASE),
     "recursive world-writable permissions from root"),
    (re.compile(r"curl\s+[^\|]*\|\s*(sudo\s+)?bash", re.IGNORECASE), "pipe curl to bash"),
    (re.compile(r"wget\s+[^\|]*\|\s*(sudo\s+)?bash", re.IGNORECASE), "pipe wget to bash"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\}\s*;:", re.IGNORECASE), "fork bomb"),
    (re.compile(r">\s*/dev/sda", re.IGNORECASE), "write to raw disk device"),
    (re.compile(r"shutdown\s+(-h\s+)?now", re.IGNORECASE), "immediate shutdown"),
    (re.compile(r"init\s+0", re.IGNORECASE), "halt system"),
]

REDACTION_MARKER = "[STRIPPED: command removed by middleware -- flagged as: {}]"


def strip_dangerous(text: str) -> tuple[str, list[str]]:
    """Replace dangerous command patterns in text. Returns (cleaned, flags)."""
    flags = []
    for pattern, label in DANGEROUS_PATTERNS:
        if pattern.search(text):
            text = pattern.sub(REDACTION_MARKER.format(label), text)
            flags.append(label)
    return text, flags


def handle_response(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("response_body"))
    if not raw:
        return passthrough(rid)

    text = raw.decode("utf-8", errors="replace")
    cleaned, flags = strip_dangerous(text)

    if not flags:
        log.info("response %s %s%s -> %d (clean)",
                 msg["method"], msg["host"], msg["uri"], msg["status_code"])
        return passthrough(rid)

    log.warning("response %s %s%s -> %d STRIPPED: %s",
                msg["method"], msg["host"], msg["uri"],
                msg["status_code"], ", ".join(flags))
    return rewrite_response(
        rid,
        body=cleaned.encode("utf-8"),
        tags={"command-stripper.flags": flags},
    )


if __name__ == "__main__":
    # Filter on LLM completion endpoints by path rather than domain so
    # this works with any provider (including self-hosted models).
    run(
        name="command-stripper",
        handle_response=handle_response,
        filters_response={
            "path": [
                "/v1/chat/completions",
                "/v1/completions",
                "/v1/responses",
                "/v1/messages",
            ],
            "content_type": ["application/json"],
        },
        max_body_bytes=2_097_152,
    )
