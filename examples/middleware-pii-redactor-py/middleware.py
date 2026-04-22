# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
PII redactor -- replaces personally identifiable information in requests
with placeholders, then restores the original values in responses.

Bidirectional:
  Request:  "Please summarize John Doe's file"
         -> "Please summarize PERSON_A's file"
  Response: "PERSON_A's file contains 3 items"
         -> "John Doe's file contains 3 items"

The upstream LLM never sees real PII, but the end user gets back a
response with the original names and emails in place.

WARNING: Example only. The regex patterns miss many PII forms (non-
Western names, international phone numbers, addresses, national IDs).
A production redactor should use a dedicated NER model (spaCy,
Presidio) or a cloud DLP API. Mapping is in-memory and won't survive
a restart; concurrent sessions share the placeholder namespace.

Usage (preferred):
    greyproxy serve --middleware-cmd 'uv run examples/middleware-pii-redactor-py/middleware.py'

Or as a WS server:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
"""
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_lib"))
from greyproxy_middleware import (  # noqa: E402
    allow,
    decode_body,
    passthrough,
    rewrite_request,
    rewrite_response,
    run,
)

log = logging.getLogger(__name__)

# Intentionally simple patterns. Production code needs a real NER model.
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
# Looks like "Firstname Lastname" (capitalized words, 2-3 parts).
# Will match many non-name phrases — that's the cost of regex-based NER.
NAME_RE = re.compile(r"\b([A-Z][a-z]{1,15})\s+([A-Z][a-z]{1,15})(?:\s+([A-Z][a-z]{1,15}))?\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE_RE = re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b")

PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (EMAIL_RE, "EMAIL"),
    (SSN_RE, "SSN"),
    (PHONE_RE, "PHONE"),
    (NAME_RE, "PERSON"),
]

# Bidirectional maps. In-memory only; lost on restart.
forward_map: dict[str, str] = {}  # real_value -> placeholder
reverse_map: dict[str, str] = {}  # placeholder -> real_value
counters: dict[str, int] = defaultdict(int)


def get_placeholder(real_value: str, category: str) -> str:
    if real_value in forward_map:
        return forward_map[real_value]
    counters[category] += 1
    # PERSON_A, PERSON_B, ..., then PERSON_27, PERSON_28, ... after 26.
    if counters[category] <= 26:
        placeholder = f"{category}_{chr(64 + counters[category])}"
    else:
        placeholder = f"{category}_{counters[category]}"
    forward_map[real_value] = placeholder
    reverse_map[placeholder] = real_value
    log.info("mapped %r -> %s", real_value, placeholder)
    return placeholder


def redact(text: str) -> tuple[str, int]:
    count = 0
    for pattern, category in PII_PATTERNS:
        # Count matches first so we can report, then replace in one shot.
        count += sum(1 for _ in pattern.finditer(text))
        text = pattern.sub(lambda m, c=category: get_placeholder(m.group(0), c), text)
    return text, count


def restore(text: str) -> tuple[str, int]:
    count = 0
    # Longest placeholder first to avoid partial replacements (PERSON_A2
    # must not be replaced by the PERSON_A rule).
    for placeholder, real_value in sorted(reverse_map.items(), key=lambda kv: -len(kv[0])):
        if placeholder in text:
            text = text.replace(placeholder, real_value)
            count += 1
    return text, count


def handle_request(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("body"))
    if not raw:
        return allow(rid)

    text = raw.decode("utf-8", errors="replace")
    redacted, count = redact(text)

    if count == 0:
        log.info("request  %s %s%s (no PII found)", msg["method"], msg["host"], msg["uri"])
        return allow(rid)

    log.warning("request  %s %s%s REDACTED %d PII value(s)",
                msg["method"], msg["host"], msg["uri"], count)
    return rewrite_request(
        rid,
        body=redacted.encode("utf-8"),
        tags={"pii.redacted": count},
    )


def handle_response(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("response_body"))
    if not raw:
        return passthrough(rid)

    text = raw.decode("utf-8", errors="replace")
    restored, count = restore(text)

    if count == 0:
        log.info("response %s %s%s -> %d (no placeholders to restore)",
                 msg["method"], msg["host"], msg["uri"], msg["status_code"])
        return passthrough(rid)

    log.info("response %s %s%s -> %d RESTORED %d PII value(s)",
             msg["method"], msg["host"], msg["uri"], msg["status_code"], count)
    return rewrite_response(
        rid,
        body=restored.encode("utf-8"),
        tags={"pii.restored": count},
    )


if __name__ == "__main__":
    run(
        name="pii-redactor",
        handle_request=handle_request,
        handle_response=handle_response,
        filters_request={
            "host": ["*.openai.com", "*.anthropic.com", "*.googleapis.com"],
            "method": ["POST"],
            "content_type": ["application/json"],
        },
        filters_response={
            "host": ["*.openai.com", "*.anthropic.com", "*.googleapis.com"],
            "content_type": ["application/json"],
        },
        max_body_bytes=2_097_152,
    )
