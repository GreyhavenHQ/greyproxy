# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
Audit log -- writes every request and response to a structured JSONL file.

Read-only: never blocks or rewrites. Bodies themselves are NOT logged
(only sizes) to keep the log manageable and avoid storing sensitive data.

Output (audit.jsonl): one line per event:
    {"ts": "...", "direction": "request", "container": "my-app",
     "method": "POST", "host": "api.openai.com", "uri": "/v1/...",
     "body_bytes": 1234, "tls": true}
    {"ts": "...", "direction": "response", "container": "my-app",
     "method": "POST", "host": "api.openai.com", "uri": "/v1/...",
     "status_code": 200, "body_bytes": 5678, "duration_ms": 312}

WARNING: Example only. No rotation, no compression, no access controls.
A production audit system should use a proper log pipeline (syslog,
SIEM, cloud logging) with tamper-proof storage.

Usage (preferred):
    greyproxy serve --middleware-cmd 'uv run examples/middleware-audit-log-py/middleware.py'

Or as a WS server:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
"""
import base64
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_lib"))
from greyproxy_middleware import allow, passthrough, run  # noqa: E402

log = logging.getLogger(__name__)

AUDIT_FILE = "audit.jsonl"

# Counters for the periodic status line.
stats = {"requests": 0, "responses": 0}


def body_size(b64: str | None) -> int:
    """Return decoded body size in bytes. base64 is ~4/3 of the raw
    length; decoding is cheap enough that we don't bother with the
    length math."""
    if not b64:
        return 0
    return len(base64.b64decode(b64))


def write_record(record: dict):
    with open(AUDIT_FILE, "a") as f:
        f.write(json.dumps(record, separators=(",", ":")) + "\n")


def handle_request(msg: dict) -> dict:
    stats["requests"] += 1
    write_record({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "direction": "request",
        "container": msg.get("container", ""),
        "method": msg["method"],
        "host": msg["host"],
        "uri": msg["uri"],
        "proto": msg.get("proto", ""),
        "body_bytes": body_size(msg.get("body")),
        "tls": msg.get("tls", False),
    })
    if stats["requests"] % 100 == 0:
        log.info("audit stats: %d requests, %d responses logged",
                 stats["requests"], stats["responses"])
    return allow(msg["id"])


def handle_response(msg: dict) -> dict:
    stats["responses"] += 1
    write_record({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "direction": "response",
        "container": msg.get("container", ""),
        "method": msg["method"],
        "host": msg["host"],
        "uri": msg["uri"],
        "status_code": msg["status_code"],
        "request_body_bytes": body_size(msg.get("request_body")),
        "response_body_bytes": body_size(msg.get("response_body")),
        "duration_ms": msg.get("duration_ms", 0),
    })
    return passthrough(msg["id"])


if __name__ == "__main__":
    log.info("writing audit log to %s", AUDIT_FILE)
    run(
        name="audit-log",
        handle_request=handle_request,
        handle_response=handle_response,
        max_body_bytes=0,  # we only log sizes, so accept null (truncated) bodies too
    )
