# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
Passthrough middleware -- reference implementation of the transport-
agnostic pattern.

Same handler code works under both greyproxy transports:

  - greyproxy serve --middleware-cmd 'uv run middleware.py'
    (greyproxy spawns us; we speak NDJSON on stdin/stdout)

  - uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
    (we run a WS server; greyproxy dials it)

The helper library in examples/_lib picks the transport based on env.
The author only writes handle_request / handle_response.

WARNING: Example only, not production-ready.
"""
import logging
import sys
from pathlib import Path

# The helper library lives one level up in examples/_lib/. This is the
# one piece of boilerplate the author keeps in their middleware file.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_lib"))
from greyproxy_middleware import allow, decode_body, passthrough, run  # noqa: E402

log = logging.getLogger(__name__)


def handle_request(msg: dict) -> dict:
    body = decode_body(msg.get("body"))
    log.info("request  %s %s%s (%d bytes) container=%s",
             msg["method"], msg["host"], msg["uri"], len(body),
             msg.get("container", ""))
    return allow(msg["id"])


def handle_response(msg: dict) -> dict:
    resp_body = decode_body(msg.get("response_body"))
    log.info("response %s %s%s -> %d (%d bytes, %dms)",
             msg["method"], msg["host"], msg["uri"],
             msg["status_code"], len(resp_body), msg.get("duration_ms", 0))
    return passthrough(msg["id"])


if __name__ == "__main__":
    run(
        name="passthrough",
        handle_request=handle_request,
        handle_response=handle_response,
        max_body_bytes=1_048_576,
    )
