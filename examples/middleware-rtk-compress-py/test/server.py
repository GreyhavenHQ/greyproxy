# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Fake LLM server -- a minimal stand-in for the Anthropic /v1/messages API
used to exercise the rtk compression middleware end-to-end.

Responses are stateless, keyed on the content of the request:
  no tool_result in messages -> tool_use asking to run `cat package.json`
  tool_result present        -> final text saying it's done
This lets the test be re-run without restarting the server.

After each request it writes the received body to /tmp/rtk_test_last_req.json
so the client can diff "what I sent" against "what the server actually saw"
(i.e. the middleware's rewrite).

Run in one terminal:
    uv run test/server.py
"""

import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 18123
TRACE_FILE = "/tmp/rtk_test_last_req.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fake-llm")

_request_count = 0


def has_tool_result(body: dict) -> bool:
    for msg in body.get("messages") or []:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                return True
    return False


def canned_response(n: int, body: dict) -> dict:
    """Return the assistant message for the given request. Stateless: the
    shape of the incoming messages decides which response to return, so the
    test can be re-run without restarting the server."""
    if not has_tool_result(body):
        return {
            "id": f"msg_fake_{n}",
            "type": "message",
            "role": "assistant",
            "model": "claude-fake-1",
            "content": [
                {"type": "text", "text": "Let me check the package.json first."},
                {
                    "type": "tool_use",
                    "id": "toolu_fake_1",
                    "name": "Bash",
                    "input": {"command": "cat package.json"},
                },
            ],
            "stop_reason": "tool_use",
        }
    return {
        "id": f"msg_fake_{n}",
        "type": "message",
        "role": "assistant",
        "model": "claude-fake-1",
        "content": [
            {
                "type": "text",
                "text": "Your project depends on react, vite, and tailwind. Done.",
            }
        ],
        "stop_reason": "end_turn",
    }


def summarize_tool_results(body: dict) -> list[tuple[str, int]]:
    """Return a list of (tool_use_id, content_length) for every tool_result
    block found in the request. Used for logging so the operator can see
    what size the server actually received after the middleware ran."""
    out: list[tuple[str, int]] = []
    for msg in body.get("messages") or []:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not (isinstance(block, dict) and block.get("type") == "tool_result"):
                continue
            tid = block.get("tool_use_id") or "?"
            tc = block.get("content")
            if isinstance(tc, str):
                out.append((tid, len(tc)))
            elif isinstance(tc, list):
                total = sum(
                    len(b.get("text", "")) for b in tc
                    if isinstance(b, dict) and b.get("type") == "text"
                )
                out.append((tid, total))
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence the default access log; we log what matters below.
        pass

    def do_POST(self):
        global _request_count
        _request_count += 1
        n = _request_count

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b""

        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = None

        try:
            with open(TRACE_FILE, "wb") as f:
                f.write(raw)
        except OSError as e:
            log.warning("could not write trace file: %s", e)

        tool_results = summarize_tool_results(body) if isinstance(body, dict) else []
        log.info("request #%d %s bytes=%d path=%s tool_results=%s",
                 n, self.command, len(raw), self.path,
                 [(tid, sz) for tid, sz in tool_results] or "none")

        if not isinstance(body, dict):
            self.send_error(400, "invalid JSON")
            return

        resp = canned_response(n, body)
        payload = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main():
    log.info("fake LLM server listening on http://%s:%d/v1/messages", HOST, PORT)
    log.info("trace file: %s", TRACE_FILE)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
        sys.exit(0)


if __name__ == "__main__":
    main()
