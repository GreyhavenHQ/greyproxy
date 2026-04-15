# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
rtk compression middleware -- rewrites LLM request bodies to compress the
output of tool_result blocks through `rtk` (https://github.com/rtk-ai/rtk)
before the model sees them, saving context-window tokens on noisy shell
output without modifying what the agent actually runs locally.

How it works:
1. Subscribe to http-request on greyproxy's `llm: true` filter. Every
   request greyproxy's endpoint registry resolves to an LLM decoder flows
   through here.
2. Parse the request body as JSON. Walk the messages looking for
   tool_result blocks (Anthropic) or role=tool messages (OpenAI).
3. For each tool result, find the paired tool_use/tool_call to recover
   the *command that produced this output* (bash command, tool name).
4. Pick an rtk stdin mode based on the command shape (diff/json/log).
   Content-first: if the output looks like a diff or JSON, trust that
   regardless of what produced it. Otherwise route by command.
5. Shell out to rtk as a pure text transformer -- rtk never executes any
   command, it only reads the already-captured output from stdin. If
   rtk fails or has nothing to strip the middleware falls through.
6. Return a `rewrite` decision with the reduced body.

Scope:
- Handles Anthropic /v1/messages and OpenAI /v1/chat/completions shapes.
- Only routes to rtk when we are confident the mode makes sense:
  diff/json by content, log by command family. Unknown shapes pass
  through untouched. `rtk log` is NOT a universal fallback -- it
  summarises by severity level and destroys content (e.g. `ls -la`)
  that has no log markers.

WARNING: This is an example only and is NOT meant for production use.
The command-shape heuristics are intentionally naive and will miss many
cases. Measure token savings on your workload before relying on this.

Usage:
    # 1. install rtk: cargo install --git https://github.com/rtk-ai/rtk
    # 2. run this middleware
    uv run middleware.py
    # 3. wire greyproxy to it
    greyproxy serve --middleware ws://localhost:9000/middleware
"""

import asyncio
import base64
import json
import logging
import re
import shutil
import subprocess

import websockets

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("middleware")

HOST = "0.0.0.0"
PORT = 9000

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Only look at LLM traffic (as determined by greyproxy's endpoint registry)
# and only at outgoing requests. Tool results flow agent -> model inside
# request bodies, not responses, so http-request is the right hook.
HELLO_RESPONSE = {
    "type": "hello",
    "name": "rtk-compress",
    "hooks": [
        {
            "type": "http-request",
            "filters": {
                "llm": True,
                "content_type": ["application/json"],
            },
        },
    ],
    "max_body_bytes": 4_194_304,  # 4 MB
}

# rtk subprocess timeout (seconds). Keep short so a hung rtk can't stall a
# live LLM request; on timeout we fall through to the original text.
RTK_TIMEOUT_S = 5

RTK_BIN = shutil.which("rtk")
if not RTK_BIN:
    log.warning("rtk binary not found on PATH -- middleware will act as a passthrough")


# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------

# Each tuple is (command-or-output predicate, rtk stdin mode).
# Evaluated in order -- first match wins. Predicates receive both the command
# string (may be empty) and the first ~256 chars of the output.

DIFF_SNIFF = re.compile(r"^(diff --git|---\s|\+\+\+\s|@@\s)", re.MULTILINE)
JSON_SNIFF = re.compile(r"^\s*[\[{]")
# Commands whose stdout is structured as severity-tagged log lines
# (Apr 15 ... [error] ...). `rtk log` expects this shape and produces a
# useful summary; applied to non-log text it destroys content by
# summarising to "0 errors 0 warnings".
LOG_CMD = re.compile(
    r"\b(tail|journalctl|dmesg|less|more)\b|/var/log/|\.log(\s|$)"
)
DIFF_CMD = re.compile(r"\bgit\s+(diff|show|log\s+-p)\b|\bdiff\s+-[a-zA-Z]*u")
JSON_CMD = re.compile(r"\bjq\b|\.json(\s|$)|curl[^|]*\|\s*jq")


def pick_mode(command: str, output_head: str) -> str | None:
    """Return the rtk subcommand to run, or None to skip compression.

    Heuristics are content-first, command-second: if the output *looks*
    like a diff or JSON, trust that regardless of what produced it.
    Unknown shapes return None so the tool_result passes through
    untouched -- rtk has no generic text compressor and mode-mismatched
    invocations (e.g. rtk log on ls output) silently destroy content.
    """
    if DIFF_SNIFF.search(output_head):
        return "diff"
    if JSON_SNIFF.match(output_head):
        return "json"
    if DIFF_CMD.search(command):
        return "diff"
    if JSON_CMD.search(command):
        return "json"
    if LOG_CMD.search(command):
        return "log"
    return None


def rtk_compress(text: str, mode: str) -> str | None:
    """Pipe text through rtk's stdin-accepting subcommand for `mode`.
    Returns compressed text, or None on any failure (empty output,
    timeout, non-zero exit). Caller falls through to the original text
    on None.

    rtk's stdin conventions differ by subcommand:
      log  -- bare `rtk log`; a `-` arg is treated as a literal filename
      json -- `rtk json -`; the `-` is accepted as stdin
      diff -- `rtk diff -`; `-` is documented as stdin for unified diff
    """
    if not RTK_BIN:
        return None
    if mode == "log":
        args = [RTK_BIN, "log"]
    else:
        args = [RTK_BIN, mode, "-"]
    try:
        result = subprocess.run(
            args,
            input=text,
            capture_output=True,
            text=True,
            timeout=RTK_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        log.warning("rtk %s timed out after %ds on %d bytes", mode, RTK_TIMEOUT_S, len(text))
        return None
    except OSError as e:
        log.warning("rtk %s exec failed: %s", mode, e)
        return None
    if result.returncode != 0:
        log.warning("rtk %s exit=%d stderr=%s", mode, result.returncode, result.stderr[:200])
        return None
    compressed = result.stdout
    if not compressed:
        return None
    return compressed


# ---------------------------------------------------------------------------
# Anthropic message walker
# ---------------------------------------------------------------------------


def _coerce_tool_result_text(content) -> tuple[str, str]:
    """Anthropic allows tool_result.content to be either a string or a list
    of content blocks. Returns (text, shape) where shape is 'str' or 'list'
    so we can write back in the same shape.
    """
    if isinstance(content, str):
        return content, "str"
    if isinstance(content, list):
        # Concatenate the text blocks. Non-text blocks (images etc.) are
        # left alone and won't be rewritten.
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
        return "\n".join(parts), "list"
    return "", "other"


def _set_tool_result_text(content, new_text: str, shape: str):
    if shape == "str":
        return new_text
    if shape == "list":
        # Replace the first text block, drop the rest of the text blocks.
        out = []
        text_written = False
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                if not text_written:
                    out.append({"type": "text", "text": new_text})
                    text_written = True
                # drop duplicate text blocks
            else:
                out.append(block)
        if not text_written:
            out.append({"type": "text", "text": new_text})
        return out
    return content


def rewrite_anthropic(body: dict) -> int:
    """Mutate body.messages in place. Returns count of rewritten blocks."""
    messages = body.get("messages")
    if not isinstance(messages, list):
        return 0

    # Index tool_use blocks by id so tool_result blocks can find their command.
    tool_use_commands: dict[str, str] = {}
    for msg in messages:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tid = block.get("id") or ""
                name = block.get("name") or ""
                inp = block.get("input") or {}
                # Bash tool: input.command is the actual shell. Other tools:
                # fall back to the tool name, which lets LOG_CMD etc. still
                # pick something up if the name is descriptive.
                cmd = inp.get("command") if isinstance(inp, dict) else None
                tool_use_commands[tid] = cmd or name

    rewritten = 0
    for msg in messages:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not (isinstance(block, dict) and block.get("type") == "tool_result"):
                continue
            tid = block.get("tool_use_id") or ""
            command = tool_use_commands.get(tid, "")
            text, shape = _coerce_tool_result_text(block.get("content"))
            if not text:
                continue
            mode = pick_mode(command, text[:256])
            if mode is None:
                continue
            compressed = rtk_compress(text, mode)
            if compressed is None or compressed == text:
                continue
            block["content"] = _set_tool_result_text(block.get("content"), compressed, shape)
            rewritten += 1
            log.info("rewrote tool_result id=%s mode=%s %d -> %d bytes (-%.0f%%)",
                     tid, mode, len(text), len(compressed),
                     100 * (1 - len(compressed) / len(text)) if text else 0)
    return rewritten


# ---------------------------------------------------------------------------
# OpenAI message walker
# ---------------------------------------------------------------------------


def rewrite_openai(body: dict) -> int:
    messages = body.get("messages")
    if not isinstance(messages, list):
        return 0

    # Index tool_calls by id so role=tool messages can find their command.
    tool_call_commands: dict[str, str] = {}
    for msg in messages:
        for tc in msg.get("tool_calls") or []:
            tid = tc.get("id") or ""
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
            # arguments is a JSON string, not a dict
            args_raw = fn.get("arguments") or ""
            cmd = name
            try:
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                if isinstance(args, dict) and "command" in args:
                    cmd = args["command"]
            except (json.JSONDecodeError, TypeError):
                pass
            tool_call_commands[tid] = cmd

    rewritten = 0
    for msg in messages:
        if msg.get("role") != "tool":
            continue
        tid = msg.get("tool_call_id") or ""
        command = tool_call_commands.get(tid, "")
        content = msg.get("content")
        if not isinstance(content, str) or not content:
            continue
        mode = pick_mode(command, content[:256])
        if mode is None:
            continue
        compressed = rtk_compress(content, mode)
        if compressed is None or compressed == content:
            continue
        msg["content"] = compressed
        rewritten += 1
        log.info("rewrote tool content id=%s mode=%s %d -> %d bytes (-%.0f%%)",
                 tid, mode, len(content), len(compressed),
                 100 * (1 - len(compressed) / len(content)) if content else 0)
    return rewritten


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


def decode_body(b64: str | None) -> bytes:
    return base64.b64decode(b64) if b64 else b""


def allow(rid: str) -> dict:
    return {"type": "decision", "id": rid, "action": "allow"}


def rewrite_request(rid: str, body: bytes, tags: dict | None = None) -> dict:
    d: dict = {
        "type": "decision",
        "id": rid,
        "action": "rewrite",
        "body": base64.b64encode(body).decode(),
    }
    if tags:
        d["tags"] = tags
    return d


def handle_request(msg: dict) -> dict:
    print("type=%s method=%s uri=%s" % (msg["type"], msg["method"], msg["uri"]))
    rid = msg["id"]
    raw = decode_body(msg.get("body"))
    if not raw:
        return allow(rid)

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as e:
        print("ERROR:JSONDECODEERROR")
        return allow(rid)
    if not isinstance(body, dict):
        print("ERROR:NOTADICT")
        return allow(rid)

    before = len(raw)
    rewritten = rewrite_anthropic(body) + rewrite_openai(body)
    if rewritten == 0:
        print("ERROR:NOREWRITE")
        return allow(rid)

    new_raw = json.dumps(body).encode("utf-8")
    saved = before - len(new_raw)
    log.info("request %s %s%s: %d tool_result rewrites, %d -> %d bytes (-%.0f%%)",
             msg["method"], msg["host"], msg["uri"], rewritten, before, len(new_raw),
             100 * saved / before if before else 0)
    return rewrite_request(rid, new_raw, tags={
        "rtk.rewrites": rewritten,
        "rtk.bytes_before": before,
        "rtk.bytes_after": len(new_raw),
    })


# ---------------------------------------------------------------------------
# WebSocket server
# ---------------------------------------------------------------------------

HANDLERS = {"http-request": handle_request}


async def serve(websocket):
    log.info("proxy connected from %s", websocket.remote_address)
    raw = await asyncio.wait_for(websocket.recv(), timeout=5)
    hello = json.loads(raw)
    if hello.get("type") != "hello":
        log.error("expected hello, got: %s", hello.get("type"))
        return
    log.info("proxy hello: version=%s", hello.get("version"))
    await websocket.send(json.dumps(HELLO_RESPONSE))
    log.info("sent hello: %d hooks, rtk=%s", len(HELLO_RESPONSE["hooks"]), RTK_BIN or "MISSING")

    async for raw in websocket:
        msg = json.loads(raw)
        handler = HANDLERS.get(msg.get("type", ""))
        if handler is None:
            log.warning("unknown message type: %s", msg.get("type"))
            continue
        await websocket.send(json.dumps(handler(msg)))


async def _main():
    async with websockets.serve(serve, HOST, PORT):
        log.info("listening on ws://%s:%d/middleware", HOST, PORT)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(_main())
