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
  through untouched.

WARNING: Example only, not production-ready. Measure token savings on
your workload before relying on this.

Usage (preferred: greyproxy owns the lifecycle):
    cargo install --git https://github.com/rtk-ai/rtk   # once
    greyproxy serve --middleware-cmd 'uv run examples/middleware-rtk-compress-py/middleware.py'

Or as a standalone WS server:
    uv run middleware.py
    greyproxy serve --middleware ws://localhost:9000/middleware
"""
import json
import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Shared helper picks transport (stdio / ws) at launch time.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_lib"))
from greyproxy_middleware import allow, decode_body, rewrite_request, run  # noqa: E402

log = logging.getLogger(__name__)

# rtk subprocess timeout. Short enough that a hung rtk doesn't stall a
# live LLM request; on timeout we fall through to the original text.
RTK_TIMEOUT_S = 5

RTK_BIN = shutil.which("rtk")


# ---------------------------------------------------------------------------
# Mode selection
# ---------------------------------------------------------------------------

DIFF_SNIFF = re.compile(r"^(diff --git|---\s|\+\+\+\s|@@\s)", re.MULTILINE)
JSON_SNIFF = re.compile(r"^\s*[\[{]")
# Commands whose stdout is structured as severity-tagged log lines.
# `rtk log` expects this shape and produces a useful summary; applied
# to non-log text it destroys content.
LOG_CMD = re.compile(r"\b(tail|journalctl|dmesg|less|more)\b|/var/log/|\.log(\s|$)")
DIFF_CMD = re.compile(r"\bgit\s+(diff|show|log\s+-p)\b|\bdiff\s+-[a-zA-Z]*u")
JSON_CMD = re.compile(r"\bjq\b|\.json(\s|$)|curl[^|]*\|\s*jq")


def pick_mode(command: str, output_head: str) -> str | None:
    """Return the rtk subcommand to run, or None to skip compression.

    Content-first: if the output *looks* like a diff or JSON, trust that
    regardless of what produced it. Unknown shapes return None so the
    tool_result passes through untouched -- rtk has no generic text
    compressor and mode-mismatched invocations silently destroy content.
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
    Returns compressed text, or None on any failure.
    """
    if not RTK_BIN:
        return None
    args = [RTK_BIN, "log"] if mode == "log" else [RTK_BIN, mode, "-"]
    try:
        result = subprocess.run(
            args, input=text, capture_output=True, text=True,
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
    return result.stdout or None


# ---------------------------------------------------------------------------
# Anthropic message walker
# ---------------------------------------------------------------------------


def _coerce_tool_result_text(content) -> tuple[str, str]:
    """Anthropic allows tool_result.content to be a string or a list of
    content blocks. Returns (text, shape) so the rewrite can preserve
    the original shape.
    """
    if isinstance(content, str):
        return content, "str"
    if isinstance(content, list):
        parts = [b.get("text", "") for b in content
                 if isinstance(b, dict) and b.get("type") == "text"]
        return "\n".join(parts), "list"
    return "", "other"


def _set_tool_result_text(content, new_text: str, shape: str):
    if shape == "str":
        return new_text
    if shape == "list":
        out = []
        text_written = False
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                if not text_written:
                    out.append({"type": "text", "text": new_text})
                    text_written = True
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

    tool_call_commands: dict[str, str] = {}
    for msg in messages:
        for tc in msg.get("tool_calls") or []:
            tid = tc.get("id") or ""
            fn = tc.get("function") or {}
            name = fn.get("name") or ""
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


def handle_request(msg: dict) -> dict:
    rid = msg["id"]
    raw = decode_body(msg.get("body"))
    if not raw:
        return allow(rid)

    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return allow(rid)
    if not isinstance(body, dict):
        return allow(rid)

    before = len(raw)
    rewritten = rewrite_anthropic(body) + rewrite_openai(body)
    if rewritten == 0:
        return allow(rid)

    new_raw = json.dumps(body).encode("utf-8")
    saved = before - len(new_raw)
    log.info("request %s %s%s: %d tool_result rewrites, %d -> %d bytes (-%.0f%%)",
             msg["method"], msg["host"], msg["uri"], rewritten, before, len(new_raw),
             100 * saved / before if before else 0)
    return rewrite_request(
        rid,
        body=new_raw,
        tags={
            "rtk.rewrites": rewritten,
            "rtk.bytes_before": before,
            "rtk.bytes_after": len(new_raw),
        },
    )


if __name__ == "__main__":
    if not RTK_BIN:
        log.warning("rtk binary not found on PATH -- middleware will act as a passthrough")
    else:
        log.info("rtk binary: %s", RTK_BIN)

    # Only outgoing requests on LLM endpoints, JSON content type.
    run(
        name="rtk-compress",
        handle_request=handle_request,
        filters_request={"llm": True, "content_type": ["application/json"]},
        max_body_bytes=4_194_304,
    )
