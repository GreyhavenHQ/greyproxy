#!/usr/bin/env python3
"""Incremental conversation assembler with API server.

Reads directly from greyproxy.db, maintains conversation.db,
and optionally serves a web UI + REST API.

Usage:
  python assemble2.py                              # one-shot assembly
  python assemble2.py --serve                      # serve API + assemble once
  python assemble2.py --serve --watch              # serve API + periodic re-assembly
  python assemble2.py --serve --watch --interval 5 # check every 5 seconds
"""

import argparse
import gzip
import json
import os
import re
import sqlite3
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TARGET_URLS = {
    "https://api.anthropic.com/v1/messages",
    "https://api.anthropic.com/v1/messages?beta=true",
}

TIME_GAP_THRESHOLD = timedelta(minutes=5)

SCAFFOLDING_TEXTS = {
    "Tool loaded.",
    "[Request interrupted by user]",
    "clear",
}

XML_TAG_PATTERNS = [
    (re.compile(r"<local-command-caveat>.*?</local-command-caveat>", re.DOTALL), ""),
    (re.compile(r"<command-name>.*?</command-name>", re.DOTALL), ""),
    (re.compile(r"<command-message>.*?</command-message>", re.DOTALL), ""),
    (re.compile(r"<command-args>.*?</command-args>", re.DOTALL), ""),
    (re.compile(r"<local-command-stdout>.*?</local-command-stdout>", re.DOTALL), ""),
]


# ---------------------------------------------------------------------------
# conversation.db schema
# ---------------------------------------------------------------------------

CONV_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    model TEXT,
    container_name TEXT,
    started_at TEXT,
    ended_at TEXT,
    turn_count INTEGER DEFAULT 0,
    system_prompt TEXT,
    system_prompt_summary TEXT,
    parent_conversation_id TEXT,
    last_turn_has_response INTEGER DEFAULT 0,
    metadata_json TEXT,
    linked_subagents_json TEXT,
    request_ids_json TEXT,
    incomplete INTEGER DEFAULT 0,
    incomplete_reason TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS turns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    turn_number INTEGER NOT NULL,
    user_prompt TEXT,
    steps_json TEXT,
    api_calls_in_turn INTEGER DEFAULT 0,
    request_ids_json TEXT,
    timestamp TEXT,
    timestamp_end TEXT,
    duration_ms INTEGER,
    model TEXT,
    UNIQUE(conversation_id, turn_number)
);

CREATE TABLE IF NOT EXISTS processing_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_turns_conv ON turns(conversation_id);
CREATE INDEX IF NOT EXISTS idx_conv_started ON conversations(started_at);
CREATE INDEX IF NOT EXISTS idx_conv_parent ON conversations(parent_conversation_id);
"""


# ---------------------------------------------------------------------------
# BLOB / decompression helpers
# ---------------------------------------------------------------------------

def try_decompress(data):
    """Try gzip decompression. Returns (bytes, was_compressed)."""
    if not data or len(data) < 2:
        return data, False
    if data[0:2] == b'\x1f\x8b':
        try:
            return gzip.decompress(data), True
        except Exception:
            pass
    return data, False


def blob_to_text(data):
    """Convert a BLOB to text, decompressing if needed. Returns None for binary."""
    if data is None:
        return None
    if isinstance(data, str):
        return data
    data, _ = try_decompress(data)
    try:
        return data.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return None


def parse_sse_from_body(body_text):
    """Parse SSE events from a response body string."""
    if not body_text or not body_text.strip().startswith("event:"):
        return []
    events = []
    current_event = {}
    for line in body_text.split("\n"):
        line = line.rstrip("\r")
        if line == "":
            if current_event:
                events.append(current_event)
                current_event = {}
            continue
        if line.startswith("event: "):
            current_event["event"] = line[7:]
        elif line.startswith("data: "):
            current_event["data"] = line[6:]
    if current_event:
        events.append(current_event)
    return events


# ---------------------------------------------------------------------------
# Read from greyproxy.db
# ---------------------------------------------------------------------------

def load_transactions_from_db(greyproxy_db, since_id=0):
    """Load Anthropic API transactions from greyproxy.db.

    Returns (transactions, max_id_seen).
    Each transaction dict mirrors what assemble.py expected from exported JSON.
    """
    conn = sqlite3.connect(f"file:{greyproxy_db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """SELECT id, timestamp, container_name, destination_host, destination_port,
                      method, url, request_headers, request_body, request_body_size,
                      request_content_type, status_code, response_headers, response_body,
                      response_body_size, response_content_type, duration_ms, rule_id, result
               FROM http_transactions
               WHERE id > ?
               ORDER BY id""",
            (since_id,),
        ).fetchall()
    finally:
        conn.close()

    txns = []
    max_id = since_id
    for row in rows:
        max_id = max(max_id, row["id"])
        url = row["url"] or ""
        # Strip query params for matching, but also check exact
        url_base = url.split("?")[0] if "?" in url else url
        if url not in TARGET_URLS and url_base not in {u.split("?")[0] for u in TARGET_URLS}:
            continue

        request_body_text = blob_to_text(row["request_body"])
        response_body_text = blob_to_text(row["response_body"])

        # Parse SSE events from response body if it's event-stream
        response_ct = row["response_content_type"] or ""
        sse_events = []
        if "text/event-stream" in response_ct and response_body_text:
            sse_events = parse_sse_from_body(response_body_text)

        txn = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "container_name": row["container_name"] or "",
            "destination_host": row["destination_host"],
            "destination_port": row["destination_port"],
            "method": row["method"],
            "url": url,
            "request_body": request_body_text or "",
            "response_body": response_body_text or "",
            "response_body_events": sse_events,
            "duration_ms": row["duration_ms"] or 0,
            "status_code": row["status_code"],
        }
        txns.append(txn)

    return txns, max_id


def load_all_transactions_for_sessions(greyproxy_db, session_ids):
    """Load ALL Anthropic transactions for the given session IDs.

    Uses SQL LIKE to pre-filter by session UUID in the request body,
    then verifies in Python. Also includes unassigned transactions
    (no parseable session) that may belong via heuristic grouping.
    """
    conn = sqlite3.connect(f"file:{greyproxy_db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        # Build a query that pre-filters by URL and session_id patterns in request_body.
        # We use LIKE for each session_id to let SQLite skip non-matching rows.
        # Also include rows where no session_id can be found (for heuristic grouping).
        like_clauses = " OR ".join(
            "CAST(request_body AS TEXT) LIKE ?" for _ in session_ids
        )
        params = [f"%session_{sid}%" for sid in session_ids]
        rows = conn.execute(
            f"""SELECT id, timestamp, container_name, destination_host, destination_port,
                      method, url, request_body, response_body,
                      response_content_type, duration_ms, status_code
               FROM http_transactions
               WHERE url LIKE '%api.anthropic.com/v1/messages%'
                 AND ({like_clauses})
               ORDER BY id""",
            params,
        ).fetchall()
    finally:
        conn.close()

    txns = []
    for row in rows:
        url = row["url"] or ""
        request_body_text = blob_to_text(row["request_body"])
        response_body_text = blob_to_text(row["response_body"])

        response_ct = row["response_content_type"] or ""
        sse_events = []
        if "text/event-stream" in response_ct and response_body_text:
            sse_events = parse_sse_from_body(response_body_text)

        txn = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "container_name": row["container_name"] or "",
            "url": url,
            "request_body": request_body_text or "",
            "response_body": response_body_text or "",
            "response_body_events": sse_events,
            "duration_ms": row["duration_ms"] or 0,
            "status_code": row["status_code"],
        }
        txns.append(txn)

    return txns


# ---------------------------------------------------------------------------
# Assembly logic (adapted from assemble.py, reads from txn dicts)
# ---------------------------------------------------------------------------

def parse_request_body_text(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def extract_session_id(body_dict=None, raw_body=""):
    if body_dict:
        uid = body_dict.get("metadata", {}).get("user_id", "")
        m = re.search(r"session_([a-f0-9-]{36})", uid)
        if m:
            return m.group(1)
    if raw_body:
        m = re.search(r"session_([a-f0-9-]{36})", raw_body)
        if m:
            return m.group(1)
    return None


def extract_model(body_dict=None, raw_body=""):
    if body_dict:
        return body_dict.get("model", "unknown")
    if raw_body:
        m = re.search(r'"model":"([^"]+)"', raw_body)
        return m.group(1) if m else "unknown"
    return "unknown"


def extract_response_from_sse(txn):
    events = txn.get("response_body_events", [])
    if not events:
        body = txn.get("response_body", "")
        if isinstance(body, str) and body.startswith("event:"):
            event_type = ""
            for line in body.split("\n"):
                line = line.strip()
                if line.startswith("event: "):
                    event_type = line[7:]
                elif line.startswith("data: "):
                    events.append({"event": event_type, "data": line[6:]})

    if not events:
        return None

    text_parts = []
    tool_calls = []
    thinking_parts = []

    for evt in events:
        event_type = evt.get("event", "")
        data_str = evt.get("data", "")
        try:
            data = json.loads(data_str)
        except (json.JSONDecodeError, TypeError):
            continue

        if event_type == "content_block_delta":
            delta = data.get("delta", {})
            dt = delta.get("type", "")
            if dt == "text_delta":
                text_parts.append(delta.get("text", ""))
            elif dt == "thinking_delta":
                thinking_parts.append(delta.get("thinking", ""))
        elif event_type == "content_block_start":
            cb = data.get("content_block", {})
            if cb.get("type") == "tool_use":
                tool_calls.append({"tool": cb.get("name", "unknown"), "input_preview": ""})

    result = {}
    if text_parts:
        result["text"] = "".join(text_parts)
    if tool_calls:
        result["tool_calls"] = tool_calls
    if thinking_parts:
        result["thinking"] = "".join(thinking_parts)[:500] + "..."
    return result if result else None


def is_real_user_message(msg):
    content = msg.get("content", "")
    if isinstance(content, str):
        if content.startswith("<available-deferred-tools>"):
            return False
        stripped = content.strip()
        if stripped in SCAFFOLDING_TEXTS or not stripped:
            return False
        return True
    if isinstance(content, list):
        has_tool_result = any(
            isinstance(b, dict) and b.get("type") == "tool_result" for b in content
        )
        real_texts = []
        for b in content:
            if not isinstance(b, dict) or b.get("type") != "text":
                continue
            text = b.get("text", "").strip()
            if not text:
                continue
            if text.startswith("<system-reminder>"):
                continue
            if text.startswith("<local-command-caveat>"):
                continue
            if text in SCAFFOLDING_TEXTS:
                continue
            real_texts.append(text)
        if has_tool_result and not real_texts:
            return False
        return len(real_texts) > 0
    return False


def clean_text(text):
    for pattern, replacement in XML_TAG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text.strip()


def get_user_text(msg):
    content = msg.get("content", "")
    if isinstance(content, str):
        if content.startswith("<available-deferred-tools>"):
            return None
        cleaned = clean_text(content)
        return cleaned if cleaned and cleaned not in SCAFFOLDING_TEXTS else None
    if isinstance(content, list):
        texts = []
        for b in content:
            if not isinstance(b, dict) or b.get("type") != "text":
                continue
            text = b.get("text", "").strip()
            if not text or text.startswith("<system-reminder>") or text in SCAFFOLDING_TEXTS:
                continue
            cleaned = clean_text(text)
            if cleaned and cleaned not in SCAFFOLDING_TEXTS:
                texts.append(cleaned)
        return "\n".join(texts) if texts else None
    return None


def get_assistant_summary(content):
    if isinstance(content, str):
        return {"text": content, "tool_calls": []}
    if not isinstance(content, list):
        return {"text": str(content), "tool_calls": []}

    texts, tool_calls, thinking = [], [], []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text":
            texts.append(block["text"])
        elif btype == "tool_use":
            tc = {
                "tool": block.get("name", "unknown"),
                "input_preview": json.dumps(block.get("input", {}), ensure_ascii=False)[:300],
            }
            if block.get("id"):
                tc["tool_use_id"] = block["id"]
            tool_calls.append(tc)
        elif btype == "thinking":
            t = block.get("thinking", "")
            if t:
                thinking.append(t)

    return {
        "text": "\n".join(texts) if texts else None,
        "tool_calls": tool_calls,
        "thinking": thinking[0][:500] + "..." if thinking else None,
    }


def get_tool_results_summary(msg):
    content = msg.get("content", [])
    if not isinstance(content, list):
        return []
    results = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        rc = block.get("content", "")
        if isinstance(rc, str):
            preview = rc[:500]
        elif isinstance(rc, list):
            text_parts = [b.get("text", "") for b in rc if isinstance(b, dict) and b.get("type") == "text"]
            preview = "\n".join(text_parts)[:500]
        else:
            preview = str(rc)[:500]
        results.append({
            "tool_use_id": block.get("tool_use_id", ""),
            "content_preview": preview,
            "is_error": block.get("is_error", False),
        })
    return results


def build_rounds_from_messages(messages):
    prompt_indices = [
        i for i, msg in enumerate(messages)
        if msg.get("role") == "user" and is_real_user_message(msg)
    ]
    if not prompt_indices:
        return []

    rounds = []
    for ri, start_idx in enumerate(prompt_indices):
        end_idx = prompt_indices[ri + 1] if ri + 1 < len(prompt_indices) else len(messages)
        user_text = get_user_text(messages[start_idx])

        steps = []
        api_calls_in_round = 0
        pending_tool_calls = {}

        for j in range(start_idx + 1, end_idx):
            msg = messages[j]
            if msg.get("role") == "assistant":
                api_calls_in_round += 1
                summary = get_assistant_summary(msg.get("content"))
                step = {"type": "assistant"}
                if summary.get("thinking"):
                    step["thinking_preview"] = summary["thinking"]
                if summary["text"]:
                    step["text"] = summary["text"]
                if summary["tool_calls"]:
                    step["tool_calls"] = summary["tool_calls"]
                    for tc in summary["tool_calls"]:
                        if tc.get("tool_use_id"):
                            pending_tool_calls[tc["tool_use_id"]] = tc
                steps.append(step)
            elif msg.get("role") == "user":
                results = get_tool_results_summary(msg)
                for r in results:
                    tid = r.get("tool_use_id", "")
                    if tid in pending_tool_calls:
                        tc = pending_tool_calls[tid]
                        tc["result_preview"] = r.get("content_preview", "")
                        tc["is_error"] = r.get("is_error", False)

        rounds.append({"user_prompt": user_text, "steps": steps, "api_calls": api_calls_in_round})
    return rounds


def compute_system_fingerprint(body):
    if not body:
        return (0, 0, "unknown")
    sys_blocks = body.get("system", [])
    sys_len = sum(len(b.get("text", "")) for b in sys_blocks if isinstance(b, dict))
    tool_count = len(body.get("tools", []))
    if sys_len > 10000:
        return (sys_len, tool_count, "main")
    elif sys_len > 1000:
        return (sys_len, tool_count, "subagent")
    elif sys_len > 100 and tool_count <= 2:
        return (sys_len, tool_count, "mcp")
    else:
        return (sys_len, tool_count, "utility")


def split_session_into_threads(entries):
    threads = defaultdict(list)
    for entry in entries:
        body = entry["body"]
        if body is None:
            threads["main"].append(entry)
            continue
        _, _, thread_type = compute_system_fingerprint(body)
        if thread_type == "main":
            threads["main"].append(entry)
        elif thread_type == "subagent":
            sys_blocks = body.get("system", [])
            sys_len = sum(len(b.get("text", "")) for b in sys_blocks if isinstance(b, dict))
            threads[f"subagent_{sys_len}"].append(entry)
        elif thread_type in ("mcp", "utility"):
            threads[thread_type].append(entry)
        else:
            threads["main"].append(entry)
    return threads


def split_subagent_invocations(entries):
    entries.sort(key=lambda e: (e["timestamp"], e["id"]))
    invocations = []
    current = []
    for entry in entries:
        msg_count = entry["msg_count"]
        if current and msg_count >= 0:
            prev_count = current[-1]["msg_count"] if current[-1]["msg_count"] >= 0 else 999
            if msg_count < prev_count - 1:
                invocations.append(current)
                current = []
        current.append(entry)
    if current:
        invocations.append(current)
    return invocations


def count_real_prompts(messages):
    return sum(1 for msg in messages if msg.get("role") == "user" and is_real_user_message(msg))


def map_requests_to_turns(entries, num_turns):
    entry_turns = {}
    for i, entry in enumerate(entries):
        if entry["body"] is not None:
            prompts = count_real_prompts(entry["body"].get("messages", []))
            entry_turns[i] = prompts

    for i in range(len(entries)):
        if i in entry_turns:
            continue
        prev_turn = 0
        for j in range(i - 1, -1, -1):
            if j in entry_turns:
                prev_turn = entry_turns[j]
                break
        next_turn = num_turns
        for j in range(i + 1, len(entries)):
            if j in entry_turns:
                next_turn = entry_turns[j]
                break
        entry_turns[i] = max(prev_turn, min(next_turn, num_turns))

    turn_entries = defaultdict(list)
    for i, entry in enumerate(entries):
        turn_num = entry_turns.get(i, 0)
        if 1 <= turn_num <= num_turns:
            turn_entries[turn_num].append(entry)
    return turn_entries


def group_by_session(txns):
    """Group transactions into sessions, split into threads."""
    raw_sessions = defaultdict(list)
    unassigned = []

    for txn in txns:
        body = parse_request_body_text(txn.get("request_body", ""))
        session_id = extract_session_id(body, txn.get("request_body", ""))
        model = extract_model(body, txn.get("request_body", ""))

        entry = {
            "txn": txn,
            "body": body,
            "session_id": session_id,
            "model": model,
            "msg_count": len(body["messages"]) if body and "messages" in body else -1,
            "timestamp": txn["timestamp"],
            "id": txn["id"],
        }

        if session_id:
            raw_sessions[session_id].append(entry)
        else:
            unassigned.append(entry)

    # Heuristic grouping for unassigned
    if unassigned:
        unassigned.sort(key=lambda e: e["timestamp"])
        groups, current_group = [], []
        for entry in unassigned:
            if not current_group:
                current_group.append(entry)
                continue
            prev_ts = datetime.fromisoformat(current_group[-1]["timestamp"].replace("Z", "+00:00"))
            curr_ts = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
            if curr_ts - prev_ts > TIME_GAP_THRESHOLD:
                groups.append(current_group)
                current_group = [entry]
            else:
                current_group.append(entry)
        if current_group:
            groups.append(current_group)

        for group in groups:
            group_start = datetime.fromisoformat(group[0]["timestamp"].replace("Z", "+00:00"))
            group_end = datetime.fromisoformat(group[-1]["timestamp"].replace("Z", "+00:00"))
            best_session, best_overlap = None, timedelta(0)
            for sid, sentries in raw_sessions.items():
                s_start = datetime.fromisoformat(sentries[0]["timestamp"].replace("Z", "+00:00"))
                s_end = datetime.fromisoformat(sentries[-1]["timestamp"].replace("Z", "+00:00"))
                overlap_start = max(s_start, group_start)
                overlap_end = min(s_end + TIME_GAP_THRESHOLD, group_end + TIME_GAP_THRESHOLD)
                if overlap_start <= overlap_end:
                    overlap = overlap_end - overlap_start
                    if overlap > best_overlap:
                        best_overlap = overlap
                        best_session = sid
            if best_session:
                raw_sessions[best_session].extend(group)
                raw_sessions[best_session].sort(key=lambda e: (e["timestamp"], e["id"]))
            else:
                fake_sid = f"heuristic_{group[0]['id']}_{group[-1]['id']}"
                raw_sessions[fake_sid] = group

    # Split each session into threads
    sessions = {}
    for sid, entries in raw_sessions.items():
        entries.sort(key=lambda e: (e["timestamp"], e["id"]))
        threads = split_session_into_threads(entries)
        for thread_key, thread_entries in threads.items():
            if not thread_entries or thread_key in ("utility", "mcp"):
                continue
            if thread_key == "main":
                sessions[sid] = thread_entries
            else:
                sub_convs = split_subagent_invocations(thread_entries)
                for i, sub_entries in enumerate(sub_convs):
                    sessions[f"{sid}/{thread_key}_{i+1}"] = sub_entries

    return sessions


def assemble_conversation(session_id, entries):
    entries.sort(key=lambda e: (e["timestamp"], e["id"]))

    best_entry = None
    for entry in reversed(entries):
        if entry["body"] is not None:
            best_entry = entry
            break

    if best_entry is None:
        return {
            "conversation_id": f"session_{session_id}",
            "model": entries[0]["model"],
            "container_name": entries[0]["txn"]["container_name"],
            "request_ids": [e["id"] for e in entries],
            "started_at": entries[0]["timestamp"],
            "ended_at": entries[-1]["timestamp"],
            "turn_count": 0,
            "turns": [],
            "incomplete": True,
            "incomplete_reason": "All request bodies truncated; cannot parse messages",
            "metadata": {
                "total_requests": len(entries),
                "truncated_requests": len(entries),
                "parseable_requests": 0,
            },
        }

    body = best_entry["body"]
    messages = body.get("messages", [])
    rounds = build_rounds_from_messages(messages)
    num_turns = len(rounds)

    conversation_entries = [
        e for e in entries
        if not (e["body"] and len(e["body"].get("messages", [])) == 1
                and e["model"] != body.get("model"))
    ]

    turn_entry_map = map_requests_to_turns(conversation_entries, num_turns)

    turn_details = []
    for i, rnd in enumerate(rounds):
        turn_num = i + 1
        turn_reqs = turn_entry_map.get(turn_num, [])
        detail = {
            "turn_number": turn_num,
            "user_prompt": rnd["user_prompt"],
            "steps": rnd["steps"],
            "api_calls_in_turn": rnd["api_calls"],
            "request_ids": [e["id"] for e in turn_reqs],
        }
        if turn_reqs:
            detail["timestamp"] = turn_reqs[0]["timestamp"]
            detail["timestamp_end"] = turn_reqs[-1]["timestamp"]
            detail["duration_ms"] = sum(e["txn"]["duration_ms"] for e in turn_reqs)
            detail["model"] = turn_reqs[0]["model"]
        elif i < len(conversation_entries):
            e = conversation_entries[i]
            detail["timestamp"] = e["timestamp"]
            detail["duration_ms"] = e["txn"]["duration_ms"]
            detail["model"] = e["model"]
        turn_details.append(detail)

    # System prompt
    system_blocks = body.get("system", [])
    system_prompt_parts = [
        b.get("text", "") for b in system_blocks
        if isinstance(b, dict) and b.get("type") == "text" and b.get("text")
    ]
    system_prompt = "\n\n---\n\n".join(system_prompt_parts) if system_prompt_parts else None
    system_summary = None
    if system_prompt and len(system_prompt) > 100:
        system_summary = system_prompt[:500] + ("..." if len(system_prompt) > 500 else "")

    # Recover last assistant response from SSE
    if turn_details:
        last_turn = turn_details[-1]
        last_steps = last_turn.get("steps", [])
        existing_texts = {
            s.get("text", "")[:200]
            for s in last_steps
            if s.get("type") == "assistant" and s.get("text")
        }
        for entry in reversed(entries):
            sse_response = extract_response_from_sse(entry["txn"])
            if not sse_response:
                continue
            sse_text = sse_response.get("text", "")
            if sse_text and sse_text[:200] in existing_texts:
                continue
            step = {"type": "assistant"}
            if sse_response.get("thinking"):
                step["thinking_preview"] = sse_response["thinking"]
            if sse_text:
                step["text"] = sse_text
            if sse_response.get("tool_calls"):
                step["tool_calls"] = sse_response["tool_calls"]
            last_steps.append(step)
            break

    last_turn_has_response = False
    if turn_details:
        last_turn_has_response = any(
            s.get("type") == "assistant" and s.get("text")
            for s in turn_details[-1].get("steps", [])
        )

    return {
        "conversation_id": f"session_{session_id}",
        "model": best_entry["model"],
        "container_name": entries[0]["txn"]["container_name"],
        "request_ids": [e["id"] for e in entries],
        "started_at": entries[0]["timestamp"],
        "ended_at": entries[-1]["timestamp"],
        "turn_count": len(turn_details),
        "system_prompt_summary": system_summary,
        "system_prompt": system_prompt,
        "turns": turn_details,
        "last_turn_has_response": last_turn_has_response,
        "metadata": {
            "total_requests": len(entries),
            "truncated_requests": sum(1 for e in entries if e["body"] is None),
            "parseable_requests": sum(1 for e in entries if e["body"] is not None),
            "messages_in_best_request": len(messages),
            "best_request_id": best_entry["id"],
        },
    }


def link_subagent_conversations(all_conversations):
    subagent_convs = {}
    for conv in all_conversations:
        cid = conv.get("conversation_id", "")
        if "/" in cid:
            base_session = cid.split("/")[0]
            subagent_convs.setdefault(base_session, []).append(conv)

    for conv in all_conversations:
        cid = conv.get("conversation_id", "")
        if "/" in cid:
            continue
        subs = subagent_convs.get(cid, [])
        if not subs:
            continue

        conv["linked_subagents"] = [
            {
                "conversation_id": s["conversation_id"],
                "turn_count": s["turn_count"],
                "started_at": s["started_at"],
                "ended_at": s["ended_at"],
                "first_prompt": (s["turns"][0]["user_prompt"] or "")[:200] if s["turns"] else "",
            }
            for s in subs
        ]

        for turn in conv.get("turns", []):
            for step in turn.get("steps", []):
                if step.get("type") != "assistant":
                    continue
                for tc in step.get("tool_calls", []):
                    if tc.get("tool") != "Agent":
                        continue
                    turn_start = turn.get("timestamp", "")
                    turn_end = turn.get("timestamp_end", turn_start)
                    best_match = None
                    for s in subs:
                        if not s.get("started_at"):
                            continue
                        if turn_start <= s["started_at"] <= (turn_end or "9999"):
                            best_match = s
                            break
                    if best_match:
                        tc["linked_conversation_id"] = best_match["conversation_id"]
                        subs = [s for s in subs if s is not best_match]


# ---------------------------------------------------------------------------
# conversation.db operations
# ---------------------------------------------------------------------------

def init_conv_db(conv_db_path):
    conn = sqlite3.connect(conv_db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(CONV_DB_SCHEMA)
    conn.commit()
    return conn


def get_last_processed_id(conn):
    row = conn.execute(
        "SELECT value FROM processing_state WHERE key = 'last_processed_id'"
    ).fetchone()
    return int(row[0]) if row else 0


def set_last_processed_id(conn, txn_id):
    conn.execute(
        "INSERT OR REPLACE INTO processing_state (key, value) VALUES ('last_processed_id', ?)",
        (str(txn_id),),
    )
    conn.commit()


def upsert_conversation(conn, conv):
    """Insert or replace a conversation and its turns."""
    cid = conv["conversation_id"]

    # Determine parent
    parent_id = None
    if "/" in cid:
        parent_id = cid.split("/")[0]

    conn.execute(
        """INSERT OR REPLACE INTO conversations
           (id, model, container_name, started_at, ended_at, turn_count,
            system_prompt, system_prompt_summary, parent_conversation_id,
            last_turn_has_response, metadata_json, linked_subagents_json,
            request_ids_json, incomplete, incomplete_reason, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
        (
            cid,
            conv.get("model"),
            conv.get("container_name"),
            conv.get("started_at"),
            conv.get("ended_at"),
            conv.get("turn_count", 0),
            conv.get("system_prompt"),
            conv.get("system_prompt_summary"),
            parent_id,
            1 if conv.get("last_turn_has_response") else 0,
            json.dumps(conv.get("metadata"), ensure_ascii=False) if conv.get("metadata") else None,
            json.dumps(conv.get("linked_subagents"), ensure_ascii=False) if conv.get("linked_subagents") else None,
            json.dumps(conv.get("request_ids"), ensure_ascii=False) if conv.get("request_ids") else None,
            1 if conv.get("incomplete") else 0,
            conv.get("incomplete_reason"),
        ),
    )

    # Delete old turns for this conversation, then re-insert
    conn.execute("DELETE FROM turns WHERE conversation_id = ?", (cid,))
    for turn in conv.get("turns", []):
        conn.execute(
            """INSERT INTO turns
               (conversation_id, turn_number, user_prompt, steps_json,
                api_calls_in_turn, request_ids_json, timestamp, timestamp_end,
                duration_ms, model)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cid,
                turn.get("turn_number"),
                turn.get("user_prompt"),
                json.dumps(turn.get("steps"), ensure_ascii=False) if turn.get("steps") else None,
                turn.get("api_calls_in_turn", 0),
                json.dumps(turn.get("request_ids"), ensure_ascii=False) if turn.get("request_ids") else None,
                turn.get("timestamp"),
                turn.get("timestamp_end"),
                turn.get("duration_ms"),
                turn.get("model"),
            ),
        )

    conn.commit()


# ---------------------------------------------------------------------------
# Assembly orchestrator
# ---------------------------------------------------------------------------

def run_assembly(greyproxy_db, conv_db_path, full=False):
    """Run incremental (or full) assembly.

    Returns the number of conversations updated.
    """
    conv_conn = init_conv_db(conv_db_path)

    if full:
        last_id = 0
    else:
        last_id = get_last_processed_id(conv_conn)

    # Load new transactions from greyproxy.db
    new_txns, max_id = load_transactions_from_db(greyproxy_db, since_id=last_id)

    if not new_txns and not full:
        conv_conn.close()
        return 0

    # Find session IDs affected by new transactions
    affected_sessions = set()
    for txn in new_txns:
        body = parse_request_body_text(txn.get("request_body", ""))
        sid = extract_session_id(body, txn.get("request_body", ""))
        if sid:
            affected_sessions.add(sid)

    if not affected_sessions and not full:
        # New transactions exist but none matched Anthropic API or had parseable sessions.
        # Still update the watermark so we don't re-scan them.
        set_last_processed_id(conv_conn, max_id)
        conv_conn.close()
        return 0

    # For affected sessions, load ALL their transactions from greyproxy.db
    if full:
        all_txns, max_id_full = load_transactions_from_db(greyproxy_db, since_id=0)
        if max_id_full > max_id:
            max_id = max_id_full
    else:
        all_txns = load_all_transactions_for_sessions(greyproxy_db, affected_sessions)
        # Also include any transactions we already had
        # (load_all_transactions_for_sessions returns all matching txns)

    print(f"  {len(all_txns)} Anthropic API transactions for {len(affected_sessions) if not full else 'all'} sessions")

    # Group and assemble
    sessions = group_by_session(all_txns)
    all_conversations = []
    for session_id, entries in sorted(sessions.items(), key=lambda x: x[1][0]["timestamp"]):
        conv = assemble_conversation(session_id, entries)
        all_conversations.append(conv)

    link_subagent_conversations(all_conversations)

    # Upsert into conversation.db
    for conv in all_conversations:
        upsert_conversation(conv_conn, conv)

    set_last_processed_id(conv_conn, max_id)

    print(f"  {len(all_conversations)} conversations assembled/updated")
    for conv in all_conversations:
        cid = conv["conversation_id"]
        short_id = cid[:40] + "..." if len(cid) > 40 else cid
        print(f"    {short_id}: {conv['turn_count']} turns, {conv['metadata']['total_requests']} requests")

    conv_conn.close()
    return len(all_conversations)


# ---------------------------------------------------------------------------
# API Server
# ---------------------------------------------------------------------------

class ConversationAPI:
    """Wraps conversation.db access for the API server."""

    def __init__(self, conv_db_path):
        self.db_path = conv_db_path

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def list_conversations(self):
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT id, model, container_name, started_at, ended_at,
                          turn_count, system_prompt_summary, parent_conversation_id,
                          last_turn_has_response, linked_subagents_json,
                          request_ids_json, incomplete, metadata_json
                   FROM conversations
           WHERE parent_conversation_id IS NULL
           ORDER BY ended_at DESC"""
            ).fetchall()
            result = []
            for r in rows:
                conv = {
                    "conversation_id": r["id"],
                    "model": r["model"],
                    "container_name": r["container_name"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "turn_count": r["turn_count"],
                    "system_prompt_summary": r["system_prompt_summary"],
                    "parent_conversation_id": r["parent_conversation_id"],
                    "last_turn_has_response": bool(r["last_turn_has_response"]),
                    "incomplete": bool(r["incomplete"]),
                }
                if r["linked_subagents_json"]:
                    conv["linked_subagents"] = json.loads(r["linked_subagents_json"])
                if r["metadata_json"]:
                    conv["metadata"] = json.loads(r["metadata_json"])
                # Get first turn's user_prompt for sidebar preview
                first_turn = conn.execute(
                    "SELECT user_prompt FROM turns WHERE conversation_id = ? AND turn_number = 1",
                    (r["id"],),
                ).fetchone()
                if first_turn:
                    conv["first_prompt"] = first_turn["user_prompt"]
                result.append(conv)
            return result
        finally:
            conn.close()

    def list_subagents(self, parent_id):
        conn = self._conn()
        try:
            rows = conn.execute(
                """SELECT id, model, container_name, started_at, ended_at,
                          turn_count, metadata_json
                   FROM conversations
                   WHERE parent_conversation_id = ?
                   ORDER BY started_at""",
                (parent_id,),
            ).fetchall()
            result = []
            for r in rows:
                sub = {
                    "conversation_id": r["id"],
                    "model": r["model"],
                    "container_name": r["container_name"],
                    "started_at": r["started_at"],
                    "ended_at": r["ended_at"],
                    "turn_count": r["turn_count"],
                }
                if r["metadata_json"]:
                    sub["metadata"] = json.loads(r["metadata_json"])
                first_turn = conn.execute(
                    "SELECT user_prompt FROM turns WHERE conversation_id = ? AND turn_number = 1",
                    (r["id"],),
                ).fetchone()
                if first_turn:
                    sub["first_prompt"] = first_turn["user_prompt"]
                result.append(sub)
            return result
        finally:
            conn.close()

    def get_conversation(self, conv_id):
        conn = self._conn()
        try:
            row = conn.execute(
                """SELECT id, model, container_name, started_at, ended_at,
                          turn_count, system_prompt, system_prompt_summary,
                          parent_conversation_id, last_turn_has_response,
                          linked_subagents_json, request_ids_json, incomplete,
                          incomplete_reason, metadata_json
                   FROM conversations WHERE id = ?""",
                (conv_id,),
            ).fetchone()
            if not row:
                return None

            conv = {
                "conversation_id": row["id"],
                "model": row["model"],
                "container_name": row["container_name"],
                "started_at": row["started_at"],
                "ended_at": row["ended_at"],
                "turn_count": row["turn_count"],
                "system_prompt": row["system_prompt"],
                "system_prompt_summary": row["system_prompt_summary"],
                "last_turn_has_response": bool(row["last_turn_has_response"]),
                "incomplete": bool(row["incomplete"]),
            }
            if row["request_ids_json"]:
                conv["request_ids"] = json.loads(row["request_ids_json"])
            if row["linked_subagents_json"]:
                conv["linked_subagents"] = json.loads(row["linked_subagents_json"])
            if row["metadata_json"]:
                conv["metadata"] = json.loads(row["metadata_json"])
            if row["incomplete_reason"]:
                conv["incomplete_reason"] = row["incomplete_reason"]

            # Load turns
            turns = conn.execute(
                """SELECT turn_number, user_prompt, steps_json, api_calls_in_turn,
                          request_ids_json, timestamp, timestamp_end, duration_ms, model
                   FROM turns WHERE conversation_id = ? ORDER BY turn_number""",
                (conv_id,),
            ).fetchall()
            conv["turns"] = []
            for t in turns:
                turn = {
                    "turn_number": t["turn_number"],
                    "user_prompt": t["user_prompt"],
                    "api_calls_in_turn": t["api_calls_in_turn"],
                    "timestamp": t["timestamp"],
                    "timestamp_end": t["timestamp_end"],
                    "duration_ms": t["duration_ms"],
                    "model": t["model"],
                }
                if t["steps_json"]:
                    turn["steps"] = json.loads(t["steps_json"])
                if t["request_ids_json"]:
                    turn["request_ids"] = json.loads(t["request_ids_json"])
                conv["turns"].append(turn)

            return conv
        finally:
            conn.close()


def make_handler(api, viewer_path):
    """Create an HTTP request handler class with access to the API and viewer."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Quieter logging
            pass

        def _send_json(self, data, status=200):
            body = json.dumps(data, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def _send_html(self, html):
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"

            if path == "/":
                if os.path.exists(viewer_path):
                    with open(viewer_path) as f:
                        self._send_html(f.read())
                else:
                    self._send_html("<h1>Viewer not found</h1>")
                return

            if path == "/api/conversations":
                convs = api.list_conversations()
                self._send_json(convs)
                return

            # /api/subagents/{parent_id}
            if path.startswith("/api/subagents/"):
                parent_id = unquote(path[len("/api/subagents/"):])
                subs = api.list_subagents(parent_id)
                self._send_json(subs)
                return

            # /api/conversations/{id} -- id may contain slashes (subagent IDs)
            if path.startswith("/api/conversations/"):
                conv_id = unquote(path[len("/api/conversations/"):])
                conv = api.get_conversation(conv_id)
                if conv:
                    self._send_json(conv)
                else:
                    self._send_json({"error": "not found"}, 404)
                return

            self.send_error(404)

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

    return Handler


def serve(conv_db_path, port, viewer_path):
    api = ConversationAPI(conv_db_path)
    handler_class = make_handler(api, viewer_path)
    server = HTTPServer(("0.0.0.0", port), handler_class)
    print(f"Serving on http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


def watch_loop(greyproxy_db, conv_db_path, interval):
    """Background loop that periodically re-assembles new transactions."""
    while True:
        time.sleep(interval)
        try:
            updated = run_assembly(greyproxy_db, conv_db_path)
            if updated:
                print(f"[watch] Updated {updated} conversations")
        except Exception as e:
            print(f"[watch] Error: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Incremental conversation assembler + API server")
    parser.add_argument("--greyproxy-db", default="greyproxy.db", help="Path to greyproxy.db")
    parser.add_argument("--conversation-db", default="conversation.db", help="Path to conversation.db")
    parser.add_argument("--full", action="store_true", help="Full re-assembly (ignore watermark)")
    parser.add_argument("--serve", action="store_true", help="Start API server after assembly")
    parser.add_argument("--port", type=int, default=8199, help="API server port")
    parser.add_argument("--watch", action="store_true", help="Periodically check for new transactions")
    parser.add_argument("--interval", type=int, default=10, help="Watch interval in seconds")
    args = parser.parse_args()

    viewer_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "viewer2.html")

    if not os.path.exists(args.greyproxy_db):
        print(f"Error: {args.greyproxy_db} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Assembling from {args.greyproxy_db} -> {args.conversation_db}")
    updated = run_assembly(args.greyproxy_db, args.conversation_db, full=args.full)
    print(f"Done. {updated} conversations.")

    if args.serve:
        if args.watch:
            t = threading.Thread(
                target=watch_loop,
                args=(args.greyproxy_db, args.conversation_db, args.interval),
                daemon=True,
            )
            t.start()
            print(f"Watching for new transactions every {args.interval}s")
        serve(args.conversation_db, args.port, viewer_path)


if __name__ == "__main__":
    main()
