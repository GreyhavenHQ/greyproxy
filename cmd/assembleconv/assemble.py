#!/usr/bin/env python3
"""Assemble HTTP transactions from greyproxy into agent conversations.

Reads exported_logs/http_transactions/*.json, groups Anthropic API calls
by session, and outputs inferred conversations.
"""

import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta


TRANSACTIONS_DIR = "exported_logs/http_transactions"
OUTPUT_DIR = "exported_logs/inferred_conversations"
TARGET_URL = "https://api.anthropic.com/v1/messages?beta=true"
# Also match without query params
TARGET_URL_BASE = "https://api.anthropic.com/v1/messages"

TIME_GAP_THRESHOLD = timedelta(minutes=5)

# Text fragments that indicate scaffolding, not real user input
SCAFFOLDING_TEXTS = {
    "Tool loaded.",
    "[Request interrupted by user]",
    "clear",
}

# Tags to strip from user messages
XML_TAG_PATTERNS = [
    (re.compile(r"<local-command-caveat>.*?</local-command-caveat>", re.DOTALL), ""),
    (re.compile(r"<command-name>.*?</command-name>", re.DOTALL), ""),
    (re.compile(r"<command-message>.*?</command-message>", re.DOTALL), ""),
    (re.compile(r"<command-args>.*?</command-args>", re.DOTALL), ""),
    (re.compile(r"<local-command-stdout>.*?</local-command-stdout>", re.DOTALL), ""),
]


def extract_response_from_sse(txn):
    """Try to extract the assistant response from SSE events in the transaction.

    Works with the new export format that includes response_body_events,
    or with a decompressed response_body that is valid text.
    """
    # New format: response_body_events is a list of {event, data} dicts
    events = txn.get("response_body_events", [])
    if not events:
        # Try parsing response_body as SSE text (if it was decompressed)
        body = txn.get("response_body", "")
        if isinstance(body, str) and body.startswith("event:"):
            for line in body.split("\n"):
                line = line.strip()
                if line.startswith("event: "):
                    event_type = line[7:]
                elif line.startswith("data: "):
                    events.append({"event": event_type, "data": line[6:]})

    if not events:
        return None

    # Reconstruct assistant response from SSE content_block_delta events
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
            delta_type = delta.get("type", "")
            if delta_type == "text_delta":
                text_parts.append(delta.get("text", ""))
            elif delta_type == "thinking_delta":
                thinking_parts.append(delta.get("thinking", ""))
            elif delta_type == "input_json_delta":
                pass  # tool input streaming
        elif event_type == "content_block_start":
            cb = data.get("content_block", {})
            if cb.get("type") == "tool_use":
                tool_calls.append({
                    "tool": cb.get("name", "unknown"),
                    "input_preview": "",
                })

    result = {}
    if text_parts:
        result["text"] = "".join(text_parts)
    if tool_calls:
        result["tool_calls"] = tool_calls
    if thinking_parts:
        result["thinking"] = "".join(thinking_parts)[:500] + "..."
    return result if result else None


def load_transactions():
    txns = []
    for fname in os.listdir(TRANSACTIONS_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(TRANSACTIONS_DIR, fname)
        with open(path) as f:
            txn = json.load(f)
        url = txn.get("url", "")
        if url == TARGET_URL or url == TARGET_URL_BASE:
            txns.append(txn)
    txns.sort(key=lambda t: (t["timestamp"], t["id"]))
    return txns


def parse_request_body(txn):
    try:
        return json.loads(txn["request_body"])
    except (json.JSONDecodeError, KeyError):
        return None


def extract_session_id(body_dict=None, raw_body=""):
    if body_dict:
        uid = body_dict.get("metadata", {}).get("user_id", "")
        m = re.search(r"session_([a-f0-9-]{36})", uid)
        if m:
            return m.group(1)
    m = re.search(r"session_([a-f0-9-]{36})", raw_body)
    if m:
        return m.group(1)
    return None


def extract_model(body_dict=None, raw_body=""):
    if body_dict:
        return body_dict.get("model", "unknown")
    m = re.search(r'"model":"([^"]+)"', raw_body)
    return m.group(1) if m else "unknown"


def is_real_user_message(msg):
    """Check if a user message is a real user prompt (not tool results or scaffolding)."""
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
            isinstance(b, dict) and b.get("type") == "tool_result"
            for b in content
        )
        # Extract non-scaffolding text blocks
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

        # If it's ONLY tool_results (+ optional scaffolding), it's not a real prompt
        if has_tool_result and not real_texts:
            return False
        # If it has real text, it's a real user message
        return len(real_texts) > 0

    return False


def clean_text(text):
    """Remove XML scaffolding tags from text."""
    for pattern, replacement in XML_TAG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text.strip()


def get_user_text(msg):
    """Extract the meaningful user text from a message."""
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
            if not text:
                continue
            if text.startswith("<system-reminder>"):
                continue
            if text in SCAFFOLDING_TEXTS:
                continue
            cleaned = clean_text(text)
            if cleaned and cleaned not in SCAFFOLDING_TEXTS:
                texts.append(cleaned)
        return "\n".join(texts) if texts else None

    return None


def get_assistant_summary(content):
    """Summarize assistant response: text + tool calls."""
    if isinstance(content, str):
        return {"text": content, "tool_calls": []}

    if not isinstance(content, list):
        return {"text": str(content), "tool_calls": []}

    texts = []
    tool_calls = []
    thinking = []

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
    """Extract tool result summaries from a user message containing tool_results."""
    content = msg.get("content", [])
    if not isinstance(content, list):
        return []

    results = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        tool_use_id = block.get("tool_use_id", "")
        rc = block.get("content", "")
        if isinstance(rc, str):
            preview = rc[:500]
        elif isinstance(rc, list):
            text_parts = [b.get("text", "") for b in rc if isinstance(b, dict) and b.get("type") == "text"]
            preview = "\n".join(text_parts)[:500]
        else:
            preview = str(rc)[:500]
        is_error = block.get("is_error", False)
        results.append({
            "tool_use_id": tool_use_id,
            "content_preview": preview,
            "is_error": is_error,
        })
    return results


def build_rounds_from_messages(messages):
    """Build conversation rounds from a full messages array.

    A "round" is one user prompt followed by the agent's full response
    (which may span multiple API calls with tool use in between).

    Each round contains a list of "steps" preserving the back-and-forth:
    - assistant steps (thinking, text, tool_calls)
    - tool_result steps (what tools returned)
    """
    # Find indices of "real" user prompts
    prompt_indices = []
    for i, msg in enumerate(messages):
        if msg.get("role") == "user" and is_real_user_message(msg):
            prompt_indices.append(i)

    if not prompt_indices:
        return []

    rounds = []
    for ri, start_idx in enumerate(prompt_indices):
        # This round spans from start_idx to the next prompt (or end)
        if ri + 1 < len(prompt_indices):
            end_idx = prompt_indices[ri + 1]
        else:
            end_idx = len(messages)

        user_text = get_user_text(messages[start_idx])

        # Build step-by-step flow within this round
        steps = []
        api_calls_in_round = 0
        # Track tool_use_id -> tool_call dict for attaching results
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
                # Attach tool results to their corresponding tool_calls
                content = msg.get("content", [])
                if isinstance(content, list):
                    results = get_tool_results_summary(msg)
                    for r in results:
                        tid = r.get("tool_use_id", "")
                        if tid in pending_tool_calls:
                            tc = pending_tool_calls[tid]
                            tc["result_preview"] = r.get("content_preview", "")
                            tc["is_error"] = r.get("is_error", False)
                            if "tool" not in r:
                                r["tool"] = tc.get("tool", "unknown")

        rounds.append({
            "user_prompt": user_text,
            "steps": steps,
            "api_calls": api_calls_in_round,
        })

    return rounds


def compute_system_fingerprint(body):
    """Compute a fingerprint for the system prompt to distinguish conversation threads.

    Returns (sys_length, tool_count, thread_type) where thread_type is:
    - "main": the primary agent conversation (longest system prompt)
    - "subagent": a subagent with medium system prompt
    - "mcp": an MCP tool call (very short system prompt, 1 tool)
    - "utility": quota check or classification (no/minimal system prompt)
    """
    if not body:
        return (0, 0, "unknown")
    sys_blocks = body.get("system", [])
    sys_len = sum(len(b.get("text", "")) for b in sys_blocks if isinstance(b, dict))
    tools = body.get("tools", [])
    tool_count = len(tools)

    if sys_len > 10000:
        return (sys_len, tool_count, "main")
    elif sys_len > 1000:
        return (sys_len, tool_count, "subagent")
    elif sys_len > 100 and tool_count <= 2:
        return (sys_len, tool_count, "mcp")
    else:
        return (sys_len, tool_count, "utility")


def split_session_into_threads(entries):
    """Split a session's entries into separate conversation threads.

    Within a single session, the main agent and its subagents all share the
    same session_id but have different system prompts. We group by system
    prompt length to separate them.

    Returns dict of thread_key -> list of entries.
    """
    threads = defaultdict(list)
    for entry in entries:
        body = entry["body"]
        sys_len, tool_count, thread_type = compute_system_fingerprint(body)

        if body is None:
            # Truncated request: assign to main thread (best guess)
            threads["main"].append(entry)
        elif thread_type == "main":
            threads["main"].append(entry)
        elif thread_type == "subagent":
            # Further split subagents by their system prompt length
            # (different subagent types have different prompt sizes)
            key = f"subagent_{sys_len}"
            threads[key].append(entry)
        elif thread_type == "mcp":
            threads["mcp"].append(entry)
        elif thread_type == "utility":
            threads["utility"].append(entry)
        else:
            threads["main"].append(entry)

    return threads


def group_by_session(txns):
    raw_sessions = defaultdict(list)
    unassigned = []

    for txn in txns:
        body = parse_request_body(txn)
        session_id = extract_session_id(body, txn.get("request_body", ""))
        model = extract_model(body, txn.get("request_body", ""))

        entry = {
            "txn": txn,
            "body": body,
            "session_id": session_id,
            "model": model,
            "msg_count": len(body["messages"]) if body else -1,
            "timestamp": txn["timestamp"],
            "id": txn["id"],
        }

        if session_id:
            raw_sessions[session_id].append(entry)
        else:
            unassigned.append(entry)

    # Heuristic grouping for unassigned (truncated) transactions
    if unassigned:
        unassigned.sort(key=lambda e: e["timestamp"])
        current_group = []
        groups = []

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

            best_session = None
            best_overlap = timedelta(0)

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

    # Now split each session into threads (main vs subagents)
    sessions = {}
    for sid, entries in raw_sessions.items():
        entries.sort(key=lambda e: (e["timestamp"], e["id"]))
        threads = split_session_into_threads(entries)

        for thread_key, thread_entries in threads.items():
            if not thread_entries:
                continue
            # Skip utility/mcp threads (not real conversations)
            if thread_key in ("utility", "mcp"):
                continue
            if thread_key == "main":
                sessions[sid] = thread_entries
            else:
                # Subagent threads: further split if message counts
                # don't grow monotonically (multiple subagent invocations)
                sub_convs = split_subagent_invocations(thread_entries)
                for i, sub_entries in enumerate(sub_convs):
                    sub_sid = f"{sid}/{thread_key}_{i+1}"
                    sessions[sub_sid] = sub_entries

    return sessions


def split_subagent_invocations(entries):
    """Split a subagent thread into separate invocations.

    A single subagent thread type (same sys_len) may have multiple
    invocations. Each invocation starts with a low message count.
    """
    entries.sort(key=lambda e: (e["timestamp"], e["id"]))
    invocations = []
    current = []

    for entry in entries:
        msg_count = entry["msg_count"]
        if current and msg_count >= 0:
            prev_count = current[-1]["msg_count"] if current[-1]["msg_count"] >= 0 else 999
            # If message count dropped, it's a new invocation
            if msg_count < prev_count - 1:
                invocations.append(current)
                current = []
        current.append(entry)

    if current:
        invocations.append(current)

    return invocations


def count_real_prompts(messages):
    """Count the number of real user prompts in a messages array."""
    count = 0
    for msg in messages:
        if msg.get("role") == "user" and is_real_user_message(msg):
            count += 1
    return count


def map_requests_to_turns(entries, num_turns):
    """Map each entry to a turn number based on real_prompt count.

    For parseable entries, count real prompts to determine the turn.
    For truncated entries, interpolate based on position between
    known turn boundaries.
    """
    # First pass: assign turn numbers to parseable entries
    entry_turns = {}  # entry index -> turn number
    last_known_turn = 0
    last_known_idx = -1

    for i, entry in enumerate(entries):
        if entry["body"] is not None:
            prompts = count_real_prompts(entry["body"].get("messages", []))
            entry_turns[i] = prompts
            last_known_turn = prompts
            last_known_idx = i

    # Second pass: assign truncated entries to turns
    # Strategy: a truncated entry gets the same turn as the nearest
    # parseable entry before it, or the nearest after it
    for i, entry in enumerate(entries):
        if i in entry_turns:
            continue
        # Find nearest known turn before this entry
        prev_turn = 0
        for j in range(i - 1, -1, -1):
            if j in entry_turns:
                prev_turn = entry_turns[j]
                break
        # Find nearest known turn after this entry
        next_turn = num_turns
        for j in range(i + 1, len(entries)):
            if j in entry_turns:
                next_turn = entry_turns[j]
                break
        # Use the higher of the two (since turns only increase)
        entry_turns[i] = max(prev_turn, min(next_turn, num_turns))

    # Group entries by turn number
    turn_entries = defaultdict(list)
    for i, entry in enumerate(entries):
        turn_num = entry_turns.get(i, 0)
        if 1 <= turn_num <= num_turns:
            turn_entries[turn_num].append(entry)

    return turn_entries


def assemble_conversation(session_id, entries):
    entries.sort(key=lambda e: (e["timestamp"], e["id"]))

    # Find the entry with the most complete message history
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
                "truncated_requests": sum(1 for e in entries if e["body"] is None),
                "parseable_requests": 0,
            },
        }

    body = best_entry["body"]
    messages = body.get("messages", [])
    rounds = build_rounds_from_messages(messages)
    num_turns = len(rounds)

    # Filter out non-conversation requests (e.g., haiku "quota" checks)
    conversation_entries = [
        e for e in entries
        if not (e["body"] and len(e["body"].get("messages", [])) == 1
                and e["model"] != body.get("model"))
    ]

    # Map requests to turns using real prompt count
    turn_entry_map = map_requests_to_turns(conversation_entries, num_turns)

    turn_details = []
    for i, rnd in enumerate(rounds):
        turn_num = i + 1
        turn_reqs = turn_entry_map.get(turn_num, [])
        req_ids = [e["id"] for e in turn_reqs]

        detail = {
            "turn_number": turn_num,
            "user_prompt": rnd["user_prompt"],
            "steps": rnd["steps"],
            "api_calls_in_turn": rnd["api_calls"],
            "request_ids": req_ids,
        }

        # Use the first request in this turn for timestamp/metadata
        if turn_reqs:
            first = turn_reqs[0]
            last = turn_reqs[-1]
            detail["timestamp"] = first["timestamp"]
            detail["timestamp_end"] = last["timestamp"]
            detail["duration_ms"] = sum(e["txn"]["duration_ms"] for e in turn_reqs)
            detail["model"] = first["model"]
        elif i < len(conversation_entries):
            e = conversation_entries[i]
            detail["timestamp"] = e["timestamp"]
            detail["duration_ms"] = e["txn"]["duration_ms"]
            detail["model"] = e["model"]

        turn_details.append(detail)

    # Extract system prompt (full + summary)
    system_blocks = body.get("system", [])
    system_prompt_parts = []
    for block in system_blocks:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text", "")
            if text:
                system_prompt_parts.append(text)
    system_prompt = "\n\n---\n\n".join(system_prompt_parts) if system_prompt_parts else None
    system_summary = None
    if system_prompt and len(system_prompt) > 100:
        system_summary = system_prompt[:500] + "..." if len(system_prompt) > 500 else system_prompt

    # Recover assistant responses from SSE for each request that isn't
    # followed by another request (whose messages would contain the response).
    # The last request's SSE is always needed. For earlier requests, the
    # response is already in the next request's messages array.
    if turn_details:
        last_turn = turn_details[-1]
        last_steps = last_turn.get("steps", [])

        # Try every request's SSE from newest to oldest, but skip if
        # the text already appears in an existing step (dedup).
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
            # Check if this response is already in the steps (dedup)
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
            break  # Only recover the very last response

    last_turn_has_response = False
    if turn_details:
        last_steps = turn_details[-1].get("steps", [])
        last_turn_has_response = any(
            s.get("type") == "assistant" and s.get("text")
            for s in last_steps
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
    """Link subagent conversations to their parent Agent tool calls.

    For each main conversation's Agent tool calls, try to find the
    corresponding subagent conversation by matching session_id and time range.
    """
    # Index subagent conversations by their base session_id
    subagent_convs = {}
    for conv in all_conversations:
        cid = conv.get("conversation_id", "")
        # Subagent conv IDs look like: session_UUID/subagent_XXXX_N
        if "/" in cid:
            base_session = cid.split("/")[0]  # e.g. "session_UUID"
            if base_session not in subagent_convs:
                subagent_convs[base_session] = []
            subagent_convs[base_session].append(conv)

    # For each main conversation, find Agent tool calls and link them
    for conv in all_conversations:
        cid = conv.get("conversation_id", "")
        if "/" in cid:
            continue  # Skip subagent conversations themselves

        subs = subagent_convs.get(cid, [])
        if not subs:
            continue

        # Add linked_subagents to the conversation
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

        # Try to match Agent tool calls in steps to specific subagent conversations
        for turn in conv.get("turns", []):
            for step in turn.get("steps", []):
                if step.get("type") != "assistant":
                    continue
                for tc in step.get("tool_calls", []):
                    if tc.get("tool") != "Agent":
                        continue
                    # Match by time: find the subagent that started closest
                    # to this turn's time range
                    turn_start = turn.get("timestamp", "")
                    turn_end = turn.get("timestamp_end", turn_start)
                    best_match = None
                    best_dist = float("inf")
                    for s in subs:
                        if not s.get("started_at"):
                            continue
                        s_start = s["started_at"]
                        # Subagent should start after the turn starts
                        if turn_start <= s_start <= (turn_end or "9999"):
                            dist = abs(ord(s_start[0]) - ord(turn_start[0]))  # rough
                            if dist < best_dist:
                                best_dist = dist
                                best_match = s
                    if best_match:
                        tc["linked_conversation_id"] = best_match["conversation_id"]
                        # Remove from pool so each subagent links once
                        subs = [s for s in subs if s is not best_match]


def main():
    print(f"Loading transactions from {TRANSACTIONS_DIR}...")
    txns = load_transactions()
    print(f"  Found {len(txns)} Anthropic /v1/messages requests")

    print("Grouping by session...")
    sessions = group_by_session(txns)
    print(f"  Found {len(sessions)} sessions")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_conversations = []
    session_items = sorted(sessions.items(), key=lambda x: x[1][0]["timestamp"])

    for i, (session_id, entries) in enumerate(session_items):
        print(f"\n--- Session: {session_id[:40]}... ---")
        print(f"  Requests: {len(entries)} (IDs: {[e['id'] for e in entries]})")
        parseable = sum(1 for e in entries if e["body"] is not None)
        print(f"  Parseable: {parseable}/{len(entries)}")

        conv = assemble_conversation(session_id, entries)
        all_conversations.append(conv)
        print(f"  Turns: {conv['turn_count']}")
        print(f"  Time: {conv['started_at']} -> {conv['ended_at']}")
        print(f"  Last turn has response: {conv.get('last_turn_has_response', 'N/A')}")

    # Link subagent conversations to parent Agent tool calls
    link_subagent_conversations(all_conversations)

    # Write all conversations
    for i, conv in enumerate(all_conversations):
        out_path = os.path.join(OUTPUT_DIR, f"conversation_{i+1:04d}.json")
        with open(out_path, "w") as f:
            json.dump(conv, f, indent=2, ensure_ascii=False)
        print(f"  Written: {out_path} ({conv['conversation_id'][:40]}...)")

        for t in conv["turns"]:
            user_p = (t.get("user_prompt") or "")[:100]
            steps = t.get("steps", [])
            asst_steps = [s for s in steps if s.get("type") == "assistant"]
            total_tools = sum(len(s.get("tool_calls", [])) for s in asst_steps)
            with_results = sum(
                1 for s in asst_steps
                for tc in s.get("tool_calls", [])
                if "result_preview" in tc
            )
            print(f"    Turn {t['turn_number']}: user={user_p!r}")
            print(f"           {len(steps)} steps, {total_tools} tool calls ({with_results} with results)")

    print(f"\nDone. {len(all_conversations)} conversations written to {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
