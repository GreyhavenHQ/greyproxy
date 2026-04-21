# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""
Fake client -- drives a two-turn Anthropic conversation through greyproxy
and the rtk middleware against the fake LLM server.

Flow:
  req 1 -> user: "What are the project dependencies?"
  resp  <- fake server returns tool_use Bash(`cat package.json`)
  (client fabricates a big fake package.json output)
  req 2 -> messages=[user, assistant(tool_use), user(tool_result=BIG JSON)]
  resp  <- fake server returns "done"

After the run, the client reads /tmp/rtk_test_last_req.json (which the
server just wrote) and compares: what the client sent on req 2 vs what
the server actually saw. If the middleware is wired in, the server's
view of the tool_result should be smaller than the client's original.

Environment:
  PROXY_URL   default http://127.0.0.1:43051 (greyproxy http-proxy service)
  SERVER_URL  default http://127.0.0.1:18123/v1/messages (fake LLM server)
"""

import json
import logging
import os
import sys
import urllib.request

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fake-client")

PROXY_URL = os.environ.get("PROXY_URL", "http://127.0.0.1:43051")
SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:18123/v1/messages")
TRACE_FILE = "/tmp/rtk_test_last_req.json"


def fake_package_json() -> str:
    """A deliberately-noisy package.json so rtk has something to compress.
    Real package.json files contain a lot of repeated structure that rtk's
    json filter collapses."""
    pkg = {
        "name": "rtk-compress-test-fixture",
        "version": "1.2.3",
        "private": True,
        "description": "A fixture package.json for exercising rtk json compression",
        "license": "MIT",
        "author": {"name": "Test Harness", "email": "[email protected]"},
        "repository": {"type": "git", "url": "git+https://example.test/fake.git"},
        "bugs": {"url": "https://example.test/fake/issues"},
        "homepage": "https://example.test/fake#readme",
        "keywords": ["fake", "fixture", "rtk", "compression", "test"],
        "scripts": {
            "build": "vite build",
            "dev": "vite",
            "lint": "eslint . --ext .ts,.tsx,.js,.jsx",
            "lint:fix": "eslint . --ext .ts,.tsx,.js,.jsx --fix",
            "test": "vitest run",
            "test:watch": "vitest",
            "typecheck": "tsc --noEmit",
            "format": "prettier --write .",
            "preview": "vite preview",
        },
        "dependencies": {
            "react": "^18.2.0",
            "react-dom": "^18.2.0",
            "react-router-dom": "^6.21.0",
            "tailwindcss": "^3.4.0",
            "@headlessui/react": "^1.7.17",
            "@heroicons/react": "^2.1.1",
            "zustand": "^4.4.7",
            "axios": "^1.6.5",
            "date-fns": "^3.0.6",
            "clsx": "^2.1.0",
            "zod": "^3.22.4",
        },
        "devDependencies": {
            "@types/react": "^18.2.47",
            "@types/react-dom": "^18.2.18",
            "@typescript-eslint/eslint-plugin": "^6.18.1",
            "@typescript-eslint/parser": "^6.18.1",
            "@vitejs/plugin-react": "^4.2.1",
            "autoprefixer": "^10.4.16",
            "eslint": "^8.56.0",
            "eslint-plugin-react-hooks": "^4.6.0",
            "eslint-plugin-react-refresh": "^0.4.5",
            "postcss": "^8.4.33",
            "prettier": "^3.1.1",
            "prettier-plugin-tailwindcss": "^0.5.11",
            "typescript": "^5.3.3",
            "vite": "^5.0.11",
            "vitest": "^1.1.3",
        },
        "engines": {"node": ">=18.0.0", "npm": ">=9.0.0"},
        "browserslist": ["> 0.2%", "last 2 versions", "not dead", "not op_mini all"],
    }
    return json.dumps(pkg, indent=2)


def post_via_proxy(url: str, body: dict) -> dict:
    """POST JSON to url via greyproxy as HTTP proxy. Returns parsed response."""
    raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": "sk-fake-not-real",
        },
    )
    proxy_handler = urllib.request.ProxyHandler({"http": PROXY_URL, "https": PROXY_URL})
    opener = urllib.request.build_opener(proxy_handler)
    with opener.open(req, timeout=30) as resp:
        return json.loads(resp.read())


def extract_tool_use(resp: dict) -> dict:
    for block in resp.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            return block
    raise RuntimeError(f"no tool_use in assistant response: {resp}")


def main():
    log.info("proxy=%s server=%s", PROXY_URL, SERVER_URL)

    # ---- Turn 1 ----------------------------------------------------------
    user_msg = {"role": "user", "content": "What are the project dependencies?"}
    req1 = {
        "model": "claude-fake-1",
        "max_tokens": 1024,
        "messages": [user_msg],
    }
    log.info("request 1 -> %s", SERVER_URL)
    resp1 = post_via_proxy(SERVER_URL, req1)
    assistant_msg = {"role": "assistant", "content": resp1["content"]}
    tool_use = extract_tool_use(resp1)
    log.info("got tool_use id=%s command=%r", tool_use["id"], tool_use["input"].get("command"))

    # ---- Turn 2 ----------------------------------------------------------
    # Build the fake tool_result: a big JSON blob representing package.json.
    tool_output = fake_package_json()
    sent_tool_result_size = len(tool_output)
    log.info("fabricated tool_result size=%d bytes", sent_tool_result_size)

    tool_result_msg = {
        "role": "user",
        "content": [
            {
                "type": "tool_result",
                "tool_use_id": tool_use["id"],
                "content": tool_output,
            }
        ],
    }
    req2 = {
        "model": "claude-fake-1",
        "max_tokens": 1024,
        "messages": [user_msg, assistant_msg, tool_result_msg],
    }
    sent_body_size = len(json.dumps(req2).encode("utf-8"))
    log.info("request 2 -> %s (body=%d bytes)", SERVER_URL, sent_body_size)
    resp2 = post_via_proxy(SERVER_URL, req2)
    log.info("final response: %r", resp2["content"][0]["text"] if resp2.get("content") else resp2)

    # ---- Compare: what client sent vs what server received --------------
    try:
        with open(TRACE_FILE, "rb") as f:
            received_raw = f.read()
    except OSError as e:
        log.error("could not read trace file %s: %s", TRACE_FILE, e)
        sys.exit(1)

    received_body = json.loads(received_raw)
    received_tool_result_size = 0
    for msg in received_body.get("messages") or []:
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                tc = block.get("content")
                if isinstance(tc, str):
                    received_tool_result_size = len(tc)
                elif isinstance(tc, list):
                    received_tool_result_size = sum(
                        len(b.get("text", "")) for b in tc
                        if isinstance(b, dict) and b.get("type") == "text"
                    )

    print()
    print("=" * 60)
    print("  rtk compression test result")
    print("=" * 60)
    print(f"  tool_result sent by client:   {sent_tool_result_size:>8} bytes")
    print(f"  tool_result seen by server:   {received_tool_result_size:>8} bytes")
    if received_tool_result_size < sent_tool_result_size:
        delta = sent_tool_result_size - received_tool_result_size
        pct = 100 * delta / sent_tool_result_size
        print(f"  delta:                        {delta:>8} bytes ({pct:.1f}% smaller)")
        print()
        print("  PASS: middleware rewrote the tool_result between client and server")
        sys.exit(0)
    elif received_tool_result_size == sent_tool_result_size:
        print()
        print("  NO REWRITE: server saw the same bytes the client sent.")
        print("  Possible causes:")
        print("   - middleware not wired (check: greyproxy serve --middleware ws://.../middleware)")
        print("   - endpoint rule missing (fake server host is not in the LLM registry, llm:true skipped)")
        print("   - rtk not installed on PATH (middleware logs 'rtk=MISSING' at startup)")
        print("   - rtk mode heuristic rejected this payload (only diff/json/log match today)")
        sys.exit(2)
    else:
        print()
        print("  WARN: server received MORE bytes than the client sent. This should")
        print("  not happen with rtk compression; inspect the trace file manually.")
        sys.exit(3)


if __name__ == "__main__":
    main()
