# /// script
# requires-python = ">=3.10"
# dependencies = ["websockets>=12.0"]
# ///
"""
Secret scanner -- blocks outbound requests that contain accidentally leaked
secrets such as API keys, AWS credentials, private keys, or passwords.

Reference implementation of a policy middleware using the shared helper.
Run either as a stdio child (preferred for local policy gates) or as a
standalone WebSocket server (for shared deployments).

WARNING: Example only, not production-ready. Patterns here cover common
formats but miss encoded/split/obfuscated credentials. Use a dedicated
tool (trufflehog, detect-secrets, gitleaks) in production.
"""
import logging
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "_lib"))
from greyproxy_middleware import allow, decode_body, deny, run  # noqa: E402

log = logging.getLogger(__name__)

# Each tuple: (compiled regex, label)
SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}"), "AWS Secret Key"),
    (re.compile(r"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{20,}"),
     "Generic API Key/Token"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI-style API Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub PAT"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{22,}"), "GitHub Fine-grained PAT"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "PEM Private Key"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack Token"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Stripe Secret Key"),
    (re.compile(r'(?i)"password"\s*:\s*"[^"]{8,}"'), "Password in JSON"),
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer Token"),
]

SKIP_HOSTS = {
    "login.microsoftonline.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
}


def scan_for_secrets(text: str) -> list[str]:
    return [label for pattern, label in SECRET_PATTERNS if pattern.search(text)]


def handle_request(msg: dict) -> dict:
    rid = msg["id"]
    host = msg.get("host", "")
    hostname = host.split(":")[0] if ":" in host else host
    if hostname in SKIP_HOSTS:
        return allow(rid)

    raw = decode_body(msg.get("body"))
    if not raw:
        return allow(rid)

    text = raw.decode("utf-8", errors="replace")
    secrets = scan_for_secrets(text)

    if not secrets:
        log.info("request  %s %s%s (clean)", msg["method"], host, msg["uri"])
        return allow(rid)

    labels = ", ".join(secrets)
    log.warning("BLOCKED  %s %s%s -- leaked secret(s): %s (container=%s)",
                msg["method"], host, msg["uri"], labels, msg.get("container", ""))
    return deny(
        rid,
        status=403,
        body=f"Request blocked: detected leaked credentials ({labels}). "
             "Remove secrets from the request body before retrying.".encode(),
        tags={"secret-scanner.labels": secrets},
    )


if __name__ == "__main__":
    run(
        name="secret-scanner",
        handle_request=handle_request,
        max_body_bytes=2_097_152,
    )
