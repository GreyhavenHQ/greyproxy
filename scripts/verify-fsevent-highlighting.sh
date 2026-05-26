#!/bin/sh
# verify-fsevent-highlighting.sh
#
# Seeds a greyproxy session with one filesystem event in each severity
# tier, then prints what to look for in the dashboard. Re-runnable; each
# call uses a fresh timestamped session_id so old runs don't bleed in.
#
# Usage:
#   sh scripts/verify-fsevent-highlighting.sh             # seed + report
#   sh scripts/verify-fsevent-highlighting.sh --cleanup   # delete the session
#
# Exits non-zero if the API does not report the expected counts.

set -e

API="${GREYPROXY_API:-http://localhost:43080}"
SID="gw-verify-$(date +%s)"
TS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)

if [ "$1" = "--cleanup" ]; then
  RAW=$(curl -sS "$API/api/sessions")
  for sid in $(SESS_JSON="$RAW" python3 -c 'import os,json;[print(s["session_id"]) for s in json.loads(os.environ["SESS_JSON"]) if s["session_id"].startswith("gw-verify-")]'); do
    curl -sS -X DELETE "$API/api/sessions/$sid" >/dev/null
    echo "deleted $sid"
  done
  exit 0
fi

echo "API:        $API"
echo "session_id: $SID"
echo

# 1. Create the session.
curl -sS -X POST "$API/api/sessions" \
  -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\",\"container_name\":\"highlight-verify\",\"ttl_seconds\":600,\"allow_all\":true,\"metadata\":{\"cmd\":\"verify-fsevent-highlighting.sh\",\"pwd\":\"$PWD\"}}" \
  >/dev/null

# 2. Ship one event of every severity tier.
curl -sS -X POST "$API/api/sessions/$SID/heartbeat" -H 'Content-Type: application/json' -d "$(cat <<EOF
{"events":[
  {"ts":"$TS","op":"open_read",  "path":"$HOME/.ssh/id_rsa",                       "pid":1001},
  {"ts":"$TS","op":"open_read",  "path":"$HOME/.aws/credentials",                  "pid":1001},
  {"ts":"$TS","op":"open_read",  "path":"/dev/kmem",                               "pid":1001},
  {"ts":"$TS","op":"open_read",  "path":"/proc/kcore",                             "pid":1001},
  {"ts":"$TS","op":"open_read",  "path":"$PWD/.env",                               "pid":1001},
  {"ts":"$TS","op":"open_write", "path":"$HOME/.zshrc",                            "pid":1001},
  {"ts":"$TS","op":"open_write", "path":"$PWD/.git/hooks/pre-commit",              "pid":1001},
  {"ts":"$TS","op":"create",     "path":"$HOME/Library/LaunchAgents/evil.plist",   "pid":1001},
  {"ts":"$TS","op":"open_read",  "path":"$PWD/main.go",                            "pid":1001},
  {"ts":"$TS","op":"open_write", "path":"$PWD/build.log",                          "pid":1001}
]}
EOF
)" >/dev/null

# 3. Read it back and assert.
SNAP=$(curl -sS "$API/api/sessions/$SID/fsevents")
SNAP_JSON="$SNAP" python3 <<'PY'
import json, os, sys
snap = json.loads(os.environ["SNAP_JSON"])
crit, warn = snap.get("critical_count", 0), snap.get("warn_count", 0)
print(f"critical_count={crit} warn_count={warn}")
print()
print(f"{'sev':<8} {'op':<10} {'tags':<30} path")
print("-"*100)
for e in snap["events"]:
    tags = ",".join(e.get("tags", []))
    print(f"{e.get('severity','info'):<8} {e['op']:<10} {tags:<30} {e['path']}")
print()
# Expected: 5 critical (4 cred-ish + 1 kernel + 1 kernel = wait let me count from script)
# Script ships: id_rsa(crit) aws(crit) kmem(crit) kcore(crit) .env(crit) -> 5 critical
#               .zshrc(warn) .git/hooks(warn) LaunchAgents(warn) -> 3 warn
#               main.go(info) build.log(info) -> 2 info
want_crit, want_warn = 5, 3
ok = crit == want_crit and warn == want_warn
print(f"expected: critical={want_crit} warn={want_warn}  -> {'OK' if ok else 'MISMATCH'}")
sys.exit(0 if ok else 1)
PY

cat <<NEXT

Now check the browser:
  open '$API/dashboard'
  -> Credentials tab -> Active Sessions card
  -> Find session card labelled "highlight-verify"

You should see, in that card:
  * Header row: a red badge "⚠ 5 critical" and an amber "3 warn".
  * Each event row tinted red (critical) / amber (warn) / plain (info)
    with a colored left bar.
  * Tag chips after the path: credentials, ssh, aws, kernel, dotenv,
    shell-init, git-hooks, launch-agents.

If you want to watch it land live, open the dashboard first, then re-run
this script in another terminal. The session.fs_alert bus event should
refresh the card without a manual reload.

When done:
  sh $0 --cleanup
NEXT
