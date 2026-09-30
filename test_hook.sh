#!/usr/bin/env bash
# End-to-end check: feed the hook the JSON Claude Code sends and check exit codes.
# Exit code 2 = blocked (Claude Code shows stderr to the agent), 0 = allowed.
set -u
cd "$(dirname "$0")" || exit 1
fail=0
check() {  # $1 = expected exit code, $2 = command string
  local got
  printf '%s' "$2" | python3 -c 'import json,sys; print(json.dumps({"tool_input":{"command":sys.stdin.read()}}))' \
    | python3 root_guard.py >/dev/null 2>&1
  got=$?
  if [ "$got" = "$1" ]; then echo "ok   rc=$got | $2"; else echo "FAIL rc=$got (want $1) | $2"; fail=1; fi
}
check 2 'chmod 0640 /*'
check 2 'rm -rf "$DIR"/*'
check 0 'rm -rf "${DIR:?}"/*'
check 0 'ls -la /tmp'
check 0 'git status'
# Malformed input must not block (fail-open for the agent's normal work):
if printf 'not json' | python3 root_guard.py >/dev/null 2>&1; then echo "ok   malformed input passes"; else echo "FAIL malformed input"; fail=1; fi
exit $fail
