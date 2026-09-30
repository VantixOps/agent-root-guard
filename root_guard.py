#!/usr/bin/env python3
"""root_guard.py - PreToolUse hook for Claude Code (Bash tool).

Blocks destructive commands whose target can collapse to the filesystem root,
and nested remote commands built from several layers of quoting.

Why this exists
---------------
An AI coding agent once ran something like

    ssh prod '... sudo -n sh -c "chmod 0640 \"$1\"/*; ..." _ "$B" ...'

On the server $1 expanded to an empty string one quoting layer earlier than
intended, so `sh -c` received `chmod 0640 /*` and ran it as root. Every
top-level directory lost its execute bit and the services went down.

A PreToolUse hook runs BEFORE the command, on the text the agent submits. It
cannot know what a variable will contain, so it blocks targets that collapse
to "/" when a variable is empty or unset (a variable SET to "/" is out of
reach for any static check). The first version matched `$VAR/` only and missed the
incident's real spelling `\\"$1\\"/*`. Lesson: test a guard with the literal
text of the real incident.

Rule A - dangerous target. In a segment containing chmod/chown/chgrp/rm/mv/
         shred/truncate/dd/mkfs, block if an argument
           * is the root directory (`/` alone) or starts with `/*`,
           * is an empty quote pair right before `/` (`""/`, `''/`, escaped too),
           * is an unguarded variable right before `/` (use `${NAME:?}`).
Rule B - nested remote command: `ssh` + destructive verb + `sh -c`/`bash -c`
         + escaped `\\"`. Put the commands into a file or a quoted heredoc
         instead: `ssh host 'bash -s' <<'EOF' ... EOF`.

Override (deliberate): put `ROOT-GUARD-OK` anywhere in the command.
Limits: splits roughly on ; && || | and newlines. A safety net, not a shell
parser. It checks the Bash tool's command line only, not scripts run by it.

Self-test: python3 root_guard.py --self-test
"""
import json
import re
import sys

OVERRIDE = "ROOT-GUARD-OK"
DESTRUCTIVE = re.compile(r"\b(chmod|chown|chgrp|rm|mv|shred|truncate|dd|mkfs\w*)\b")
SPLIT = re.compile(r"\n|;|&&|\|\||\|")

# Variable right before "/". Only ${NAME:?...} is safe: it aborts when NAME is unset OR empty.
# ${NAME:-}, ${NAME-x}, ${NAME?}, ${NAME:+...} can all expand to "" and count as dangerous.
VAR_BEFORE_SLASH = re.compile(r"\$(\{(?![A-Za-z_]\w*:\?)[^}]*\}|[A-Za-z_]\w*|[0-9@*])(\\?[\"'])?/")
# Empty quote pair right before "/" (escaped too): ""/  ''/  \"\"/  \'\'/
EMPTY_BEFORE_SLASH = re.compile(r"""(?:^|[\s=])(?:""|''|\\"\\"|\\'\\')/""")
# Bare root as an argument: " / ", " /*", " /" at the end - but not "/usr".
ROOT_TARGET = re.compile(r"(?:^|\s)/(?:\s|\*|$)")

NESTED_SHELL = re.compile(r"\b(sh|bash)\s+-c\b")
ESCAPED_QUOTE = re.compile(r'\\"')


def dangerous_target(segment: str) -> bool:
    return bool(
        VAR_BEFORE_SLASH.search(segment)
        or EMPTY_BEFORE_SLASH.search(segment)
        or ROOT_TARGET.search(segment)
    )


def finding(command: str) -> str | None:
    if OVERRIDE in command:
        return None
    if (
        re.search(r"\bssh\b", command)
        and DESTRUCTIVE.search(command)
        and NESTED_SHELL.search(command)
        and ESCAPED_QUOTE.search(command)
    ):
        return "NESTED: " + command.strip()[:160]
    for segment in SPLIT.split(command):
        if DESTRUCTIVE.search(segment) and dangerous_target(segment):
            return "TARGET: " + segment.strip()[:160]
    return None


CASES = [
    # (command, should_block) - the first five are the real incident in its forms
    ('ssh h sudo -n sh -c "chmod 0640 \\"\\"/*" _ ""', True),
    ("chmod 0640 /*", True),
    ("chmod 0640 /", True),
    ('ssh h \'sudo -n sh -c "chmod 0640 \\"$1\\"/*" _ "$B"\'', True),
    ("chmod 755 / /boot /etc", True),
    ('rm -rf "$D"/*', True),
    ("rm -rf $D/x", True),
    ("mv ${SRC}/a b", True),
    ('chmod 600 "$1"/x', True),
    ("rm -rf /*", True),
    ('rm -rf "${DIR:-}"/*', True),   # default expansion can be empty
    ('rm -rf "${DIR-x}"/*', True),
    ("rm -rf ${DIR:+$DIR}/x", True),
    ('rm -rf "${DIR?}"/*', True),     # ? without : lets an EMPTY value through
    # Not covered on purpose: overwriting devices is a different class.
    ("dd if=/dev/zero of=/dev/vda", False),
    ('rm -rf "${D:?}"/*', False),
    ('ls "$D"/x', False),
    ("chmod 640 /tmp/x", False),
    ("chmod 755 /usr/bin /usr/lib64", False),
    ('sudo find "$B" -type f -exec chmod 0640 {} +', False),
    ('chown -R app:app "$B"', False),
    ("ssh h 'bash -s' <<'EOF'", False),
    ('rm -rf "$D"/* # ROOT-GUARD-OK', False),
    ('cp "$A"/x /tmp/', False),
    ('echo "$X"/y; rm file', False),
]


def self_test() -> int:
    errors = 0
    for command, expected in CASES:
        actual = finding(command) is not None
        ok = actual == expected
        errors += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {'blocks' if actual else 'passes'} | {command[:80]}")
    print(f"{len(CASES) - errors}/{len(CASES)} cases correct")
    return 1 if errors else 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    try:
        command = json.load(sys.stdin).get("tool_input", {}).get("command", "")
    except Exception:
        return 0
    where = finding(command or "")
    if where is None:
        return 0
    if where.startswith("NESTED:"):
        print(
            "BLOCKED - nested remote command: ssh + destructive verb + `sh -c \"...\"` "
            "with escaped quotes.\n"
            f"   {where[8:]}\n"
            "   An empty variable in the inner layer turns this into `chmod ... /*` as root.\n"
            "   Write the commands to a file or use a quoted heredoc:\n"
            "     ssh host 'bash -s' <<'EOF' ... EOF\n"
            f"   Deliberate exception: add {OVERRIDE} to the command.",
            file=sys.stderr,
        )
    else:
        print(
            "BLOCKED - destructive command whose target is the root directory or an "
            "unguarded variable before \"/\":\n"
            f"   {where[8:]}\n"
            "   If the variable is empty, this hits the whole system.\n"
            "   Use ${NAME:?} instead of $NAME, or name a concrete path.\n"
            f"   Deliberate exception: add {OVERRIDE} to the command.",
            file=sys.stderr,
        )
    return 2


if __name__ == "__main__":
    sys.exit(main())
