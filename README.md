# agent-root-guard

A small [Claude Code](https://code.claude.com/docs) [`PreToolUse` hook](https://code.claude.com/docs/en/hooks) that stops an AI coding agent from running destructive commands whose target can collapse to `/`.

```text
chmod 0640 /*            -> blocked
rm -rf "$DIR"/*          -> blocked   (empty $DIR = rm -rf /*)
rm -rf "${DIR:?}"/*      -> allowed   (fails safely if DIR is empty)
```

## Why

It happened to us. An agent built a remote command with several layers of quoting:

```text
ssh prod '... sudo -n sh -c "chmod 0640 \"$1\"/*" _ "$B" ...'
```

On the server, `$1` expanded to nothing one quoting layer earlier than intended, so `sh -c` received `chmod 0640 /*` and ran it as root. All top-level directories lost their execute bit and the services on that machine went down.

A `PreToolUse` hook runs **before** the command, on the text the agent submits. It cannot know what a variable will contain – least of all on another machine. So this guard does not try to predict values. It blocks destructive targets that collapse to `/` when a variable is **empty or unset**: an unguarded variable before `/`, a literal `/` or `/*`, an empty quote pair, and nested remote shells whose inner expansion it cannot see.

Two things we learned while building it, both caught by review before release:

- Our first version matched `$VAR/` only. The incident's actual spelling was `\"$1\"/*` – an escaped quote between variable and slash – and slipped through. Test a guard with the literal text of the real incident.
- `${VAR:-}`, `${VAR-x}`, `${VAR?}` and `${VAR:+…}` can all expand to an empty string. Only `${VAR:?}` aborts on both unset **and** empty, so it is the only form the guard accepts.

## What it blocks

**Rule A – dangerous target.** In a segment with `chmod`, `chown`, `chgrp`, `rm`, `mv`, `shred`, `truncate`, `dd` or `mkfs*`, it blocks if an argument

- is the root directory (`/`) or starts with `/*`,
- is an empty quote pair right before `/` (`""/`, `''/`, also escaped),
- is a variable right before `/` without the `${NAME:?}` guard.

**Rule B – nested remote command.** `ssh` + destructive verb + `sh -c`/`bash -c` + escaped `\"`. Use a quoted heredoc instead: `ssh host 'bash -s' <<'EOF' … EOF`.

**Override:** add `ROOT-GUARD-OK` anywhere in the command when you really mean it.

## What it does not do

It is a safety net, not a shell parser. It splits roughly on `;`, `&&`, `||`, `|` and newlines, checks only the command line of the Bash tool (not the scripts that command runs), and deliberately ignores device overwrites like `dd of=/dev/sda`. It also cannot know a variable's **value**: `rm -rf "${DIR:?}"/*` passes, because `${DIR:?}` guarantees a non-empty value – but if `DIR` is set to `/`, it still hits the root.

Expect the occasional false positive, too – for example `cp ${A}/x /tmp/rm` is blocked because `rm` appears as a word, or a command merely *contains* such a string as test data. We prefer a false alarm over a missed deletion.

## Install

Requires Python 3.10+.

1. Copy `root_guard.py` somewhere stable, e.g. `~/.claude/hooks/root_guard.py`.
2. Add the hook to `~/.claude/settings.json` (or a project's `.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "python3 ~/.claude/hooks/root_guard.py" }
        ]
      }
    ]
  }
}
```

The hook exits with code `2` to block. Claude Code then shows the message on stderr to the agent, which usually rewrites the command with `${NAME:?}` or a concrete path.

## Test

```bash
python3 root_guard.py --self-test   # 25 cases, including the real incident
bash test_hook.sh                   # end-to-end: JSON in, exit code out
```

Both run on every push via GitHub Actions.

## License

MIT – see [LICENSE](LICENSE). Made by [VantixOps](https://vantix-ops.de), Bremen.
