#!/usr/bin/env python3
"""Parse-or-refuse check for Claude Code managed settings.

Rebuilds a CI-side check. Does not copy Claude Code source.
Claude Code v2.1.259+ refuses to start on bad managed settings; this job
must also fail if the file cannot be written, read, or parsed — before
claude-code-action launches.
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path

DEFAULT_PATH = "/etc/claude-code/managed-settings.json"
WRAPPER_RULE = "Bash(/usr/local/bin/ar-panel-run)"
PANEL_RUN_DENY = (
    "Bash(python .claude/skills/adversarial-review/scripts/panel.py run:*)",
    "Bash(python3 .claude/skills/adversarial-review/scripts/panel.py run:*)",
)
# Representative invocations the closed wrapper is meant to be the only path for.
_PANEL_RUN_COMMANDS = (
    "python .claude/skills/adversarial-review/scripts/panel.py run",
    "python3 .claude/skills/adversarial-review/scripts/panel.py run",
    "python .claude/skills/adversarial-review/scripts/panel.py run --context-file x",
    "python3 .claude/skills/adversarial-review/scripts/panel.py run --context-file x",
)
# panel.py immediately followed by a wildcard / end — no subcommand pin.
_PANEL_PY_SUPERSET = re.compile(r"panel\.py(?:\s*:\*|\s*$|\s*\))")


def fail(msg: str) -> None:
    print(f"ERROR: managed-settings parse-or-refuse: {msg}", file=sys.stderr)
    raise SystemExit(1)


def _bash_inner(rule: str) -> str | None:
    if not rule.startswith("Bash(") or not rule.endswith(")"):
        return None
    return rule[5:-1]


def _bash_covers(inner: str, command: str) -> bool:
    """Whether a Claude Code Bash(allow) inner pattern would authorize command."""
    if inner in ("*", "*:*") or inner.startswith("*:") or inner == "":
        return True
    if inner.endswith(":*"):
        prefix = inner[:-2]
        if prefix in ("", "*"):
            return True
        return command == prefix or command.startswith(prefix)
    return command == inner


def rule_authorizes_direct_panel_run(rule: str) -> bool:
    """True if this allow rule can invoke panel.py run without the closed wrapper."""
    if "panel.py run" in rule:
        return True
    if _PANEL_PY_SUPERSET.search(rule):
        return True
    inner = _bash_inner(rule)
    if inner is None:
        return False
    return any(_bash_covers(inner, cmd) for cmd in _PANEL_RUN_COMMANDS)


def _is_regular_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        fail(f"unreadable: {path}: {exc}")
    return stat.S_ISREG(mode)


def check(path: Path) -> None:
    if not path.exists():
        fail(f"missing file: {path}")
    if path.is_symlink() or not _is_regular_file(path):
        fail(f"not a regular file (symlink/dir refused): {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"unreadable: {path}: {exc}")
    if not text.strip():
        fail(f"empty file: {path}")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        fail(f"unparseable JSON: {path}: {exc}")
    if not isinstance(data, dict):
        fail("top-level value must be a JSON object")
    if data.get("allowManagedPermissionRulesOnly") is not True:
        fail("allowManagedPermissionRulesOnly must be true")
    perms = data.get("permissions")
    if not isinstance(perms, dict):
        fail("permissions must be an object")
    if perms.get("defaultMode") != "dontAsk":
        fail('permissions.defaultMode must be "dontAsk"')
    if perms.get("disableBypassPermissionsMode") != "disable":
        fail('permissions.disableBypassPermissionsMode must be "disable"')
    if perms.get("disableAutoMode") != "disable":
        fail('permissions.disableAutoMode must be "disable"')
    allow = perms.get("allow")
    if not isinstance(allow, list):
        fail("permissions.allow must be an array")
    for rule in allow:
        if not isinstance(rule, str):
            fail("permissions.allow entries must be strings")
        if rule == WRAPPER_RULE:
            continue
        if rule == "Bash(*)" or (rule.startswith("Bash(*") and rule != WRAPPER_RULE):
            fail(
                "permissions.allow must not include Bash(*) or other unbounded "
                "Bash wildcards that re-enable panel.py run"
            )
        if rule_authorizes_direct_panel_run(rule):
            fail(
                "permissions.allow must not authorize panel.py run except via "
                f"exact {WRAPPER_RULE}; rejected {rule!r}"
            )
    if WRAPPER_RULE not in allow:
        fail(f"permissions.allow must include exact {WRAPPER_RULE} (no :*)")
    deny = perms.get("deny")
    if not isinstance(deny, list):
        fail("permissions.deny must be an array")
    for rule in deny:
        if not isinstance(rule, str):
            fail("permissions.deny entries must be strings")
    for required in PANEL_RUN_DENY:
        if required not in deny:
            fail(f"permissions.deny must include exact {required}")
    print(f"OK: managed-settings readable and parseable at {path}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    raw = args[0] if args else os.environ.get("CLAUDE_MANAGED_SETTINGS_PATH", DEFAULT_PATH)
    check(Path(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
