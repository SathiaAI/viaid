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
import stat
import sys
from pathlib import Path

DEFAULT_PATH = "/etc/claude-code/managed-settings.json"
WRAPPER_RULE = "Bash(/usr/local/bin/ar-panel-run)"


def fail(msg: str) -> None:
    print(f"ERROR: managed-settings parse-or-refuse: {msg}", file=sys.stderr)
    raise SystemExit(1)


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
    allow = perms.get("allow")
    if not isinstance(allow, list):
        fail("permissions.allow must be an array")
    for rule in allow:
        if not isinstance(rule, str):
            fail("permissions.allow entries must be strings")
        if "panel.py run" in rule:
            fail(
                "permissions.allow must not list panel.py run directly; "
                "use the closed wrapper Bash(/usr/local/bin/ar-panel-run)"
            )
    if WRAPPER_RULE not in allow:
        fail(f"permissions.allow must include exact {WRAPPER_RULE} (no :*)")
    print(f"OK: managed-settings readable and parseable at {path}")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    raw = args[0] if args else os.environ.get("CLAUDE_MANAGED_SETTINGS_PATH", DEFAULT_PATH)
    check(Path(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
