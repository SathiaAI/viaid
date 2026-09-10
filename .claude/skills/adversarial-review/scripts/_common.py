"""Shared helpers for adversarial-review scripts. Stdlib only, by design."""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

RUN_ROOT = Path(os.environ.get("AR_RUN_DIR", ".adversarial-review"))


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def resolve_run(run_arg=None):
    """Return the run directory: explicit arg, else newest run-* under the root."""
    if run_arg:
        p = Path(run_arg) if os.sep in str(run_arg) else RUN_ROOT / run_arg
        if not p.is_dir():
            die(f"run directory not found: {p}")
        return p
    if not RUN_ROOT.is_dir():
        die(f"no {RUN_ROOT}/ directory — run `panel.py init` first")
    runs = sorted(d for d in RUN_ROOT.iterdir() if d.is_dir() and d.name.startswith("run-"))
    if not runs:
        die(f"no runs under {RUN_ROOT}/ — run `panel.py init` first")
    return runs[-1]


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path, obj):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def die(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def require_under_run_root(path_arg, flag_name):
    """Refuse paths that are not real files inside AR_RUN_DIR / RUN_ROOT.

    Symlink escapes are resolved first, then the real path must stay under the
    run root. Missing or unreadable files fail closed.
    """
    if not path_arg:
        die(f"{flag_name} is required")
    try:
        root = RUN_ROOT.expanduser().resolve()
    except OSError as exc:
        die(f"cannot resolve AR_RUN_DIR ({RUN_ROOT}): {exc}")
    try:
        resolved = Path(path_arg).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        die(f"{flag_name}: cannot resolve {path_arg!r}: {exc}")
    try:
        resolved.relative_to(root)
    except ValueError:
        die(f"{flag_name} must be under AR_RUN_DIR ({root}); refused {path_arg!r}")
    if not resolved.is_file():
        die(f"{flag_name} is not a readable file under AR_RUN_DIR: {resolved}")
    return resolved


# Provider-family normalization. Family = the model AUTHOR's organization — the unit of
# independence. Slug prefixes vary across routers; map known variants to one family key.
FAMILY_ALIASES = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google",
    "x-ai": "xai", "xai": "xai",
    "qwen": "qwen", "alibaba": "qwen",
    "mistralai": "mistral", "mistral": "mistral",
    "deepseek": "deepseek",
    "meta-llama": "meta", "meta": "meta",
    "moonshotai": "moonshot", "moonshot": "moonshot",
    "z-ai": "zai", "zai": "zai", "zhipu": "zai",
    "cohere": "cohere",
    "amazon": "amazon",
    "microsoft": "microsoft",
    "nvidia": "nvidia",
    "ai21": "ai21",
}


def family_of(slug):
    prefix = slug.split("/", 1)[0].lower()
    return FAMILY_ALIASES.get(prefix, prefix)
