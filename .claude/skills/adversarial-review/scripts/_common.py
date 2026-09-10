"""Shared helpers for adversarial-review scripts. Stdlib only, by design."""
import errno
import json
import os
import stat
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


def _require_containment_open_flags():
    """Fail closed if this platform cannot do a no-follow openat walk."""
    missing = [
        name
        for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_DIRECTORY")
        if not hasattr(os, name)
    ]
    if missing:
        die(
            f"{', '.join(missing)} unavailable; refusing rather than losing "
            "the AR_RUN_DIR no-follow containment guard"
        )


def _rel_parts_under_run_root(path_arg, flag_name):
    """Return (resolved_root, relative parts) for a path that must stay inside RUN_ROOT.

    The last path component is not resolved, so a swapped symlink cannot be
    followed during this mapping. Relative paths are tried against cwd and
    against the run root.
    """
    if not path_arg:
        die(f"{flag_name} is required")
    root_given = RUN_ROOT.expanduser()
    try:
        root_real = root_given.resolve()
    except OSError as exc:
        die(f"cannot resolve AR_RUN_DIR ({RUN_ROOT}): {exc}")
    if not root_real.is_dir():
        die(f"AR_RUN_DIR is not a directory: {root_real}")

    raw = Path(path_arg).expanduser()
    candidates = []
    if raw.is_absolute():
        candidates.append(Path(os.path.normpath(str(raw))))
    else:
        candidates.append(Path(os.path.normpath(str(Path.cwd() / raw))))
        candidates.append(Path(os.path.normpath(str(root_real / raw))))
        candidates.append(Path(os.path.normpath(str(root_given / raw))))

    root_given_norm = Path(os.path.normpath(str(root_given)))
    for cand in candidates:
        for base in (root_real, root_given_norm):
            try:
                rel = cand.relative_to(base)
            except ValueError:
                continue
            parts = [p for p in rel.parts if p not in ("", ".")]
            if not parts or ".." in parts:
                continue
            return root_real, parts
    die(f"{flag_name} must be under AR_RUN_DIR ({root_real}); refused {path_arg!r}")


def _open_regular_under_run_root(path_arg, flag_name):
    """Open path_arg once, root-anchored, no-follow. Return (display_path, fd).

    Walks each component from the resolved run root with openat + O_NOFOLLOW so
    an intermediate or final symlink cannot escape AR_RUN_DIR. Caller owns the
    fd and must close it. The opened object is verified to be a regular file
    via fstat on this descriptor — the pathname is not reopened.
    """
    _require_containment_open_flags()
    root_real, parts = _rel_parts_under_run_root(path_arg, flag_name)
    display = root_real.joinpath(*parts)
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK

    try:
        root_fd = os.open(str(root_real), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        die(f"cannot open AR_RUN_DIR ({root_real}): {exc}")

    current = root_fd
    close_current = True
    try:
        for i, part in enumerate(parts):
            is_last = i == len(parts) - 1
            flags = file_flags if is_last else dir_flags
            try:
                nxt = os.open(part, flags, dir_fd=current)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    die(
                        f"{flag_name} is a symlink; refused "
                        f"(no-follow under AR_RUN_DIR): {display}"
                    )
                if exc.errno in (errno.EAGAIN, getattr(errno, "EWOULDBLOCK", errno.EAGAIN)):
                    die(f"{flag_name} is not a readable regular file under AR_RUN_DIR: {display}")
                die(f"{flag_name}: cannot open {display}: {exc}")
            os.close(current)
            current = nxt
        st = os.fstat(current)
        if not stat.S_ISREG(st.st_mode):
            die(f"{flag_name} is not a regular file under AR_RUN_DIR: {display}")
        close_current = False
        return display, current
    finally:
        if close_current:
            os.close(current)


def read_under_run_root(path_arg, flag_name):
    """Read a regular file under AR_RUN_DIR from a single no-follow descriptor.

    Use this when the bytes will be sent onward (concur prompt, prepare/run
    context). Do not reopen the pathname after this returns.
    """
    _path, fd = _open_regular_under_run_root(path_arg, flag_name)
    try:
        with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as fh:
            fd = -1
            return fh.read()
    except OSError as exc:
        die(f"{flag_name} is not a readable file under AR_RUN_DIR: {exc}")
    finally:
        if fd >= 0:
            os.close(fd)


def require_under_run_root(path_arg, flag_name):
    """Refuse paths that are not readable regular files inside AR_RUN_DIR.

    Opens once with a root-anchored no-follow walk and fstat. Callers that
    need the file bytes should use read_under_run_root instead of reopening
    the returned pathname.
    """
    display, fd = _open_regular_under_run_root(path_arg, flag_name)
    os.close(fd)
    return display


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
