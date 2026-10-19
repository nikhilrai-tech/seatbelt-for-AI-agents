"""Register (or remove) the hook in a Claude Code settings.json. Merge-only: other settings and hooks are kept."""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

MARKER = "seatbelt hook"
MATCHER = "Bash|PowerShell|Read|Write|Edit|MultiEdit|NotebookEdit|Glob|Grep"
ON_FAILURE_MIN = (2, 1, 295)  # `onFailure: "block"` needs Claude Code >= this
EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")  # Pre decides; the Post events only record that a call ran


def settings_path(scope: str, cwd: Optional[str] = None) -> Path:
    if scope == "user":
        return Path(os.path.expanduser("~/.claude/settings.json"))
    base = Path(cwd or os.getcwd()) / ".claude"
    return base / ("settings.local.json" if scope == "local" else "settings.json")


STABLE_TOOL_ENVS = ("/pipx/venvs/", "/uv/tools/")  # tool installers recreate these in place and keep a stable launcher on PATH

VENV_WARNING = ("seatbelt is running from a virtual environment ({where}) and the hook will point into it. If that environment is "
                "deleted or recreated, the hook stops working silently and Claude Code runs commands unchecked. Install it as a tool "
                "instead: `pipx install seatbelt-guard`, then run `seatbelt install claude-code --write` again.")


def is_fragile_python_env(path: str) -> bool:
    """True if `path` lives in an ordinary virtual environment (one a person may delete), not a tool installer's."""
    p = str(Path(path).absolute())
    if any(marker in p for marker in STABLE_TOOL_ENVS):
        return False
    return any((parent / "pyvenv.cfg").is_file() for parent in list(Path(p).parents)[:4])


def hook_command(headless: bool = False) -> str:
    exe = shutil.which("seatbelt")
    # with pipx the launcher on PATH is a symlink into the tool's venv: prefer it, it survives a reinstall
    if exe and Path(exe).resolve().parent == Path(sys.executable).parent:
        base = shlex.quote(exe)
    else:
        base = f"{shlex.quote(sys.executable)} -m seatbelt"
    return f"{base} hook" + (" --headless" if headless else "")


def claude_version() -> Optional[tuple[int, int, int]]:
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=8).stdout
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
        return tuple(int(x) for x in m.groups()) if m else None
    except Exception:
        return None


def build_entry(command: str, on_failure_block: bool) -> dict:
    handler: dict = {"type": "command", "command": command}
    if on_failure_block:
        handler["onFailure"] = "block"
    return {"matcher": MATCHER, "hooks": [handler]}


def _is_ours(entry: dict) -> bool:
    return any(MARKER in str(h.get("command", "")) for h in entry.get("hooks", []))


def merge(settings: dict, entry: dict, event: str = "PreToolUse") -> tuple[dict, bool]:
    """Add our entry under settings['hooks'][event]. Returns (settings, changed). Idempotent: ours is replaced."""
    hooks = settings.setdefault("hooks", {})
    current = hooks.setdefault(event, [])
    kept = [e for e in current if not _is_ours(e)]
    changed = kept + [entry] != current
    hooks[event] = kept + [entry]
    return settings, changed


def entries_for(command: str, on_failure_block: bool) -> dict[str, dict]:
    """Pre decides (and may fail closed); the Post events only log, so a failure there is harmless."""
    return {event: build_entry(command, on_failure_block and event == "PreToolUse") for event in EVENTS}


def merge_all(settings: dict, command: str, on_failure_block: bool) -> tuple[dict, bool]:
    changed = False
    for event, entry in entries_for(command, on_failure_block).items():
        settings, c = merge(settings, entry, event)
        changed = changed or c
    return settings, changed


def remove(settings: dict) -> tuple[dict, bool]:
    removed = False
    for event in EVENTS:
        current = settings.get("hooks", {}).get(event, [])
        kept = [e for e in current if not _is_ours(e)]
        if len(kept) == len(current):
            continue
        removed = True
        if kept:
            settings["hooks"][event] = kept
        else:
            del settings["hooks"][event]
    if removed and not settings.get("hooks"):
        settings.pop("hooks", None)
    return settings, removed


def load(path: Path) -> dict:
    if not path.exists():
        return {}
    text = path.read_text()
    return json.loads(text) if text.strip() else {}


def save(path: Path, settings: dict) -> Optional[Path]:
    """Write settings, keeping a .bak of what was there. Returns the backup path if one was made."""
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if path.exists():
        backup = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, backup)
    path.write_text(json.dumps(settings, indent=2) + "\n")
    return backup
