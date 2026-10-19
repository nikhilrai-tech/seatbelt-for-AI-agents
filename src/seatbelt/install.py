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
MATCHER = "Bash|PowerShell"
ON_FAILURE_MIN = (2, 1, 295)  # `onFailure: "block"` needs Claude Code >= this


def settings_path(scope: str, cwd: Optional[str] = None) -> Path:
    if scope == "user":
        return Path(os.path.expanduser("~/.claude/settings.json"))
    base = Path(cwd or os.getcwd()) / ".claude"
    return base / ("settings.local.json" if scope == "local" else "settings.json")


def hook_command(headless: bool = False) -> str:
    exe = shutil.which("seatbelt")
    if exe and Path(exe).parent == Path(sys.executable).parent:
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


def merge(settings: dict, entry: dict) -> tuple[dict, bool]:
    """Add our entry to settings['hooks']['PreToolUse']. Returns (settings, changed). Idempotent: ours is replaced."""
    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])
    kept = [e for e in pre if not _is_ours(e)]
    changed = kept + [entry] != pre
    hooks["PreToolUse"] = kept + [entry]
    return settings, changed


def remove(settings: dict) -> tuple[dict, bool]:
    pre = settings.get("hooks", {}).get("PreToolUse", [])
    kept = [e for e in pre if not _is_ours(e)]
    if len(kept) == len(pre):
        return settings, False
    if kept:
        settings["hooks"]["PreToolUse"] = kept
    else:
        del settings["hooks"]["PreToolUse"]
        if not settings["hooks"]:
            del settings["hooks"]
    return settings, True


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
