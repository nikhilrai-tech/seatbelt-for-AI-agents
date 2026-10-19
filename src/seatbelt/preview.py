"""Blast-radius preview: what would this deletion actually touch?

Everything here is done in-process by reading the filesystem. seatbelt deliberately never runs `git`, `kubectl` or any
other tool to find out: running git inside a repository the agent just cloned can execute code from that repository's
own config (`core.fsmonitor`, `core.pager`, hooks...), and a guardrail must not be the thing that triggers it.
"""
from __future__ import annotations

import glob as globmod
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .context import Context, Resolver
from .model import Level
from .rules.fs import DISK_DEVICE_PREFIXES
from .rules.opts import parse_words
from .shell import Command

MAX_ENTRIES = 200_000
BUDGET_SECONDS = 1.2  # for the whole preview of one command line, however many paths it names
FILTERS = {"-name", "-iname", "-path", "-ipath", "-regex", "-type", "-newer", "-mtime", "-mmin", "-empty", "-user", "-size", "-perm", "-atime", "-ctime"}
MAX_GLOB_MATCHES = 200
VIRTUAL_ROOTS = ("/proc", "/sys", "/dev", "/run")
IRREPLACEABLE = re.compile(r"(?i)^(\.env(\..*)?|.*\.(pem|key|p12|pfx|jks|keystore|sqlite3?|db|rdb|dump|bak|tfstate|kdbx))$")
ENV_EXAMPLES = (".example", ".sample", ".template", ".dist")


@dataclass
class Tree:
    files: int = 0
    dirs: int = 0
    bytes: int = 0
    recent: int = 0  # modified in the last 24 hours
    has_git: bool = False
    irreplaceable: list[str] = field(default_factory=list)
    truncated: bool = False
    skipped_mounts: int = 0

    def add(self, other: "Tree") -> None:
        self.files += other.files
        self.dirs += other.dirs
        self.bytes += other.bytes
        self.recent += other.recent
        self.has_git = self.has_git or other.has_git
        self.irreplaceable += [n for n in other.irreplaceable if n not in self.irreplaceable]
        self.truncated = self.truncated or other.truncated
        self.skipped_mounts += other.skipped_mounts


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def human_age(seconds: float) -> str:
    if seconds < 90:
        return "just now"
    for limit, div, unit in ((5400, 60, "minute"), (129600, 3600, "hour"), (86400 * 60, 86400, "day")):
        if seconds < limit:
            n = max(1, round(seconds / div))
            return f"{n} {unit}{'s' if n != 1 else ''} ago"
    return f"{round(seconds / (86400 * 30))} months ago"


def enabled() -> bool:
    return os.environ.get("SEATBELT_PREVIEW", "on").lower() not in ("off", "0", "false", "no")


def measure(path: str, now: Optional[float] = None, budget: float = BUDGET_SECONDS, max_entries: int = MAX_ENTRIES,
            deadline: Optional[float] = None) -> Optional[Tree]:
    """Count what is under `path` without following symlinks or crossing filesystems. None if it does not exist.

    `deadline` (a time.monotonic() value) lets several measurements share one budget.
    """
    now = now or time.time()
    try:
        st = os.lstat(path)
    except OSError:
        return None
    t = Tree()
    if not os.path.isdir(path) or os.path.islink(path):
        t.files, t.bytes = 1, st.st_size
        t.recent = int(now - st.st_mtime < 86400)
        if IRREPLACEABLE.match(os.path.basename(path)) and not path.endswith(ENV_EXAMPLES):
            t.irreplaceable.append(os.path.basename(path))
        return t
    if path.startswith(VIRTUAL_ROOTS):
        t.truncated = True
        return t
    root_dev, seen = st.st_dev, 0
    deadline = deadline if deadline is not None else time.monotonic() + budget
    if time.monotonic() >= deadline:
        t.truncated = True
        return t
    stack = [path]
    t.dirs = 1
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    seen += 1
                    if seen >= max_entries or (seen % 64 == 0 and time.monotonic() > deadline):
                        t.truncated = True
                        return t
                    try:
                        es = e.stat(follow_symlinks=False)
                        is_dir = e.is_dir(follow_symlinks=False)
                    except OSError:
                        continue
                    if is_dir:
                        if e.name == ".git":
                            t.has_git = True
                            continue  # history is flagged, not counted
                        if es.st_dev != root_dev:
                            t.skipped_mounts += 1
                            continue
                        t.dirs += 1
                        stack.append(e.path)
                    else:
                        t.files += 1
                        t.bytes += es.st_size
                        t.recent += int(now - es.st_mtime < 86400)
                        if len(t.irreplaceable) < 4 and IRREPLACEABLE.match(e.name) and not e.name.endswith(ENV_EXAMPLES):
                            t.irreplaceable.append(e.name)
        except OSError:
            continue
    return t


def describe_tree(path: str, t: Tree, verb: str = "deletes") -> str:
    plus = "at least " if t.truncated else ""
    if t.files == 1 and t.dirs == 0:
        return f"{verb} the file {path} ({human_bytes(t.bytes)})" + (", changed in the last 24 hours" if t.recent else "")
    parts = [f"{verb} {plus}{t.files:,} files in {t.dirs:,} folders ({plus}{human_bytes(t.bytes)}) under {path}"]
    notes = []
    if t.has_git:
        notes.append("includes a .git directory (the history)")
    if t.recent:
        notes.append(f"{t.recent:,} file{'s' if t.recent != 1 else ''} changed in the last 24 hours, so possibly uncommitted work")
    if t.irreplaceable:
        notes.append(f"includes {', '.join(t.irreplaceable[:3])}, which are probably not in version control")
    if t.skipped_mounts:
        notes.append(f"{t.skipped_mounts} mounted filesystem(s) inside it are not counted")
    if t.truncated:
        notes.append("stopped counting early; the real total is larger")
    return parts[0] + ("; " + "; ".join(notes) if notes else "")


def _targets(cmd: Command, res: Resolver, words) -> list[str]:
    out: list[str] = []
    for w in words:
        r = res.resolve(w, cmd.cwd)
        if r.path is None:
            continue
        if r.glob:
            matches = sorted(globmod.glob(r.path))[:MAX_GLOB_MATCHES]
            out += matches
        else:
            out.append(r.path)
    return out


def describe_command(cmd: Command, ctx: Context, res: Resolver, deadline: Optional[float] = None) -> list[str]:
    """Sentences describing what this command would destroy. Empty when there is nothing to measure."""
    deadline = deadline if deadline is not None else time.monotonic() + BUDGET_SECONDS
    name = cmd.name
    paths: list[str] = []
    verb = "deletes"
    if name in ("rm", "unlink", "rmdir", "shred"):
        o = parse_words(cmd.words[1:])
        paths = _targets(cmd, res, o.pos)
        verb = "overwrites" if name == "shred" else "deletes"
    elif name == "find" and "-delete" in cmd.argv and not FILTERS & set(cmd.argv):  # a filter makes the real set smaller
        roots = []
        for w in cmd.words[1:]:
            if w.text.startswith("-") or w.text in ("(", "!", ")"):
                break
            roots.append(w)
        paths = _targets(cmd, res, roots or [type(cmd.words[0])(".")])
    elif name == "dd":
        for a in cmd.argv[1:]:
            if a.startswith("of=") and not a[3:].startswith(("/dev/null", "/dev/zero")):
                r = res.resolve(a[3:], cmd.cwd)
                if r.path and not r.path.startswith(DISK_DEVICE_PREFIXES):
                    paths.append(r.path)
        verb = "overwrites"
    out: list[str] = []
    total = Tree()
    shown = 0
    unmeasured = 0
    for p in paths[:MAX_GLOB_MATCHES]:
        if time.monotonic() >= deadline:
            unmeasured += 1
            continue
        t = measure(p, deadline=deadline)
        if t is None:
            continue
        total.add(t)
        if shown < 3:
            out.append(describe_tree(p, t, verb))
            shown += 1
    if len(paths) > 3 and total.files:
        more = f" (stopped measuring; {unmeasured} paths not counted)" if unmeasured else ""
        out.append(f"{len(paths)} paths in total: {'at least ' if unmeasured or total.truncated else ''}{total.files:,} files ({human_bytes(total.bytes)}){more}")
    if unmeasured and not total.files:
        out.append(f"{unmeasured} path{'s' if unmeasured != 1 else ''} not counted (the preview ran out of time)")
    return out


def collect(commands: list[Command], findings, ctx: Context, res: Resolver) -> list[str]:
    """Previews for every command that raised an ASK/DENY finding (nothing is measured for harmless commands)."""
    if not enabled() or any(f.level == Level.DENY for f in findings):
        return []  # a DENY is already final; there is nothing to help anyone decide
    flagged = {f.command for f in findings if f.level >= Level.ASK}
    deadline = time.monotonic() + BUDGET_SECONDS
    out: list[str] = []
    for cmd in commands:
        if cmd.raw in flagged and cmd.words:
            for line in describe_command(cmd, ctx, res, deadline):
                if line not in out:
                    out.append(line)
    return out[:6]
