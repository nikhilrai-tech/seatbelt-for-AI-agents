"""Tamper protection: an agent must not be able to switch off its own guardrails, or plant things that run later."""
from __future__ import annotations

import fnmatch
import posixpath
from typing import Optional

from ..context import Context, Resolver
from ..model import Finding, Level
from ..shell import Command, Word
from ..policy import config_dir
from . import rule
from .opts import parse_words

ASK, DENY = Level.ASK, Level.DENY
WRITE_OPS = {">", ">>", ">|", "&>", "&>>", "<>"}
RC_FILES = {".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin"}
CI_FILES = {".gitlab-ci.yml", "Jenkinsfile", ".travis.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml"}


def audit_paths(ctx: Context) -> set[str]:
    out = {f"{ctx.home.rstrip('/')}/.local/state/seatbelt/audit.jsonl"}
    for key in ("SEATBELT_AUDIT_LOG",):
        if ctx.environ.get(key):
            out.add(ctx.environ[key])
    state = ctx.environ.get("XDG_STATE_HOME")
    if state:
        out.add(f"{state.rstrip('/')}/seatbelt/audit.jsonl")
    return out


def protected_kind(path: str, ctx: Context) -> Optional[tuple[Level, str]]:
    """(level, what) if changing `path` would weaken the guardrails or plant a persistent foothold."""
    home = ctx.home.rstrip("/")
    base = posixpath.basename(path)
    rel = path[len(home) + 1:] if path.startswith(home + "/") else None
    if fnmatch.fnmatchcase(path, "*/.claude/settings*.json") or "/.claude/hooks/" in path or base == ".claude.json":
        return DENY, "the agent's own settings or hooks"
    if base in ("seatbelt.toml", ".seatbelt.toml") or (rel and rel.startswith(".config/seatbelt/")) \
            or path.startswith(config_dir(ctx.home, ctx.environ).as_posix() + "/") or path == ctx.environ.get("SEATBELT_CONFIG"):
        return DENY, "seatbelt's own configuration"
    if path in audit_paths(ctx) or path.rstrip("/").endswith(".jsonl.1") and "/seatbelt/" in path:
        return DENY, "seatbelt's audit log"
    if "/pipx/venvs/seatbelt-guard" in path or "/uv/tools/seatbelt-guard" in path or "/site-packages/seatbelt" in path:
        return DENY, "seatbelt's own installation (the hook lives there; breaking it makes Claude Code run commands unchecked)"
    if base == "authorized_keys":
        return DENY, "SSH authorized_keys (it grants remote access)"
    if path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers") or path.startswith(("/etc/sudoers.d/", "/etc/ssh/", "/etc/pam.d/")):
        return DENY, "system authentication files"
    if rel is not None and posixpath.dirname(rel) == "" and base in RC_FILES:
        return ASK, f"your shell startup file ({base}), which runs every time you open a terminal"
    if rel == ".config/fish/config.fish":
        return ASK, "your shell startup file (config.fish)"
    if "/.git/hooks/" in path or path.endswith("/.git/config"):
        return ASK, "git hooks/config (they run automatically on git commands)"
    if "/.github/workflows/" in path or "/.circleci/" in path or base in CI_FILES:
        return ASK, "CI pipeline configuration"
    if path.startswith(("/etc/systemd/", "/etc/cron", "/var/spool/cron", "/etc/profile", "/etc/environment", "/etc/hosts")) \
            or (rel and rel.startswith(".config/systemd/user/")):
        return ASK, "system startup/scheduling configuration"
    if rel == ".ssh/config" or rel == ".gitconfig":
        return ASK, f"~/{rel}"
    return None


SED_VALUE_OPTS = {"-e", "-f", "--expression", "--file", "-l", "--line-length"}
CP_VALUE_OPTS = {"-t", "--target-directory", "-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group"}


def write_targets(cmd: Command) -> list[Word | str]:
    """Paths this command writes to, deletes or renames (best effort, by command)."""
    n = cmd.name
    targets: list[Word | str] = [r.target for r in cmd.redirects if r.op in WRITE_OPS and r.target]
    words = cmd.words[1:]
    if n == "tee":
        targets += parse_words(words).pos
    elif n in ("sed", "perl", "gsed"):
        o = parse_words(words, SED_VALUE_OPTS)
        if any(f == "-i" or f.startswith("--in-place") for f in o.flags):
            targets += o.pos if (o.has("-e", "-f", "--expression", "--file") or n == "perl") else o.pos[1:]
    elif n in ("cp", "mv", "install", "ln", "rsync", "scp"):
        o = parse_words(words, CP_VALUE_OPTS)
        dest = (o.values.get("-t") or o.values.get("--target-directory") or [None])[0]
        if n == "mv":
            targets += o.pos
        if dest:
            targets.append(dest)
        elif len(o.pos) >= 2:
            targets.append(o.pos[-1])
    elif n in ("rm", "unlink", "shred", "rmdir"):
        targets += parse_words(words).pos
    elif n == "truncate":
        targets += parse_words(words, {"-s", "--size", "-r", "--reference"}).pos
    elif n in ("chmod", "chown", "chgrp"):
        targets += parse_words(words).pos[1:]
    elif n == "dd":
        targets += [a[3:] for a in cmd.argv[1:] if a.startswith("of=")]
    return targets


@rule("*")
def tamper(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    out: list[Finding] = []
    for t in write_targets(cmd):
        r = res.resolve(t, cmd.cwd)
        if r.path is None:
            continue
        hit = protected_kind(r.path, ctx)
        if hit:
            level, what = hit
            msg = f"`{cmd.name}` would change {what} ({r.path})"
            if level == DENY:
                msg += ": agents must not edit their own guardrails or access paths; do it yourself if you mean it"
            out.append(Finding("tamper.protected-file", level, "tamper", msg, cmd.raw))
            break
    return out
