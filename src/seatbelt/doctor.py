"""`seatbelt doctor`: is the guardrail actually in place and working?

The worst failure of a guardrail is the silent one. Claude Code treats a hook that cannot run (binary moved, venv deleted,
a typo in settings) as a non-blocking error, so every command goes through unchecked and nothing looks wrong. The doctor
checks the settings *and* runs the installed hook command for real against a dangerous and a harmless payload.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Optional

from . import __version__, install
from . import policy as policy_mod
from .audit import default_path

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"
DENY_PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "seatbelt-doctor",
                "tool_input": {"command": "git push --force origin main"}}
SAFE_PAYLOAD = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "seatbelt-doctor",
                "tool_input": {"command": "ls"}}

Runner = Callable[[str, dict], tuple[int, str, str]]


@dataclass
class Check:
    status: str
    title: str
    detail: str = ""
    fix: str = ""


def run_hook_command(command: str, payload: dict, cwd: str) -> tuple[int, str, str]:
    env = dict(os.environ, SEATBELT_AUDIT="off", SEATBELT_HEADLESS="0")
    p = subprocess.run(command, shell=True, input=json.dumps({**payload, "cwd": cwd}), capture_output=True, text=True,
                       timeout=20, env=env)
    return p.returncode, p.stdout, p.stderr


def _entries(settings: dict, event: str) -> list[dict]:
    return [e for e in settings.get("hooks", {}).get(event, []) if install._is_ours(e)]


def _command_of(entry: dict) -> str:
    return next((h.get("command", "") for h in entry.get("hooks", []) if install.MARKER in str(h.get("command", ""))), "")


def _executable_exists(command: str) -> tuple[bool, str]:
    try:
        first = shlex.split(command)[0]
    except (ValueError, IndexError):
        return False, command
    return bool(shutil.which(first) or (os.path.isabs(first) and os.access(first, os.X_OK))), first


def self_test(command: str, cwd: str, runner: Runner) -> list[Check]:
    out: list[Check] = []
    for label, payload, expect_deny in (("a dangerous command", DENY_PAYLOAD, True), ("a harmless command", SAFE_PAYLOAD, False)):
        try:
            code, stdout, stderr = runner(command, payload)
        except Exception as exc:
            out.append(Check(FAIL, f"live test: {label}", f"could not run the hook command ({type(exc).__name__}: {exc})",
                             "re-run `seatbelt install claude-code --write`"))
            continue
        if code != 0:
            out.append(Check(FAIL, f"live test: {label}", f"the hook exited with {code}. Claude Code would let the command run. {stderr.strip()[:160]}",
                             "re-run `seatbelt install claude-code --write`"))
            continue
        if expect_deny:
            try:
                decision = json.loads(stdout)["hookSpecificOutput"]["permissionDecision"]
            except Exception:
                decision = None
            ok = decision == "deny"
            out.append(Check(OK if ok else FAIL, "live test: a force-push to main is blocked",
                             "deny, as expected" if ok else f"expected a deny, got {stdout.strip()[:120] or 'no output'}",
                             "" if ok else "the installed hook is not enforcing; re-run `seatbelt install claude-code --write`"))
        else:
            ok = stdout.strip() == ""
            out.append(Check(OK if ok else FAIL, "live test: a harmless command (`ls`) is left alone",
                             "silent, as expected" if ok else f"unexpected output: {stdout.strip()[:120]}",
                             "" if ok else "run `seatbelt check ls` to see why"))
    return out


def check_settings_file(path: Path, scope: str, claude_ver: Optional[tuple[int, int, int]]) -> tuple[list[Check], Optional[str]]:
    """Checks for one settings file. Returns (checks, the hook command if our PreToolUse hook is installed there)."""
    out: list[Check] = []
    try:
        settings = install.load(path)
    except ValueError:
        return [Check(FAIL, f"{scope} settings ({path})", "not valid JSON, so Claude Code may ignore the whole file",
                      "fix the JSON by hand")], None
    pre = _entries(settings, "PreToolUse")
    if settings.get("disableAllHooks") is True:
        out.append(Check(FAIL, f"{scope} settings ({path})", '"disableAllHooks": true: no hook runs, seatbelt included',
                         'remove "disableAllHooks" or set it to false'))
    if not pre:
        return out, None
    command = _command_of(pre[0])
    out.append(Check(OK, f"{scope}: PreToolUse hook installed", str(path)))
    exists, first = _executable_exists(command)
    out.append(Check(OK if exists else FAIL, f"{scope}: hook program exists", first if exists else
                     f"`{first}` cannot be found. Claude Code treats that as a non-blocking error: commands run unchecked",
                     "" if exists else "re-run `seatbelt install claude-code --write` from the environment where seatbelt is installed"))
    if exists and install.is_fragile_python_env(first):
        out.append(Check(WARN, f"{scope}: the hook lives in a virtual environment",
                         f"{first}: if that environment is deleted or recreated the hook silently stops working",
                         "install it as a tool (`pipx install seatbelt-guard`) and run `seatbelt install claude-code --write` again"))
    matcher = pre[0].get("matcher", "")
    missing = [t for t in install.MATCHER.split("|") if t not in matcher] if matcher not in ("", "*") else []
    if missing:
        out.append(Check(WARN, f"{scope}: matcher is out of date", f"does not cover {', '.join(missing)}",
                         "re-run `seatbelt install claude-code --write`"))
    on_failure = any(h.get("onFailure") == "block" for h in pre[0].get("hooks", []))
    if on_failure:
        out.append(Check(OK, f"{scope}: a failing hook blocks (onFailure=block)"))
    elif claude_ver and claude_ver >= install.ON_FAILURE_MIN:
        out.append(Check(WARN, f"{scope}: a failing hook lets commands through",
                         "onFailure=block is not set, and this Claude Code supports it",
                         "re-run `seatbelt install claude-code --write`"))
    else:
        out.append(Check(INFO, f"{scope}: onFailure=block not available",
                         "needs Claude Code >= 2.1.295; until then a hook that cannot run lets commands through"))
    missing_events = [e for e in install.EVENTS[1:] if not _entries(settings, e)]
    if missing_events:
        out.append(Check(INFO, f"{scope}: learn mode is not recording", f"no {', '.join(missing_events)} hook",
                         "re-run `seatbelt install claude-code --write`"))
    return out, command


def run(cwd: str, home: str, environ: Mapping[str, str], runner: Optional[Runner] = None,
        claude_version: Optional[Callable[[], Optional[tuple[int, int, int]]]] = None,
        settings_paths: Optional[dict[str, Path]] = None) -> list[Check]:
    runner = runner or (lambda cmd, payload: run_hook_command(cmd, payload, cwd))
    ver = (claude_version or install.claude_version)()
    checks = [Check(INFO, "seatbelt", __version__),
              Check(OK if ver else WARN, "Claude Code", ".".join(map(str, ver)) if ver else "not found on PATH",
                    "" if ver else "seatbelt only works with agents it is wired into; install Claude Code or run on a machine that has it")]
    paths = settings_paths or {"user": install.settings_path("user"), "project": install.settings_path("project", cwd),
                               "local": install.settings_path("local", cwd)}
    commands: list[str] = []
    for scope, path in paths.items():
        if not Path(path).exists():
            continue
        found, command = check_settings_file(Path(path), scope, ver)
        checks += found
        if command:
            commands.append(command)
    if not commands:
        checks.append(Check(FAIL, "no seatbelt hook is installed", "Claude Code is running every command unchecked",
                            "run `seatbelt install claude-code --write`"))
        commands = [install.hook_command()]  # still prove the engine itself works on this machine
        checks.append(Check(INFO, "testing the engine with a default command instead"))
    checks += self_test(commands[0], cwd, runner)

    pol = policy_mod.load(cwd, home, environ)
    if pol.error:
        checks.append(Check(FAIL, "configuration", pol.error, "fix or remove the config file (while it is broken every command asks)"))
    else:
        looked = policy_mod.user_config_path(home, environ)
        checks.append(Check(OK, "configuration", ", ".join(pol.sources) if pol.sources else
                            f"none (built-in rules only; the user config would be {looked})"))
    checks += [Check(WARN, "configuration", w) for w in pol.warnings]

    log = Path(os.environ.get("SEATBELT_AUDIT_LOG") or default_path())
    parent = log.parent
    writable = os.access(parent if parent.exists() else next((p for p in parent.parents if p.exists()), Path("/")), os.W_OK)
    if os.environ.get("SEATBELT_AUDIT", "on").lower() in ("off", "0", "false", "no"):
        checks.append(Check(INFO, "audit log", "switched off (SEATBELT_AUDIT=off); `seatbelt learn` will have nothing to read"))
    else:
        size = f", {log.stat().st_size // 1024} KB" if log.exists() else ", not created yet"
        checks.append(Check(OK if writable else FAIL, "audit log", f"{log}{size}",
                            "" if writable else "the directory is not writable, so nothing is recorded"))
    return checks


def format_checks(checks: list[Check], color: bool = False) -> str:
    sym = {OK: ("\033[32mok  \033[0m" if color else "ok  "), WARN: ("\033[33mWARN\033[0m" if color else "WARN"),
           FAIL: ("\033[31mFAIL\033[0m" if color else "FAIL"), INFO: "    "}
    lines = []
    for c in checks:
        lines.append(f"{sym[c.status]} {c.title}" + (f": {c.detail}" if c.detail else ""))
        if c.fix and c.status in (WARN, FAIL, INFO):
            lines.append(f"       -> {c.fix}")
    bad = sum(c.status == FAIL for c in checks)
    warn = sum(c.status == WARN for c in checks)
    lines.append("")
    lines.append("Everything is in place." if not bad and not warn else f"{bad} problem(s), {warn} warning(s).")
    return "\n".join(lines)
