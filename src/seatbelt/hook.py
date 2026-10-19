"""Claude Code `PreToolUse` hook adapter.

Contract (from the Claude Code hooks reference, checked while building this):
  * stdin: one JSON object with `tool_name`, `tool_input`, `cwd`, `session_id`, `permission_mode`, `hook_event_name`.
  * To decide, print one JSON object on stdout and exit 0:
        {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny|ask|allow",
                                "permissionDecisionReason": "..."}}
  * Printing nothing and exiting 0 leaves the normal permission flow untouched.
  * Exit 2 blocks (stderr is the reason). Any OTHER non-zero exit is a non-blocking error: **the tool call still runs**.

Consequences for this module:
  * It must never crash or exit non-zero, so every failure path answers `ask`, never silence.
  * It never answers `allow`: `allow` skips the user's permission prompt, and a guardrail has no business doing that.
    Safe commands get silence, which keeps the user's own rules in charge.
  * Only JSON may reach stdout.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

from .audit import AuditLog
from .context import Context
from .engine import analyze
from .model import Finding, Level, Verdict

SHELL_TOOLS = {"Bash", "PowerShell"}
DENY_SUFFIX = (" Do not retry with a different spelling or split it into steps: if this is really intended, "
               "ask the user to run it themselves.")

_PS_DENY = re.compile(r"(?i)\b(Format-Volume|Clear-Disk|Remove-Partition|Initialize-Disk)\b")
_PS_ASK = [
    (re.compile(r"(?i)\b(Remove-Item|ri|rm|del|rmdir)\b.*(-Recurse|\s-r\b)"), "recursive delete"),
    (re.compile(r"(?i)\b(Invoke-Expression|iex)\b"), "Invoke-Expression runs code built at runtime"),
    (re.compile(r"(?i)\b(Stop-Computer|Restart-Computer)\b"), "stops or restarts the machine"),
    (re.compile(r"(?i)\b(Set-ExecutionPolicy\s+(Bypass|Unrestricted))\b"), "weakens the PowerShell execution policy"),
]


def analyze_powershell(text: str, ctx: Context) -> Verdict:
    """PowerShell is not POSIX shell, so only a few unmistakable patterns are checked; everything else stays quiet."""
    findings: list[Finding] = []
    if _PS_DENY.search(text):
        findings.append(Finding("powershell.disk", Level.DENY, "irreversible", "this formats or wipes disks", text[:80]))
    for rx, msg in _PS_ASK:
        if rx.search(text):
            findings.append(Finding("powershell.risky", Level.ASK, "destructive", msg, text[:80]))
    level = max((f.level for f in findings), default=Level.ALLOW)
    if ctx.headless and level == Level.ASK:
        level = Level.DENY
    return Verdict(level, findings)


def decision_output(decision: str, reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}


def _context(payload: dict, headless: bool) -> Context:
    kw = {"headless": headless or os.environ.get("SEATBELT_HEADLESS", "").lower() in ("1", "true", "yes", "on")}
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        kw["cwd"] = cwd
    return Context(**kw)


def handle(payload: dict, headless: bool = False, audit: Optional[AuditLog] = None) -> Optional[dict]:
    """Return the hook's JSON answer, or None to stay silent. Never raises."""
    try:
        if payload.get("hook_event_name") not in (None, "PreToolUse"):
            return None
        tool = payload.get("tool_name")
        if tool not in SHELL_TOOLS:
            return None
        command = (payload.get("tool_input") or {}).get("command")
        if not isinstance(command, str):
            return decision_output("ask", "seatbelt: this shell call has no readable command, so it cannot be checked.")
        ctx = _context(payload, headless)
        verdict = analyze_powershell(command, ctx) if tool == "PowerShell" else analyze(command, ctx)
        if audit is not None and AuditLog.enabled():
            audit.record({"session_id": payload.get("session_id"), "tool": tool, "cwd": ctx.cwd, "command": command,
                          "decision": verdict.level.name.lower(), "rules": [f.rule for f in verdict.findings],
                          "categories": sorted({f.category for f in verdict.findings}), "reason": verdict.reason})
        if verdict.level == Level.ALLOW:
            return None
        reason = f"seatbelt: {verdict.reason}."
        if verdict.level == Level.DENY:
            return decision_output("deny", reason + DENY_SUFFIX)
        return decision_output("ask", reason)
    except Exception as exc:  # fail closed: a crash would let the command through
        return decision_output("ask", f"seatbelt hit an internal error ({type(exc).__name__}) and could not check this "
                                      f"command; review it yourself before approving.")


def run(stdin_text: str, headless: bool = False, audit: Optional[AuditLog] = None) -> Optional[str]:
    """Parse the hook input and return the text to print on stdout (None = print nothing)."""
    try:
        payload = json.loads(stdin_text)
        if not isinstance(payload, dict):
            raise ValueError("hook input is not an object")
    except Exception:
        return json.dumps(decision_output("ask", "seatbelt could not read the hook input, so it cannot check this "
                                                 "command; review it yourself before approving."))
    out = handle(payload, headless, audit)
    return None if out is None else json.dumps(out)
