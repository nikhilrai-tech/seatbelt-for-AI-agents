"""Learn mode: turn the prompts you approved into suggested `allow` rules. Suggestions only; nothing is ever applied.

How it knows you approved: the hook logs every decision with Claude Code's `tool_use_id`, and logs a second row when the
Post event for the same id arrives (the command ran). An `ask` followed by that row was approved. An `ask` with no row was
declined, or never ran, and counts against the pattern.

Safety rules (these are the point of the feature):
  * only ASK decisions are considered, never DENY;
  * only plain `destructive`/`irreversible` asks: anything touching secrets, exfiltration, tampering, remote code,
    privilege, exposure, production or dynamic (unverifiable) commands is never suggested;
  * patterns stay as narrow as possible: flags are kept literally and only the last path component is wildcarded;
  * a pattern is suggested only after N approvals, never if it was ever declined, and only if it provably lowers the ask
    (every example is re-run through the real engine with the candidate rule applied).
"""
from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from .context import Context
from .engine import analyze
from .model import Level
from .policy import Policy, PolicyRule

ELIGIBLE = {"destructive", "irreversible"}
PENDING_GRACE = timedelta(minutes=10)  # a recent ask without a Post row may simply not have been answered yet


@dataclass
class Candidate:
    pattern: str
    approvals: int = 0
    declined: int = 0
    examples: list[str] = field(default_factory=list)
    categories: set[str] = field(default_factory=set)
    last_seen: str = ""
    blocked_by: str = ""  # why it is not suggested, if it is not


@dataclass
class Report:
    suggested: list[Candidate]
    skipped: list[Candidate]
    asks_seen: int
    approved: int
    declined: int
    pending: int


def generalize(raw: str) -> Optional[str]:
    """`git push --force origin feature/login` -> `git push --force origin feature/*`. None if it can't be done safely."""
    tokens = raw.split()
    if not tokens or any(c in raw for c in ("$(", "`", "***", "${")):
        return None
    out = [tokens[0]]
    for t in tokens[1:]:
        if t.startswith("-") or not ("/" in t):
            out.append(t)
        else:
            head = posixpath.dirname(t.rstrip("/"))
            out.append(f"{head}/*" if head else t)  # `/tmp/x` -> `/tmp/*`, `build/old` -> `build/*`
    return " ".join(out)


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return datetime.fromtimestamp(0, timezone.utc)


def learn(rows: Iterable[dict], min_approvals: int = 3, now: Optional[datetime] = None,
          ctx: Optional[Context] = None) -> Report:
    now = now or datetime.now(timezone.utc)
    rows = list(rows)
    executed = {r["tool_use_id"] for r in rows if r.get("event") == "executed" and r.get("tool_use_id")}
    asks = [r for r in rows if r.get("decision") == "ask" and r.get("tool") in ("Bash", "PowerShell") and r.get("command")]

    cands: dict[str, Candidate] = {}
    approved = declined = pending = 0
    for r in asks:
        tid = r.get("tool_use_id")
        if tid in executed:
            state = "approved"
            approved += 1
        elif now - _parse_ts(r.get("ts", "")) < PENDING_GRACE:
            pending += 1
            continue
        else:
            state = "declined"
            declined += 1
        base = ctx or Context(cwd=r.get("cwd") or "/", environ={})
        verdict = analyze(r["command"], Context(cwd=r.get("cwd") or base.cwd, home=base.home, environ=base.environ))
        by_cmd: dict[str, list] = defaultdict(list)
        for f in verdict.findings:
            if f.level == Level.ASK and f.command:
                by_cmd[f.command].append(f)
        for simple, findings in by_cmd.items():
            pattern = generalize(simple)
            if not pattern:
                continue
            c = cands.setdefault(pattern, Candidate(pattern))
            c.categories |= {f.category for f in findings}
            if state == "approved":
                c.approvals += 1
                if simple not in c.examples and len(c.examples) < 3:
                    c.examples.append(simple)
            else:
                c.declined += 1
            c.last_seen = max(c.last_seen, r.get("ts", ""))

    suggested: list[Candidate] = []
    skipped: list[Candidate] = []
    for c in cands.values():
        if c.approvals == 0:
            continue
        bad = c.categories - ELIGIBLE
        if bad:
            c.blocked_by = f"never suggested for {', '.join(sorted(bad))}"
        elif c.declined:
            c.blocked_by = f"it was also declined or never ran {c.declined} time(s)"
        elif c.approvals < min_approvals:
            c.blocked_by = f"approved {c.approvals}x, needs {min_approvals}"
        elif not _takes_effect(c, ctx):
            c.blocked_by = "the rule would not lower the ask (another check still applies)"
        (skipped if c.blocked_by else suggested).append(c)
    suggested.sort(key=lambda c: -c.approvals)
    skipped.sort(key=lambda c: -c.approvals)
    return Report(suggested, skipped, len(asks), approved, declined, pending)


def _takes_effect(c: Candidate, ctx: Optional[Context]) -> bool:
    """Re-run every example with the candidate rule applied: it must come out as ALLOW, and must not touch a DENY."""
    base = ctx or Context(environ={})
    for ex in c.examples:
        test = Context(cwd=base.cwd, home=base.home, environ=base.environ)
        test.policy = Policy(allow=[PolicyRule(c.pattern)])
        if analyze(ex, test).level != Level.ALLOW:
            return False
    return bool(c.examples)


def to_toml(cands: list[Candidate]) -> str:
    lines = ["# Suggested by `seatbelt learn`. Review each one; paste into ~/.config/seatbelt/config.toml (not a project file:", "# a project's seatbelt.toml cannot grant permissions)."]
    for c in cands:
        reason = f"approved {c.approvals} times"
        lines += ["", "[[allow]]", f'command = "{_esc(c.pattern)}"', f'reason = "{reason}"']
    return "\n".join(lines) + "\n"


def _esc(s: str) -> str:
    return re.sub(r'(["\\])', r"\\\1", s)


def format_report(rep: Report, min_approvals: int) -> str:
    out = [f"Looked at {rep.asks_seen} prompts: {rep.approved} approved, {rep.declined} declined or never ran, "
           f"{rep.pending} still pending."]
    if rep.suggested:
        out += ["", f"Approved at least {min_approvals} times, safe to suggest:"]
        for i, c in enumerate(rep.suggested, 1):
            out.append(f"  {i}. {c.pattern}")
            out.append(f"       approved {c.approvals}x, e.g. `{c.examples[0]}`")
        out += ["", to_toml(rep.suggested).rstrip()]
    else:
        out += ["", "Nothing to suggest yet."]
    if rep.skipped:
        out += ["", "Not suggested:"]
        for c in rep.skipped[:10]:
            out.append(f"  - {c.pattern}  ({c.blocked_by})")
    return "\n".join(out)
