"""Turn a command line into a Verdict: parse it, run every rule on every command found, take the strictest result."""
from __future__ import annotations

import re
from typing import Optional

from .context import Context, Resolver
from . import preview
from .model import Finding, Level, Verdict
from .policy import Policy
from .rules import rules_for
from .rules.pipeline import analyze_pipelines
from .rules.fs import DISK_DEVICE_PREFIXES, HARMLESS_DEVICES
from .shell import Command, parse

FORK_BOMB = re.compile(r":\s*\(\s*\)\s*\{[^}]*:\s*\|\s*:[^}]*\}")
WRITE_OPS = {">", ">>", ">|", "&>", "&>>", "<>"}
PROBLEM_TEXT = {
    "dynamic-command": "the program to run is computed at runtime, so it cannot be checked",
    "eval": "an `eval` of a runtime string runs code that cannot be checked",
    "unbalanced": "the command could not be parsed reliably",
    "too-deep": "the command is nested too deeply to check",
}


def _track_cwd(cmd: Command, cur: Optional[str], res: Resolver) -> Optional[str]:
    if cmd.name in ("cd", "pushd"):
        args = [a for a in cmd.argv[1:] if not a.startswith("-") or a == "-"]
        if not args:
            return res.ctx.home
        if cmd.words and cmd.dyn(cmd.argv.index(args[0])) or args[0] == "-":
            return None
        return res.resolve(args[0], cur).path
    if cmd.name == "popd":
        return None
    return cur


def _redirects(cmd: Command, res: Resolver) -> list[Finding]:
    out = []
    for r in cmd.redirects:
        if r.op in WRITE_OPS and r.target and r.target not in HARMLESS_DEVICES:
            path = res.resolve(r.target, cmd.cwd).path
            if path and path.startswith(DISK_DEVICE_PREFIXES):
                out.append(Finding("fs.redirect.device", Level.DENY, "irreversible",
                                   f"redirecting output into the disk device {path} destroys its data", cmd.raw))
    return out


def analyze(text: str, ctx: Optional[Context] = None) -> Verdict:
    ctx = ctx or Context()
    res = Resolver(ctx)
    parsed = parse(text)
    findings: list[Finding] = []

    if FORK_BOMB.search(text):
        findings.append(Finding("system.fork-bomb", Level.DENY, "destructive", "this is a fork bomb", text[:80]))
    for p in parsed.problems:
        findings.append(Finding(f"parse.{p.kind}", Level.ASK, "dynamic", PROBLEM_TEXT.get(p.kind, p.message), p.raw))

    cur: Optional[str] = ctx.cwd
    for cmd in parsed.commands:
        cmd.cwd = cur
        for fn in rules_for(cmd.name):
            findings += fn(cmd, ctx, res)
        findings += _redirects(cmd, res)
        cur = _track_cwd(cmd, cur, res)
    findings += analyze_pipelines(parsed.commands, ctx, res)
    findings = _apply_policy(findings, parsed.commands, ctx.policy)

    verdict = verdict_of(findings, ctx, parsed.commands)
    if verdict.level != Level.ALLOW:
        try:
            verdict.impact = preview.collect(parsed.commands, verdict.findings, ctx, res)
        except Exception:  # a preview is a nicety: it must never change or break the decision
            verdict.impact = []
    return verdict


def _apply_policy(findings: list[Finding], commands: list[Command], policy: Policy) -> list[Finding]:
    """User/project rules. `deny` and `ask` add findings; `allow` only removes ASKs (never DENY, never tamper)."""
    if policy.error:
        findings = findings + [Finding("policy.invalid", Level.ASK, "policy",
                                       f"seatbelt's configuration is broken, so your rules are not being applied: {policy.error}", "")]
    allowed: set[str] = set()
    for cmd in commands:
        text = " ".join(cmd.argv)
        bare = " ".join(a for a in cmd.argv if not a.startswith("-"))  # `npm run --silent deploy` is still `npm run deploy`
        for rules, level, word in ((policy.deny, Level.DENY, "denied"), (policy.ask, Level.ASK, "flagged")):
            r = Policy.match(rules, text) or Policy.match(rules, bare)
            if r:
                findings = findings + [Finding(f"policy.{word}", level, "policy",
                                               r.reason or f"{word} by your seatbelt policy ({r.pattern})", cmd.raw)]
        if Policy.match(policy.allow, text):
            allowed.add(cmd.raw)
    if allowed:
        findings = [f for f in findings if not (f.level == Level.ASK and f.command in allowed and f.category not in ("tamper", "policy"))]
    return findings


def verdict_of(findings: list[Finding], ctx: Context, commands: Optional[list[Command]] = None) -> Verdict:
    """Deduplicate, take the strictest level, and apply headless mode."""
    unique: list[Finding] = []
    for f in findings:
        if (f.rule, f.message) not in {(u.rule, u.message) for u in unique}:
            unique.append(f)
    level = max((f.level for f in unique), default=Level.ALLOW)
    if (ctx.headless or ctx.policy.headless is True) and level == Level.ASK:
        level = Level.DENY
    return Verdict(level, unique, commands or [])
