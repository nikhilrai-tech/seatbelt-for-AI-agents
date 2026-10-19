from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from . import __version__, demo, doctor, install, learn
from .audit import AuditLog
from . import policy as policy_mod
from .context import Context
from .engine import analyze
from .model import Level, Verdict

COLORS = {Level.ALLOW: "\033[32m", Level.ASK: "\033[33m", Level.DENY: "\033[31m"}


def _fmt(command: str, v: Verdict, color: bool) -> str:
    label = v.level.name
    tag = f"{COLORS[v.level]}{label:<5}\033[0m" if color else f"{label:<5}"
    lines = [f"{tag} {command}"]
    for f in sorted(v.findings, key=lambda f: -int(f.level)):
        lines.append(f"        - {f.message}  [{f.rule}]")
    for line in v.impact:
        lines.append(f"        = impact: {line}")
    return "\n".join(lines)


def _check_file(path: str, ctx: Context, color: bool) -> int:
    """Corpus lines: `EXPECTED<TAB>command` (EXPECTED is ALLOW, ASK or DENY) or just a command. Exit 1 on any mismatch."""
    bad = 0
    for raw in Path(path).read_text().splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        expected = None
        head, sep, rest = line.partition("\t")
        if sep and head in Level.__members__:
            expected, line = Level[head], rest
        v = analyze(line, ctx)
        print(_fmt(line, v, color))
        if expected is not None and v.level != expected:
            bad += 1
            print(f"        !! expected {expected.name}")
    if bad:
        print(f"\n{bad} line(s) did not match their expected verdict", file=sys.stderr)
    return 1 if bad else 0


ZSH_HISTORY = re.compile(r"^: \d+:\d+;")


def _check_stdin(ctx, color: bool, quiet: bool) -> int:
    """Run every line of stdin through seatbelt and summarise. The quickest way to find false positives: point it at your
    own shell history. Nothing is executed, previews are off (history paths are not on this disk), and the commands are
    redacted before they are printed, so the output is safe to paste into an issue."""
    from .audit import redact
    from .engine import analyze

    os.environ["SEATBELT_PREVIEW"] = "off"
    counts = {Level.ALLOW: 0, Level.ASK: 0, Level.DENY: 0}
    for raw in sys.stdin.read().splitlines():
        line = ZSH_HISTORY.sub("", raw).strip()  # zsh extended history: ": 1700000000:0;command"
        if not line or line.startswith("#"):
            continue
        v = analyze(line, ctx)
        counts[v.level] += 1
        if quiet and v.level == Level.ALLOW:
            continue
        print(_fmt(redact(line), v, color))
    total = sum(counts.values())
    if not total:
        print("no commands on stdin", file=sys.stderr)
        return 2
    print(f"\n{total} commands: {counts[Level.ALLOW]} left alone, {counts[Level.ASK]} would ask first, "
          f"{counts[Level.DENY]} would be denied.")
    if counts[Level.ASK] + counts[Level.DENY]:
        print("A harmless one in the list? Please open a 'false positive' issue with its `seatbelt check --json` output.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="seatbelt", description="A seatbelt for AI coding agents.")
    p.add_argument("--version", action="version", version=f"seatbelt {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="explain what seatbelt would do with a command (nothing is executed)")
    c.add_argument("cmd", nargs=argparse.REMAINDER, help="the command line to check (quote it, or put options before it)")
    c.add_argument("--file", help="check every line of a file (plain commands, or EXPECTED<TAB>command for the regression corpus)")
    c.add_argument("--stdin", action="store_true",
                   help="check every command read from stdin, one per line (bash and zsh history files work); prints a summary")
    c.add_argument("--quiet", action="store_true", help="with --stdin: hide the commands that would be left alone")
    c.add_argument("--cwd", help="pretend the command runs here (default: current directory)")
    c.add_argument("--home", help="pretend this is the home directory")
    c.add_argument("--headless", action="store_true", help="nobody can answer prompts: ASK becomes DENY")
    c.add_argument("--config", help="seatbelt config file (default: ~/.config/seatbelt/config.toml, plus ./seatbelt.toml)")
    c.add_argument("--no-config", action="store_true", help="ignore every config file (reproducible results)")
    c.add_argument("--json", action="store_true")
    c.add_argument("--no-color", action="store_true")

    h = sub.add_parser("hook", help="Claude Code PreToolUse hook: reads the hook JSON on stdin, answers on stdout")
    h.add_argument("--headless", action="store_true", help="nobody can answer prompts: ASK becomes DENY")
    h.add_argument("--audit-log", help="audit log path (default: ~/.local/state/seatbelt/audit.jsonl)")

    for name, text in (("install", "add the hook to a Claude Code settings.json"), ("uninstall", "remove the hook again")):
        i = sub.add_parser(name, help=text)
        i.add_argument("target", choices=["claude-code"])
        i.add_argument("--scope", choices=["user", "project", "local"], default="user",
                       help="user: ~/.claude/settings.json, project: ./.claude/settings.json, local: ./.claude/settings.local.json")
        i.add_argument("--settings-file", help="use this settings file instead of the scope's default")
        i.add_argument("--write", action="store_true", help="actually change the file (default: only show what would change)")
        if name == "install":
            i.add_argument("--headless", action="store_true", help="install with --headless (ASK becomes DENY)")
            i.add_argument("--no-on-failure-block", action="store_true", help="don't add onFailure=block")

    dr = sub.add_parser("doctor", help="check that the guardrail is in place and really works (runs the installed hook as a test)")
    dr.add_argument("--json", action="store_true")
    dr.add_argument("--cwd", help="check as if run from this project directory")

    dm = sub.add_parser("demo", help="a guided tour of what seatbelt does with risky commands (nothing is executed)")
    dm.add_argument("--no-color", action="store_true")
    dm.add_argument("--short", action="store_true", help="three examples per scenario")

    ln = sub.add_parser("learn", help="suggest allow rules from the prompts you approved (suggestions only, nothing is applied)")
    ln.add_argument("--min", type=int, default=3, help="approvals needed before a pattern is suggested (default 3)")
    ln.add_argument("--audit-log")
    ln.add_argument("--json", action="store_true")

    g = sub.add_parser("log", help="show what the agent ran")
    g.add_argument("--tail", type=int, default=20)
    g.add_argument("--decision", choices=["allow", "ask", "deny"])
    g.add_argument("--audit-log")
    g.add_argument("--json", action="store_true")
    return p


def _cmd_hook(args) -> int:
    from .cli import run_hook
    return run_hook(args.headless, args.audit_log)


def _cmd_install(args) -> int:
    path = Path(args.settings_file) if args.settings_file else install.settings_path(args.scope)
    try:
        settings = install.load(path)
    except ValueError:
        print(f"{path} is not valid JSON; fix it first (nothing was changed).", file=sys.stderr)
        return 2
    if args.command == "uninstall":
        settings, changed = install.remove(settings)
        print(f"{path}: {'hook removed' if changed else 'seatbelt hook was not installed'}")
        if changed and args.write:
            install.save(path, settings)
        elif changed:
            print("(dry run: add --write to apply)")
        return 0

    version = install.claude_version()
    can_block = version is not None and version >= install.ON_FAILURE_MIN
    on_failure = can_block and not args.no_on_failure_block
    command = install.hook_command(args.headless)
    settings, changed = install.merge_all(settings, command, on_failure)
    print(f"Settings file: {path}")
    print(f"Claude Code version: {'.'.join(map(str, version)) if version else 'not found'}")
    if not on_failure:
        print("NOTE: onFailure=block is NOT set. If this hook ever fails to run (seatbelt uninstalled, broken venv),\n"
              "      Claude Code lets the command through. Add \"onFailure\": \"block\" yourself on Claude Code >= 2.1.295.")
    print("Hook entries:\n" + json.dumps({"hooks": {e: [x] for e, x in install.entries_for(command, on_failure).items()}}, indent=2))
    if args.write:
        backup = install.save(path, settings)
        print(f"\nWritten.{f' Previous file saved as {backup}.' if backup else ''} Restart Claude Code to load it.")
    else:
        print("\n(dry run: add --write to apply)")
    return 0


def _cmd_doctor(args) -> int:
    cwd = args.cwd or os.getcwd()
    checks = doctor.run(cwd, os.path.expanduser("~"), dict(os.environ))
    if args.json:
        print(json.dumps([vars(c) for c in checks], indent=2))
    else:
        print(doctor.format_checks(checks, color=sys.stdout.isatty()))
    return 1 if any(c.status == doctor.FAIL for c in checks) else 0


def _cmd_demo(args) -> int:
    text, wrong = demo.run_demo(color=sys.stdout.isatty() and not args.no_color, short=args.short)
    print(text)
    if wrong:
        print("\nthese scenarios no longer behave as documented: " + "; ".join(wrong), file=sys.stderr)
    return 1 if wrong else 0


def _cmd_learn(args) -> int:
    log = AuditLog(args.audit_log) if args.audit_log else AuditLog()
    rows = list(log.read())
    if not rows:
        print(f"no entries in {log.path}; install the hook and use your agent for a while first", file=sys.stderr)
        return 1
    rep = learn.learn(rows, args.min)
    if args.json:
        print(json.dumps({"suggested": [vars(c) | {"categories": sorted(c.categories)} for c in rep.suggested],
                          "skipped": [vars(c) | {"categories": sorted(c.categories)} for c in rep.skipped],
                          "asks": rep.asks_seen, "approved": rep.approved, "declined": rep.declined}, indent=2))
    else:
        print(learn.format_report(rep, args.min))
    return 0


def _cmd_log(args) -> int:
    log = AuditLog(args.audit_log) if args.audit_log else AuditLog()
    rows = [r for r in log.read() if not args.decision or r.get("decision") == args.decision]
    for r in rows[-args.tail:]:
        if args.json:
            print(json.dumps(r))
        else:
            print(f"{r.get('ts', '')}  {str(r.get('decision', '')).upper():<5} {r.get('command', '')}")
            if r.get("reason"):
                print(f"        {r['reason']}")
    if not rows:
        print(f"no entries in {log.path}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "hook":
        return _cmd_hook(args)
    if args.command in ("install", "uninstall"):
        return _cmd_install(args)
    if args.command == "log":
        return _cmd_log(args)
    if args.command == "learn":
        return _cmd_learn(args)
    if args.command == "doctor":
        return _cmd_doctor(args)
    if args.command == "demo":
        return _cmd_demo(args)
    if args.command == "check":
        kw = {}
        if args.cwd:
            kw["cwd"] = args.cwd
        if args.home:
            kw["home"] = args.home
        ctx = Context(headless=args.headless, **kw)
        if not args.no_config:
            env = dict(ctx.environ)
            if args.config:
                env["SEATBELT_CONFIG"] = args.config
            ctx.policy = policy_mod.load(ctx.cwd, ctx.home, env)
            for w in ctx.policy.warnings:
                print(f"note: {w}", file=sys.stderr)
        color = sys.stdout.isatty() and not args.no_color
        if args.stdin:
            return _check_stdin(ctx, color, args.quiet)
        if args.file:
            return _check_file(args.file, ctx, color)
        if not args.cmd:
            print("give a command to check, or --file", file=sys.stderr)
            return 2
        text = " ".join(args.cmd)
        v = analyze(text, ctx)
        print(json.dumps(v.to_dict(), indent=2) if args.json else _fmt(text, v, color))
        return int(v.level)  # 0 allow, 1 ask, 2 deny
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
