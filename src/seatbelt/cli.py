from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, hook, install
from .audit import AuditLog
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="seatbelt", description="A seatbelt for AI coding agents.")
    p.add_argument("--version", action="version", version=f"seatbelt {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="explain what seatbelt would do with a command (nothing is executed)")
    c.add_argument("cmd", nargs=argparse.REMAINDER, help="the command line to check (quote it, or put options before it)")
    c.add_argument("--file", help="check every line of a corpus file")
    c.add_argument("--cwd", help="pretend the command runs here (default: current directory)")
    c.add_argument("--home", help="pretend this is the home directory")
    c.add_argument("--headless", action="store_true", help="nobody can answer prompts: ASK becomes DENY")
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

    g = sub.add_parser("log", help="show what the agent ran")
    g.add_argument("--tail", type=int, default=20)
    g.add_argument("--decision", choices=["allow", "ask", "deny"])
    g.add_argument("--audit-log")
    g.add_argument("--json", action="store_true")
    return p


def _cmd_hook(args) -> int:
    if sys.stdin.isatty():
        print("seatbelt hook reads a Claude Code hook payload on stdin; it is run by Claude Code, not by hand.\n"
              "See `seatbelt install claude-code`.", file=sys.stderr)
        return 0
    out = hook.run(sys.stdin.read(), args.headless, AuditLog(args.audit_log) if args.audit_log else AuditLog())
    if out is not None:
        sys.stdout.write(out + "\n")
    return 0


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
    entry = install.build_entry(install.hook_command(args.headless), on_failure)
    settings, changed = install.merge(settings, entry)
    print(f"Settings file: {path}")
    print(f"Claude Code version: {'.'.join(map(str, version)) if version else 'not found'}")
    if not on_failure:
        print("NOTE: onFailure=block is NOT set. If this hook ever fails to run (seatbelt uninstalled, broken venv),\n"
              "      Claude Code lets the command through. Add \"onFailure\": \"block\" yourself on Claude Code >= 2.1.295.")
    print("Hook entry:\n" + json.dumps({"hooks": {"PreToolUse": [entry]}}, indent=2))
    if args.write:
        backup = install.save(path, settings)
        print(f"\nWritten.{f' Previous file saved as {backup}.' if backup else ''} Restart Claude Code to load it.")
    else:
        print("\n(dry run: add --write to apply)")
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
    if args.command == "check":
        kw = {}
        if args.cwd:
            kw["cwd"] = args.cwd
        if args.home:
            kw["home"] = args.home
        ctx = Context(headless=args.headless, **kw)
        color = sys.stdout.isatty() and not args.no_color
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
