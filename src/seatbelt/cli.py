"""Entry point. `seatbelt hook` runs before every command an agent makes, so it takes a fast path that imports only what
it needs (no argparse, no demo/doctor/learn); everything else goes through `cli_full`."""
from __future__ import annotations

import sys


def run_hook(headless: bool = False, audit_path: str | None = None) -> int:
    from . import hook
    from .audit import AuditLog

    if sys.stdin.isatty():
        print("seatbelt hook reads a Claude Code hook payload on stdin; it is run by Claude Code, not by hand.\n"
              "See `seatbelt install claude-code`.", file=sys.stderr)
        return 0
    out = hook.run(sys.stdin.read(), headless, AuditLog(audit_path) if audit_path else AuditLog())
    if out is not None:
        sys.stdout.write(out + "\n")
    return 0


def _fast_hook_args(rest: list[str]) -> tuple[bool, str | None] | None:
    headless, audit, i = False, None, 0
    while i < len(rest):
        if rest[i] == "--headless":
            headless = True
        elif rest[i] == "--audit-log" and i + 1 < len(rest):
            audit = rest[i + 1]
            i += 1
        else:
            return None  # anything unusual (including --help): let argparse deal with it
        i += 1
    return headless, audit


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["hook"]:
        parsed = _fast_hook_args(argv[1:])
        if parsed is not None:
            return run_hook(*parsed)
    from .cli_full import main as full_main
    return full_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
