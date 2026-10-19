"""An agent must not be able to switch seatbelt off by *running seatbelt* (or its package manager).

Editing `settings.json` is already blocked (rules/tamper.py). But `seatbelt uninstall claude-code --write` does the same
edit through the official front door, `pip uninstall seatbelt-guard` makes the hook fail (and Claude Code then lets every
command through), and deleting the environment the hook lives in does the same. A prompt injection needs only one of them.
Humans run these in their own terminal, where no hook is involved, so nothing is lost.
"""
from __future__ import annotations

from ..context import Context, Resolver
from ..model import Finding, Level
from ..shell import Command
from . import rule

PACKAGE = "seatbelt-guard"
MESSAGE = "{what}: agents must not remove, reinstall or reconfigure their own guardrail; run it yourself in a terminal if you mean it"


def _seatbelt_args(cmd: Command) -> list[str] | None:
    """The arguments given to seatbelt, if this command runs seatbelt in any of its usual spellings."""
    argv, name = cmd.argv, cmd.name
    if name == "seatbelt":
        return argv[1:]
    if name.startswith("python") and argv[1:3] == ["-m", "seatbelt"]:
        return argv[3:]
    if name in ("pipx", "uvx", "uv", "pipenv", "poetry", "hatch") and "seatbelt" in argv:
        return argv[argv.index("seatbelt") + 1:]
    return None


def _finding(cmd: Command, what: str) -> Finding:
    return Finding("tamper.self-protection", Level.DENY, "tamper", MESSAGE.format(what=what), cmd.raw)


@rule("*")
def self_protection(cmd: Command, ctx: Context, res: Resolver) -> list[Finding]:
    if not cmd.words or cmd.dyn(0):
        return []
    args = _seatbelt_args(cmd)
    if args is not None:
        positional = [a for a in args if not a.startswith("-")]
        sub = positional[0] if positional else ""
        if sub == "uninstall":
            return [_finding(cmd, "`seatbelt uninstall` removes the hook")]
        if sub == "install" and "--write" in args:
            return [_finding(cmd, "`seatbelt install --write` rewrites the agent's settings")]
    argv = cmd.argv
    if cmd.name in ("pip", "pip3", "pipx", "uv", "uvx", "conda", "mamba") and any(a in ("uninstall", "remove") for a in argv) \
            and any(a == PACKAGE or a == "seatbelt" or a.startswith(f"{PACKAGE}==") for a in argv):
        return [_finding(cmd, f"uninstalling {PACKAGE} makes the hook fail, and a failing hook lets commands through")]
    if cmd.name.startswith("python") and "pip" in argv and "uninstall" in argv and PACKAGE in argv:
        return [_finding(cmd, f"uninstalling {PACKAGE} makes the hook fail, and a failing hook lets commands through")]
    return []
