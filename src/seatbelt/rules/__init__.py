"""Rule registry. A rule is `fn(cmd, ctx, resolver) -> list[Finding]`, registered under the command names it handles."""
from __future__ import annotations

from typing import Callable

from ..context import Context, Resolver
from ..model import Finding
from ..shell import Command

Rule = Callable[[Command, Context, Resolver], list[Finding]]
REGISTRY: dict[str, list[Rule]] = {}


def rule(*names: str):
    def deco(fn: Rule) -> Rule:
        for n in names:
            REGISTRY.setdefault(n, []).append(fn)
        return fn
    return deco


def rules_for(name: str) -> list[Rule]:
    if name.startswith("mkfs."):  # mkfs.ext4, mkfs.xfs ...
        name = "mkfs"
    return REGISTRY.get(name, [])


from . import fs, git, system  # noqa: E402

RULE_MODULES = (fs, git, system)  # importing them registers their rules
